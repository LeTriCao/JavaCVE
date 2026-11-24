"""Build version-pinned Java libraries and run one ordinary API check per JAR."""
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def invoke(args, cwd, env):
    proc = subprocess.run(list(map(str, args)), cwd=cwd, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, errors="replace", timeout=600)
    if proc.returncode:
        # Keep transient machine paths and repository credentials out of saved results.
        tail = [s for s in proc.stdout.splitlines() if s.strip()][-12:]
        print("\n".join(tail))
        raise RuntimeError(f"{Path(args[0]).name} returned {proc.returncode}")
    return proc.stdout


def extract_tools(archive, dest):
    with tempfile.TemporaryDirectory(dir=dest.parent) as temp:
        with tarfile.open(archive) as tar:
            tar.extractall(temp, filter="data")
        roots = list(Path(temp).iterdir())
        if len(roots) != 1 or not roots[0].is_dir():
            raise ValueError("Unexpected tool distribution")
        try:
            roots[0].rename(dest)
        except OSError:
            if not dest.is_dir():
                raise


def tool_paths(prior):
    spec = json.loads((ROOT / "data/toolchain.json").read_text())
    found = {}
    for tool, command, url, sha in [
        ("jdk", "javac", spec["jdk_url"], spec["jdk_sha256"]),
        ("maven", "mvn", spec["maven_url"], spec["maven_archive_sha256"]),
    ]:
        cache = ROOT / ".cache" / sha
        cache.mkdir(parents=True, exist_ok=True)
        dest = cache / tool
        existing = prior / "toolchain" / tool
        if (existing / "bin" / command).is_file():
            found[tool] = existing
            continue
        if tool == "jdk" and (platform.machine() != "x86_64" or platform.system() != "Linux"):
            raise RuntimeError("Automatic JDK setup requires Linux x86_64 (including Ubuntu WSL)")
        if not dest.exists():
            with tempfile.NamedTemporaryFile(dir=cache) as f:
                with urllib.request.urlopen(url, timeout=120) as remote:
                    shutil.copyfileobj(remote, f)
                f.flush()
                if digest(Path(f.name)) != sha:
                    raise ValueError(f"{tool}: archive SHA-256 mismatch")
                extract_tools(Path(f.name), dest)
        found[tool] = dest
    return found


def prepare_maven(tmp, jdk, maven, prior):
    env = os.environ.copy()
    env["JAVA_HOME"] = str(jdk)
    env["PATH"] = str(jdk / "bin") + os.pathsep + env["PATH"]
    trust = env.get("JAVA_CVE_TRUSTSTORE")
    if trust:
        env["JAVA_TOOL_OPTIONS"] = env.get("JAVA_TOOL_OPTIONS", "") + ' -Djavax.net.ssl.trustStore="' + trust + '"'
    settings = ET.Element("settings", xmlns="http://maven.apache.org/SETTINGS/1.0.0")
    mirror = ET.SubElement(ET.SubElement(settings, "mirrors"), "mirror")
    for key, value in {"id": "repro-central-https", "mirrorOf": "central,external:http:*",
                       "url": "https://repo.maven.apache.org/maven2"}.items():
        ET.SubElement(mirror, key).text = value
    proxy_url = env.get("HTTPS_PROXY") or env.get("https_proxy")
    if proxy_url:
        u = urllib.parse.urlsplit(proxy_url)
        proxy = ET.SubElement(ET.SubElement(settings, "proxies"), "proxy")
        for key, value in {"id": "local", "active": "true", "protocol": u.scheme,
                           "host": u.hostname, "port": str(u.port or 80),
                           "username": u.username, "password": u.password}.items():
            if value:
                ET.SubElement(proxy, key).text = urllib.parse.unquote(value)
    f = tmp / "settings.xml"
    ET.ElementTree(settings).write(f, encoding="utf-8", xml_declaration=True)
    old_cache = prior / "cache/m2"
    cache = old_cache if old_cache.is_dir() else ROOT / ".cache/m2"
    return env, [maven / "bin/mvn", "-B", "-ntp", "-U", "-s", f, "-Dmaven.repo.local=" + str(cache)]


def populate(case, phase, tmp, prior, env):
    c = case["cve_id"]
    pin = case[phase + "_commit"]
    tree = case[phase + "_tree"]
    checkout = tmp / "source"
    checkout.mkdir()
    archive = prior / "source_archives" / f"{c}-{phase}.tar.gz"
    if archive.is_file():
        if digest(archive) != case["archive_sha256"][phase]:
            raise ValueError("Cached source archive SHA-256 mismatch")
        with tarfile.open(archive) as tar:
            tar.extractall(checkout, filter="data")
        return checkout, "verified_archive"
    invoke(["git", "init", "-q"], checkout, env)
    invoke(["git", "fetch", "-q", "--depth", "1", case["repository_url"], pin], checkout, env)
    invoke(["git", "checkout", "-q", "--detach", pin], checkout, env)
    if invoke(["git", "rev-parse", "HEAD^{tree}"], checkout, env).strip() != tree:
        raise ValueError("Git tree mismatch")
    return checkout, "verified_git_tree"


def package_and_test(source, module, check, tmp, env, mvn, jdk, build_module=None):
    work = source / module
    invoke(mvn + ["-Dmaven.test.skip=true", "-Dcheckstyle.skip=true", "-Drat.skip=true", "package"],
           source / (build_module or module), env)
    jars = [p for p in (work / "target").glob("*.jar")
            if not re.search(r"-(javadoc|sources|tests)\.jar$", p.name) and not p.name.startswith("original-")]
    if len(jars) != 1:
        raise ValueError("Expected one primary library JAR")
    jar = jars[0]
    smoke = ROOT / "smoke" / check / "ApiCheck.java"
    invoke([jdk / "bin/javac", "-classpath", jar, "-d", tmp, smoke], tmp, env)
    result = invoke([jdk / "bin/java", "-classpath", os.pathsep.join([str(tmp), str(jar)]), "ApiCheck"], tmp, env)
    if result.splitlines()[-1:] != ["PASS"]:
        raise ValueError("Unexpected API check output")
    return {"jar_name": jar.name, "jar_sha256": digest(jar), "api_check": "PASS"}


def build(cases, prior, report, save):
    tools = tool_paths(prior)
    with tempfile.TemporaryDirectory() as session:
        env, mvn = prepare_maven(Path(session), tools["jdk"], tools["maven"], prior)
        jdk = tools["jdk"]
        versions = invoke(mvn[:1] + ["--version"], Path(session), env)
        java = invoke([jdk / "bin/java", "-version"], Path(session), env)
        spec = json.loads((ROOT / "data/toolchain.json").read_text())
        if "Apache Maven " + spec["maven_version"] not in versions or spec["jdk_version"] not in java:
            raise ValueError("Installed toolchain differs from the release manifest")
        report["toolchain"] = {"jdk": spec["jdk_version"], "maven": spec["maven_version"]}
        for case in cases:
            for phase in ("before", "after"):
                record = {"cve_id": case["cve_id"], "phase": phase, "commit": case[phase + "_commit"]}
                report["builds"].append(record)
                try:
                    with tempfile.TemporaryDirectory() as folder:
                        tmp = Path(folder)
                        source, mode = populate(case, phase, tmp, prior, env)
                        record["source_check"] = mode
                        record.update(package_and_test(source, case["build_module"], case["check"], tmp, env, mvn, jdk))
                        record["status"] = "PASS"
                except (OSError, RuntimeError, ValueError, subprocess.SubprocessError, tarfile.TarError) as e:
                    record.update(status="FAIL", error_type=type(e).__name__)
                    print(case["cve_id"], phase, str(e))
                save()
                print(case["cve_id"], phase, record["status"], flush=True)
    if any(r["status"] != "PASS" for r in report["builds"]):
        raise RuntimeError("One or more builds or API checks failed")
