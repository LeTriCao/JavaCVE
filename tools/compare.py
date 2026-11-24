"""Measure build success for both pipelines on the same original benchmark snapshots."""
import csv
import io
import json
import os
from pathlib import Path
import shutil
import sys
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET

from .build import digest, invoke, package_and_test, prepare_maven
from .observations import require


def fresh_tree(archive, folder):
    folder.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(folder, filter="data")


def git_archive(repo, args):
    return subprocess.check_output(["git", "-C", str(repo), "archive", "HEAD", *args], timeout=120)


def run_comparison(args, cases, report, save):
    import importlib.util
    require(importlib.util.find_spec("docker") is not None, "Install the Docker Python SDK for the upstream builder")
    upstream, jdk, maven, seed = [p.resolve() for p in (args.upstream, args.jdk, args.maven, args.m2)]
    env = dict(os.environ, JAVA_HOME=str(jdk), PATH=str(jdk / "bin") + os.pathsep + os.environ["PATH"])
    require(seed.is_dir(), "Missing initial Maven cache directory")
    require("1.8.0_514-b01" in invoke([jdk / "bin/java", "-version"], upstream, env), "Expected the pinned JDK 8")
    require("Apache Maven 3.5.0" in invoke([maven / "bin/mvn", "--version"], upstream, env), "Expected Maven 3.5.0")
    head = invoke(["git", "rev-parse", "HEAD"], upstream, env).strip()
    require(all(head == c["benchmark_revision"] for c in cases), "Unexpected IRIS revision")
    bench_archive = git_archive(upstream, ["src", "scripts", "data/project_info.csv", "data/patches"])
    records = []
    report.update(comparisons=records, toolchain={"jdk":"1.8.0_514-b01","maven":"3.5.0"})
    with tempfile.TemporaryDirectory() as session:
        tmp = Path(session)
        bench = tmp / "benchmark"
        fresh_tree(bench_archive, bench)
        with (bench / "data/project_info.csv").open() as f:
            index = {r["cve_id"]: r for r in csv.DictReader(f)}
        for case in cases:
            c = case["cve_id"]
            slug = index[c]["project_slug"]
            repo = upstream / "data/project-sources" / slug
            # The original loader also applies build patches for some other dataset entries.
            # This matched clean-tree protocol covers entries without a local build patch.
            require(not (bench / "data/patches" / (slug + ".patch")).exists(), "This protocol requires a pristine seed tree")
            if not repo.is_dir():
                invoke([sys.executable, "scripts/fetch_one.py", slug], bench, env)
                repo = bench / "data/project-sources" / slug
            require(invoke(["git","rev-parse","HEAD"],repo,env).strip() == case["seed_commit"], "Seed revision mismatch")
            archive = git_archive(repo, [])
            row = {"cve_id": c, "commit":case["seed_commit"], "module_packaged":".", "module_sampled":case["build_module"]}
            records.append(row)
            for arm in ("upstream","pilot"):
                try:
                    with tempfile.TemporaryDirectory(dir=session) as local:
                        work = Path(local)
                        fresh_tree(bench_archive, work / "iris")
                        private = work / "iris"
                        (private / "data/build-info").mkdir()
                        source = private / "data/project-sources" / slug
                        fresh_tree(archive, source)
                        private_maven = work / "maven"
                        shutil.copytree(maven, private_maven, symlinks=True)
                        shutil.copytree(seed, work / "cache/m2")
                        build_env, _ = prepare_maven(work, jdk, private_maven, work)
                        cfg = work / "settings.xml"
                        settings = ET.parse(cfg)
                        ns = "{http://maven.apache.org/SETTINGS/1.0.0}"
                        ET.register_namespace("", ns[1:-1])
                        ET.SubElement(settings.getroot(), ns+"localRepository").text = str(work / "cache/m2")
                        settings.write(private_maven / "conf/settings.xml", encoding="utf-8")
                        if arm == "upstream":
                            paths = {"jdks":{"8":str(jdk)}, "mvn":{"3.5.0":str(private_maven)}}
                            (private / "dep_configs.json").write_text(json.dumps(paths))
                            # Upstream appends its selected Maven bin to PATH.
                            exec_env = dict(build_env, PATH=str(private_maven / "bin") + os.pathsep + build_env["PATH"])
                            invoke([sys.executable,"scripts/build_one.py",slug,"--jdk","8","--mvn","3.5.0"], private, exec_env)
                            jars = [p for p in (source / case["build_module"] / "target").glob("*.jar")
                                    if not p.name.endswith(("-sources.jar","-tests.jar","-javadoc.jar"))]
                            require(len(jars)==1, "Missing or ambiguous reference JAR")
                            result = {"jar_name":jars[0].name,"jar_sha256":digest(jars[0])}
                        else:
                            result = package_and_test(source,case["build_module"],case["check"],work,build_env,
                                                      [private_maven / "bin/mvn","-B"],jdk,build_module=".")
                        row[arm] = {"status":"PASS",**result}
                except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as e:
                    row[arm] = {"status":"FAIL","error_type":type(e).__name__}
                    print(c, arm, str(e))
                save()
                print(c, arm, row[arm]["status"], flush=True)
    require(all(r[a]["status"]=="PASS" for r in records for a in ("upstream","pilot")), "Comparison contains failed builds")
