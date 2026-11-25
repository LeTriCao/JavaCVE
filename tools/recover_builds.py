"""Bounded source-package recovery for two selected CVEs; never execute CVE probes.

python3 -m tools.recover_builds --cve CVE-2018-1000850 --timeout 300
Recorded temporary POM overlays pin Retrofit's Kotlin plugin to its historical
1.2.60 property and optionally omit Jenkins HPI's test-only dependency staging.
The repository's pinned source and production Java stay untouched.
"""
import argparse
from contextlib import nullcontext
import difflib
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

from .build import ROOT, digest, prepare_maven, tool_paths
from .observations import require
from .pipeline import archive_source, primary_jar
from .runtime import Run, StepError, utc
from .maven_transport import official_transport

TARGETS = ("CVE-2018-1000850", "CVE-2022-25174")


def kotlin_overlay(source):
    """Recover the declared historical compiler, recording an explicit build overlay."""
    root_pom = (source / "pom.xml").read_text()
    declaration = re.search(r"<kotlin.version>([^<]+)</kotlin.version>", root_pom)
    require(declaration is not None, "Missing historical Kotlin version")
    version = declaration.group(1)
    require(version == "1.2.60", "Unexpected historical Kotlin version")
    path = source / "retrofit/pom.xml"
    original = path.read_bytes()
    marker = b"<artifactId>kotlin-maven-plugin</artifactId>"
    require(original.count(marker) == 1, "Ambiguous Kotlin plugin declaration")
    plugin_tail = original.split(marker, 1)[1].split(b"</plugin>", 1)[0]
    require(b"<version>" not in plugin_tail, "Kotlin plugin already pinned")
    patched = original.replace(marker, marker + b"\n        <version>${kotlin.version}</version>")
    path.write_bytes(patched)
    return {"path": "retrofit/pom.xml", "kind": "build_configuration_only",
            "reason": "Missing plugin version otherwise resolves current metadata, ignoring kotlin.version=1.2.60",
            "version": version, "provenance_path": "pom.xml",
            "original_sha256": hashlib.sha256(original).hexdigest(),
            "configured_sha256": hashlib.sha256(patched).hexdigest(),
            "diff": "".join(difflib.unified_diff(original.decode().splitlines(True), patched.decode().splitlines(True),
                                               fromfile="upstream/retrofit/pom.xml", tofile="configured/retrofit/pom.xml"))}


def jenkins_test_overlay(source):
    """Disable only the test harness staging goal when packaging with tests skipped."""
    path = source / "pom.xml"
    original = path.read_bytes()
    require(b"<version>4.33</version>" in original and b"<build>" not in original,
            "Unexpected Jenkins parent/build configuration")
    block = b'''\n  <build><plugins><plugin>
    <groupId>org.jenkins-ci.tools</groupId><artifactId>maven-hpi-plugin</artifactId>
    <executions><execution><id>default-resolve-test-dependencies</id><phase>none</phase></execution></executions>
  </plugin></plugins></build>\n'''
    require(original.count(b"</project>") == 1, "Ambiguous project closing tag")
    patched = original.replace(b"</project>", block + b"</project>")
    path.write_bytes(patched)
    plugin = ROOT / ".cache/m2/org/jenkins-ci/tools/maven-hpi-plugin/3.22/maven-hpi-plugin-3.22.jar"
    return dict(path="pom.xml", kind="build_configuration_only",
                reason="maven.test.skip does not disable HPI 3.22 test harness dependency staging; omit this test-only goal for source package",
                parent_version="4.33", plugin_version="3.22", disabled_execution="default-resolve-test-dependencies",
                plugin_descriptor_source_sha256=digest(plugin),
                original_sha256=hashlib.sha256(original).hexdigest(), configured_sha256=hashlib.sha256(patched).hexdigest(),
                diff="".join(difflib.unified_diff(original.decode().splitlines(True),patched.decode().splitlines(True),
                                               fromfile="upstream/pom.xml",tofile="configured/pom.xml")))


def recover(args):
    require(not (args.offline and args.python_transport), "Python transport requires online mode")
    cases = [json.loads(s) for s in (ROOT / "data/batch-02/cases.jsonl").read_text().splitlines()]
    cases = [c for c in cases if c["cve_id"] in args.cve]
    run = Run("build-recovery", " ".join(args.cve))
    run.report.update(batch_dataset_sha256=digest(ROOT / "data/batch-02/versions.jsonl"),
                      prior_receipt="evidence/v0.2.0/2b54f962ab544cb789aaf746c087715e/run.json",
                      hypothesis="Historical Kotlin plugin pin for Retrofit; offline repository/cache diagnosis for Jenkins",
                      selection=args.cve, offline=args.offline, timeout_seconds=args.timeout,
                      scope="Source package only; tests skipped. No security assertions or label changes.")
    tools = tool_paths(ROOT.parent / "JavaCVE_Reproducible")
    with tempfile.TemporaryDirectory(prefix="javacve-recovery-") as session:
        session = Path(session)
        use_jenkins = "CVE-2022-25174" in args.cve
        env, mvn = prepare_maven(session, tools["jdk"], tools["maven"], ROOT, use_jenkins)
        mvn = [x for x in mvn if x != "-U"]
        mvn += ["-Dmaven.wagon.rto=15000", "-Dmaven.wagon.http.retryHandler.count=1",
                "-Daether.connector.connectTimeout=15000", "-Daether.connector.requestTimeout=15000"]
        if args.offline:
            mvn.append("-o")
        if args.python_transport:
            require(not args.offline, "Python transport requires online mode")
            mvn.append("-U")
        downloads = []
        run.report["transport_downloads"] = downloads
        run.report["transport"] = "Python TLS via loopback; official repository URLs only" if args.python_transport else "Maven native"
        run.report["repository_policy"] = ("central_and_jenkins_https" if use_jenkins else "central_https_and_declared_https") + "; existing repository IDs retained"
        run.report["toolchain"] = {
            "java": run.execute("java-version", [tools["jdk"] / "bin/java", "-version"], env=env),
            "maven": run.execute("maven-version", [tools["maven"] / "bin/mvn", "--version"], env=env),
        }
        transport = official_transport(session / "settings.xml", downloads, run.directory / "logs/transport.log") if args.python_transport else nullcontext()
        with transport:
          for case in cases:
            for phase in ("before", "after"):
                start = time.monotonic()
                record = {"cve_id": case["cve_id"], "phase": phase, "commit": case[phase + "_commit"],
                          "status": "running", "start_utc": utc(), "security_status": "BLOCKED_NO_REVIEWED_PAIRED_FIXTURE"}
                run.report["snapshots"].append(record)
                try:
                    with tempfile.TemporaryDirectory(dir=session) as work:
                        source = Path(work) / "source"
                        source.mkdir()
                        repo = ROOT / ".cache/batch02-repos" / case["cve_id"]
                        tree = subprocess.check_output(["git", "-C", str(repo), "rev-parse", record["commit"] + "^{tree}"], text=True).strip()
                        require(tree == case[phase + "_tree"], "Source tree mismatch")
                        record["tree"] = tree
                        archive_source(repo, record["commit"], source)
                        upstream = {p.relative_to(source).as_posix(): digest(p) for p in source.rglob("*") if p.is_file() and not p.is_symlink()}
                        overlays = ([kotlin_overlay(source)] if case["cve_id"] == TARGETS[0] else
                                    [jenkins_test_overlay(source)] if args.skip_test_staging else [])
                        record["build_config_overrides"] = overlays
                        configured = dict(upstream)
                        for overlay in overlays:
                            configured[overlay["path"]] = overlay["configured_sha256"]
                        command = mvn + ["-Dmaven.test.skip=true", "-Dcheckstyle.skip=true", "-Drat.skip=true", "package"]
                        try:
                            run.execute("build", command, cwd=source / case["build_module"], env=env,
                                        timeout=args.timeout, owner=(case["cve_id"], phase, record["commit"]))
                            artifact = primary_jar(source / case["build_module"])
                            destination = run.directory / "artifacts" / case["cve_id"] / phase / artifact.name
                            destination.parent.mkdir(parents=True)
                            shutil.copy2(artifact, destination)
                            record.update(build_status="PASS", artifact_sha256=digest(artifact),
                                          artifact=destination.relative_to(run.directory).as_posix(), module=case["build_module"],
                                          status="PASS", exit_code=0)
                        finally:
                            unexpected = [name for name, h in configured.items() if not (source / name).is_file() or digest(source / name) != h]
                            record["source_integrity"] = {"baseline": "upstream plus explicitly recorded POM overlay",
                                                          "checked_original_files": len(upstream), "changed_files": unexpected}
                            record["upstream_config_changes"] = [o["path"] for o in overlays]
                            require(not unexpected, "Unexpected tracked-source mutation during build")
                except Exception as exc:
                    record.update(status="FAIL", exit_code=getattr(exc, "code", 1), error=str(exc),
                                  error_category=getattr(exc, "category", "VALIDATION"))
                record.update(end_utc=utc(), seconds=round(time.monotonic() - start, 6))
                run.save()
                print(case["cve_id"], phase, record["status"], record.get("error", ""), flush=True)
    error = None if all(s["status"] == "PASS" for s in run.report["snapshots"]) else StepError("One or more recovery builds failed")
    run.finish(error)
    return run.directory


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cve", action="append", choices=TARGETS, required=True)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--python-transport", action="store_true")
    parser.add_argument("--skip-test-staging", action="store_true", help="Jenkins only: explicit POM overlay disables HPI test dependency staging")
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    require(1 <= len(args.cve) <= 2 and len(set(args.cve)) == len(args.cve), "Select one or two unique CVEs")
    directory = recover(args)
    sys.exit(0 if json.loads((directory / "run.json").read_text())["status"] == "PASS" else 1)
