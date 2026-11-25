"""Run one upstream ordinary ZIP extraction test on each pinned Plexus source tree."""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.build import prepare_maven, tool_paths

CVE = "CVE-2023-37460"
REPOSITORY = "https://github.com/codehaus-plexus/plexus-archiver.git"
CLASS = "org.codehaus.plexus.archiver.zip.ZipUnArchiverTest"
METHOD = "testZipMaxOutputSizeEqualToExtractedFileSize"
TEST = Path("src/test/java", *CLASS.split(".")).with_suffix(".java")
ARCHIVE = Path("src/test/jars/test.zip")
TEST_HASH = "fd2a22cb933f9579db2e1d50a871a01e60f55c03ab8386df20989bbe069f94c2"
ARCHIVE_HASH = "31c66140bc0a686d893f4e4f825efe37ac4da21a9809ab7df3613eab94a255f5"
FLAGS = ["-Dtest=" + CLASS + "#" + METHOD, "-DfailIfNoTests=true",
         "-Dsurefire.failIfNoSpecifiedTests=true", "-Dcheckstyle.skip=true", "-Drat.skip=true", "test"]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=120).stdout.decode().strip()


def observe(source, remote, pin, tree, mvn, env, record):
    source.mkdir()
    record["stage"] = "checkout"
    git(source, "init", "-q")
    git(source, "fetch", "--quiet", "--depth=1", remote, pin)
    git(source, "-c", "core.autocrlf=false", "checkout", "--quiet", "--detach", "FETCH_HEAD")
    if git(source, "rev-parse", "HEAD") != pin or git(source, "rev-parse", "HEAD^{tree}") != tree:
        raise ValueError("Source identity mismatch")

    record["stage"] = "common_input"
    record["test_file_sha256"] = sha((source / TEST).read_bytes())
    record["archive_sha256"] = sha((source / ARCHIVE).read_bytes())
    if (record["test_file_sha256"], record["archive_sha256"]) != (TEST_HASH, ARCHIVE_HASH):
        raise ValueError("Unexpected test or input archive")
    with zipfile.ZipFile(source / ARCHIVE) as archive:
        entries = archive.infolist()
        if len(entries) != 1 or entries[0].filename != "test.sh" or entries[0].file_size != 11:
            raise ValueError("Unexpected ZIP member")
        if not stat.S_ISREG(entries[0].external_attr >> 16):
            raise ValueError("Expected an ordinary file")
        expected = archive.read(entries[0])

    record["input_member_sha256"] = sha(expected)
    record["stage"] = "maven_test"
    command = [*mvn, *FLAGS]
    process = subprocess.run(command, cwd=source, env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, timeout=600)
    record["maven_exit"] = process.returncode
    if process.returncode:
        raise ValueError("Maven test failed")
    record["stage"] = "surefire_report"
    reports = list((source / "target/surefire-reports").glob("TEST-*.xml"))
    if len(reports) != 1:
        raise ValueError("Expected one Surefire report")
    suite = ET.parse(reports[0]).getroot()
    counts = {key: int(suite.attrib[key]) for key in ("tests", "failures", "errors", "skipped")}
    record["surefire"] = counts
    tests = suite.findall("testcase")
    if counts != {"tests": 1, "failures": 0, "errors": 0, "skipped": 0} or len(tests) != 1:
        raise ValueError("Expected one executed and passing test")
    if (tests[0].get("classname"), tests[0].get("name")) != (CLASS, METHOD):
        raise ValueError("Surefire selected another method")
    record["stage"] = "extracted_file"
    output = source / "target/zip-size-tests/test.sh"
    if not stat.S_ISREG(output.lstat().st_mode):
        raise ValueError("Output is not a regular file")
    actual = output.read_bytes()
    record["output_bytes"] = len(actual)
    record["output_sha256"] = sha(actual)
    if actual != expected:
        raise ValueError("Extracted bytes differ from archive member")
    record["stage"] = "source_integrity"
    if git(source, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("Tracked upstream source changed during test")
    record.update(status="PASS", stage="complete", tracked_files_changed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repo", type=Path, help="Existing local upstream Git repository")
    parser.add_argument("--dataset-toolchain", action="store_true", help="Use tool versions in data/toolchain.json")
    parser.add_argument("--offline", action="store_true", help="Use Maven's offline mode with the local cache")
    args = parser.parse_args()
    remote = str(args.repo.resolve()) if args.repo else REPOSITORY
    cases = (ROOT / "data/batch-02/cases.jsonl").read_text(encoding="utf-8").splitlines()
    case = next(row for row in map(json.loads, cases) if row["cve_id"] == CVE)
    receipt = {
        "cve_id": CVE, "reviewer": "AI", "scope": "Ordinary ZIP extraction at an 11-byte output limit",
        "upstream": REPOSITORY, "test_class": CLASS, "test_method": METHOD,
        "test_path": TEST.as_posix(), "archive_path": ARCHIVE.as_posix(), "member": "test.sh",
        "maven_test_arguments": FLAGS, "maven_offline": args.offline,
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {"os": platform.system(), "architecture": platform.machine()}, "snapshots": [],
    }
    with tempfile.TemporaryDirectory(prefix="plexus-control-") as tmp:
        base = Path(tmp)
        if args.dataset_toolchain:
            tools = tool_paths(base)
            jdk, maven = tools["jdk"], tools["maven"]
        else:
            jdk = Path(os.environ["JAVA_HOME"]).resolve()
            maven = Path(shutil.which("mvn") or "mvn").resolve().parents[1]
        env, mvn = prepare_maven(base, jdk, maven, base)
        mvn_output = subprocess.check_output([*mvn, "--version"], env=env, stderr=subprocess.STDOUT, text=True)
        receipt["environment"]["maven"] = re.search(r"Apache Maven ([\d.]+)", mvn_output)[1]
        receipt["environment"]["java"] = re.search(r"Java version: ([\w.+-]+)", mvn_output)[1]
        if args.offline:
            mvn.append("--offline")
        for phase in ("before", "after"):
            pin, tree = case[phase + "_commit"], case[phase + "_tree"]
            result = {"phase": phase, "commit": pin, "tree": tree, "status": "FAIL"}
            try:
                observe(base / phase, remote, pin, tree, mvn, env, result)
            except (ValueError, OSError, subprocess.SubprocessError, ET.ParseError) as error:
                result["failure"] = str(error) if isinstance(error, ValueError) else type(error).__name__
            receipt["snapshots"].append(result)
            print(phase, result["status"], result["stage"], flush=True)
    receipt["finished_utc"] = datetime.now(timezone.utc).isoformat()
    receipt["status"] = "PASS" if all(r["status"] == "PASS" for r in receipt["snapshots"]) else "FAIL"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return int(receipt["status"] != "PASS")


if __name__ == "__main__":
    sys.exit(main())
