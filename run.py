"""Command line entry point for the JavaCVE pilot."""
import argparse
import datetime
import json
import os
import platform
import sys
import uuid
from pathlib import Path
from tools.catalog import ROOT, rows, verify, verify_sources
from tools.observations import read_archive, require
from tools.build import build


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("demo", help="Verify the release and display its dataset statistics")
    all_cmd = commands.add_parser("all", help="Verify data, build paired Java modules and run ordinary API tests")
    all_cmd.add_argument("--prior", type=Path, default=ROOT.parent / "JavaCVE_Reproducible", help="Optional existing toolchain and archives")
    all_cmd.add_argument("--cve", action="append", help="Limit to a CVE marked buildable in the catalog")
    check = commands.add_parser("verify-source", help="Verify Java files and method texts in an existing stage 3 cases folder")
    check.add_argument("cases_dir", type=Path)
    check.add_argument("--git-repos", action="store_true", help="Read local Git repositories named by CVE with both commits available")
    check.add_argument("--export", type=Path, help="New local JSONL file with verified production source texts")
    audit = commands.add_parser("audit-wsl", help="Compare the archived evidence with the published observations")
    audit.add_argument("archive", type=Path)
    comp = commands.add_parser("compare", help="Build the same benchmark seeds using the two pipelines")
    for flag in ("upstream", "jdk", "maven", "m2"):
        comp.add_argument("--" + flag, type=Path, required=True)
    args = parser.parse_args()
    run_id = uuid.uuid4().hex
    directory = ROOT / "runs" / run_id
    directory.mkdir(parents=True)
    output = directory / "run.json"
    report = {"run_id":run_id, "release":"0.1.0", "command":args.action, "start_utc":utc(),
              "status":"running", "environment":{"system":platform.system(),"architecture":platform.machine(),
              "python":platform.python_version()}}

    def save():
        tmp = output.with_suffix(".tmp")
        tmp.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, output)

    save()
    try:
        report["catalog"] = verify()
        if args.action == "demo":
            print(json.dumps(report["catalog"], ensure_ascii=False, indent=2))
        elif args.action == "audit-wsl":
            observed = read_archive(args.archive, rows("cases"))
            expected = json.loads((ROOT / "evidence/wsl.json").read_text())
            require(observed["observations"] == expected["observations"], "Different WSL observations")
            report["archive_sha256"] = observed["archive_sha256"]
            report["identical_submitted_archive"] = observed["archive_sha256"] == expected["archive_sha256"]
        elif args.action == "compare":
            from tools.compare import run_comparison
            run_comparison(args, [c for c in rows("cases") if "matched_build" in c["evidence_sets"]], report, save)
        elif args.action == "verify-source":
            report["source_review"] = verify_sources(args.cases_dir, args.export, args.git_repos)
        else:
            selected = [c for c in rows("cases") if c["build_module"] is not None and (not args.cve or c["cve_id"] in args.cve)]
            require(bool(selected) and (not args.cve or set(args.cve) == {c["cve_id"] for c in selected}), "Unknown or unsupported CVE")
            report["builds"] = []
            report["selection"] = [c["cve_id"] for c in selected]
            build(selected, args.prior.resolve(), report, save)
        report["status"] = "PASS"
    except Exception as exc:
        report.update(status="FAIL", error_type=type(exc).__name__)
        print(str(exc), file=sys.stderr)
    finally:
        report["end_utc"] = utc()
        save()
    print(report["status"], output.relative_to(ROOT))
    return int(report["status"] != "PASS")


if __name__ == "__main__":
    sys.exit(main())
