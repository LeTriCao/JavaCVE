"""JavaCVE: inspect, acquire, build, test and audit version-pinned Java CVE samples."""
import argparse
import json
from pathlib import Path
import sys
from tools.catalog import ROOT, rows, verify, verify_sources
from tools.observations import read_archive, require
from tools.runtime import Run


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    cmds = p.add_subparsers(dest="action", required=True)
    cmds.add_parser("demo", help="Offline release and catalog verification")
    doctor = cmds.add_parser("doctor", help="Inspect local tools and optional repository connectivity")
    doctor.add_argument("--network", action="store_true")
    batch = cmds.add_parser("expand", help="Prepare separate batch-02, preserving uncertain labels")
    batch.add_argument("--out", type=Path)
    batch.add_argument("--repos", type=Path,default=ROOT/".cache/batch02-repos")
    batch.add_argument("--offline", action="store_true")
    batch_build = cmds.add_parser("batch-build", help="Attempt normalized batch sources and changed upstream test classes")
    batch_build.add_argument("batch_dir",type=Path)
    batch_build.add_argument("--cve",action="append")
    batch_build.add_argument("--repos",type=Path,default=ROOT/".cache/batch02-repos")
    batch_build.add_argument("--prior",type=Path,default=ROOT.parent/"JavaCVE_Reproducible")
    batch_build.add_argument("--timeout",type=int,default=120)
    batch_build.add_argument("--offline",action="store_true")
    batch_build.add_argument("--retry-from",type=Path)
    batch_build.add_argument("--upstream-repositories",action="store_true")
    listing = cmds.add_parser("list", help="List CVEs, projects, CWEs and evidence status")
    for flag in ("project", "cwe", "status"):
        listing.add_argument("--"+flag)
    listing.add_argument("--json", action="store_true")
    for name in ("fetch", "build", "security", "all", "investigate", "measure"):
        c = cmds.add_parser(name, help={"fetch":"Download locked source commits", "build":"Build paired snapshots and ordinary API checks", "security":"Build and run existing security probes", "all":"Build, API checks and security probes", "investigate":"Attempt the four Jenkins/NiFi build profiles", "measure":"Recompute seed-to-fix versus parent-to-fix Java file counts"}[name])
        c.add_argument("--cve", action="append")
        c.add_argument("--repos", type=Path, default=ROOT/".cache/repos")
        c.add_argument("--offline", action="store_true")
        c.add_argument("--prior", type=Path, default=ROOT.parent/"JavaCVE_Reproducible")
        c.add_argument("--timeout", type=int, default=600)
        c.add_argument("--retry-from", type=Path)
        c.add_argument("--from-run", type=Path, help="security only: replay verified source-built artifacts from this run")
        c.add_argument("--seed", action="store_true", help="Also acquire original benchmark commits")
        c.add_argument("--upstream-repositories", action="store_true", help="Experimental: enable explicit Jenkins HTTPS repositories")
    for name in ("verify-source", "export", "audit"):
        c = cmds.add_parser(name, help="Verify source blobs, line ranges and method hashes")
        c.add_argument("cases_dir", nargs="?", type=Path, default=ROOT/".cache/repos")
        c.add_argument("--git-repos", action="store_true", help="Read pinned Git objects (default for managed cache)")
        c.add_argument("--export", type=Path)
        c.add_argument("--include-tests", action="store_true")
        c.add_argument("--batch",type=Path,help="Verify/export separately normalized expansion batch")
    archive = cmds.add_parser("audit-wsl", help="Validate historical results.zip without executing its content")
    archive.add_argument("archive", type=Path)
    comp = cmds.add_parser("compare", help="Matched-seed build experiment using original IRIS scripts")
    for flag in ("upstream", "jdk", "maven", "m2"):
        comp.add_argument("--"+flag, type=Path, required=True)
    for name in ("stats", "report", "split"):
        c = cmds.add_parser(name)
        c.add_argument("--run", action="append", type=Path, default=[])
        c.add_argument("--out", type=Path, help="New output directory; existing paths are never overwritten")
        c.add_argument("--unit", choices=("project", "cve"), default="project")
        c.add_argument("--with-batch",type=Path,help="split: include this expansion batch, recomputing common token hashes")
        c.add_argument("--repos",type=Path,default=ROOT/".cache/repos")
        c.add_argument("--batch-repos",type=Path,default=ROOT/".cache/batch02-repos")
    cmds.add_parser("seal", help="Maintainer: regenerate release checksums after reviewed changes")
    return p


def main():
    p = parser()
    args = p.parse_args()
    if args.action == "seal":
        from tools.checksums import seal
        seal()
        return 0
    if getattr(args,"from_run",None) and args.action != "security":
        p.error("--from-run is supported only by security")
    run = Run(args.action, " ".join(sys.argv[1:]))
    error = None
    try:
        run.report["catalog"] = verify()
        if args.action == "demo":
            print(json.dumps(run.report["catalog"],ensure_ascii=False,indent=2))
        elif args.action == "doctor":
            from tools.doctor import diagnose
            run.report["diagnostics"] = diagnose(args.network)
            print(json.dumps(run.report["diagnostics"],ensure_ascii=False,indent=2))
        elif args.action == "expand":
            from tools.batch import prepare
            prepare(args,run)
        elif args.action == "batch-build":
            import hashlib
            from tools.pipeline import pipeline
            from tools.batch import batch_cases
            run.report["batch_dataset_sha256"] = hashlib.sha256((args.batch_dir/"versions.jsonl").read_bytes()).hexdigest()
            pipeline(batch_cases(args.batch_dir,args.cve),args,run)
        elif args.action == "list":
            from tools.quality import list_cases
            selected = list_cases(args)
            run.report["cases"] = selected
            if args.json:
                print(json.dumps(selected,ensure_ascii=False,indent=2))
            else:
                for c in selected:
                    print(c["cve_id"], c["target_cwe"], c["project"], c["verification_status"], "after="+c["after_label"])
        elif args.action == "audit-wsl":
            observed = read_archive(args.archive, rows("cases"))
            expected = json.loads((ROOT/"evidence/wsl.json").read_text())
            require(observed["observations"] == expected["observations"], "Different WSL observations")
            run.report.update(archive_sha256=observed["archive_sha256"], identical_submitted_archive=observed["archive_sha256"] == expected["archive_sha256"])
        elif args.action == "compare":
            from tools.compare import run_comparison
            run_comparison(args, [c for c in rows("cases") if "matched_build" in c["evidence_sets"]], run.report, run.save)
        elif args.action in ("verify-source", "export", "audit"):
            base = args.cases_dir.resolve()
            is_git = args.git_repos or base == (ROOT/".cache/repos").resolve()
            destination = args.export
            if args.action == "export" and destination is None:
                destination = run.directory/"methods.jsonl"
            if args.batch:
                from tools.batch import verify_batch
                run.report["source_review"] = verify_batch(args.batch,base,destination,args.include_tests)
            else:
                run.report["source_review"] = verify_sources(base,destination,is_git,args.include_tests)
            if args.action == "audit" and not args.batch:
                from tools.quality import quality_review
                run.report["quality"] = quality_review(run)
        elif args.action in ("stats", "report", "split"):
            from tools.quality import generate_report, make_split
            if args.action == "split":
                run.report["split"] = make_split(args,run)
            else:
                run.report["statistics"] = generate_report(args,run)
        else:
            from tools.pipeline import select, fetch, pipeline
            cases = select(args.cve,args.action in ("build", "security", "all"))
            if args.action == "investigate":
                cases = [c for c in cases if c["build_module"] is None]
                require(bool(cases), "No experimental CVEs selected")
            run.report["selection"] = [c["cve_id"] for c in cases]
            if args.action in ("fetch", "measure"):
                if args.action == "measure":
                    args.seed = True
                fetch(cases,args,run)
                if args.action == "measure":
                    from tools.quality import measure_files
                    run.report["file_comparison"] = measure_files(cases,args.repos,run)
            else:
                pipeline(cases,args,run,args.action == "investigate")
    except (Exception,KeyboardInterrupt) as exc:
        error = exc
        print(str(exc),file=sys.stderr)
    finally:
        run.finish(error)
    return 0 if error is None else min(max(getattr(error,"code",1),1),125)


if __name__ == "__main__":
    sys.exit(main())
