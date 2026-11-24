"""Pinned source acquisition, builds and bounded security checks with explicit evidence."""
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import time

from .build import digest, prepare_maven, tool_paths
from .catalog import ROOT, rows
from .observations import require
from .runtime import StepError, read_run, utc
from .security import parse_probe


def select(cves=None, supported=False):
    cases = rows("cases")
    if cves:
        require(set(cves) <= {c["cve_id"] for c in cases}, "Unknown CVE")
        cases = [c for c in cases if c["cve_id"] in cves]
    if supported:
        require(not cves or all(c["build_module"] is not None for c in cases), "Unsupported CVE; use investigate for Jenkins/NiFi")
        cases = [c for c in cases if c["build_module"] is not None]
    require(bool(cases), "Empty selection")
    return cases


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.PIPE, timeout=120)


def fetch_case(case, repos, run, offline=False, seed=False):
    repo = repos.resolve() / case["cve_id"]
    require(repo.is_relative_to(repos.resolve()), "Invalid repository path")
    if not repo.exists():
        repo.mkdir(parents=True)
        run.execute("git-init", ["git", "init", "--bare", "-q", str(repo)])
    pins = [case[p+"_commit"] for p in ("before", "after")]
    if seed:
        pins += [case["seed_commit"], *case["seed_fix_commits"]]
    for pin in dict.fromkeys(pins):
        exists = subprocess.run(["git", "-C", str(repo), "cat-file", "-e", pin+"^{commit}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        if not exists:
            if offline:
                raise StepError("Pinned commit unavailable in offline cache: "+pin, 3, "OFFLINE_CACHE_MISS")
            run.execute("fetch", ["git", "-C", str(repo), "fetch", "--no-tags", "--depth=2", case["repository_url"], pin], timeout=600,
                        owner=(case["cve_id"], "source", pin))
    for phase in ("before", "after"):
        require(git(repo, "rev-parse", case[phase+"_commit"]+"^{tree}").decode().strip() == case[phase+"_tree"], "Git tree mismatch")
    header = git(repo, "cat-file", "-p", case["after_commit"]).decode().split("\n\n", 1)[0]
    parents = [line.split()[1] for line in header.splitlines() if line.startswith("parent ")]
    require(parents[case["selected_parent_index"]] == case["before_commit"], "Selected parent differs from pinned before commit")
    return repo


def fetch(cases, args, run):
    for case in cases:
        record = dict(cve_id=case["cve_id"], start_utc=utc())
        run.report.setdefault("sources", []).append(record)
        try:
            fetch_case(case, args.repos, run, args.offline, getattr(args, "seed", False))
            record.update(status="PASS", commits={p:case[p+"_commit"] for p in ("before", "after")}, exit_code=0)
        except Exception as exc:
            record.update(status="FAIL", error=str(exc), error_category=getattr(exc, "category", "VALIDATION"), exit_code=getattr(exc,"code",1))
        record["end_utc"] = utc()
        run.save()
        print(case["cve_id"], "fetch", record["status"], flush=True)
    require(all(x["status"] == "PASS" for x in run.report["sources"]), "One or more source fetches failed")


def archive_source(repo, commit, dest):
    data = git(repo, "archive", commit)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        archive.extractall(dest, filter="data")


def primary_jar(work):
    jars = [p for p in (work / "target").glob("*.jar") if not re.search(r"-(sources|javadoc|tests)\.jar$",p.name) and not p.name.startswith("original-")]
    require(len(jars) == 1, "Expected exactly one freshly built primary JAR")
    return jars[0]


def run_probe(case, record, artifact, dependencies, tools, env, run, tmp):
    fixture = ROOT / "fixtures/RegressionProbe.java"
    classes = tmp / "probe"
    classes.mkdir()
    owner = (case["cve_id"], record["phase"], record["commit"])
    run.execute("probe-compile", [tools["jdk"]/"bin/javac", "-encoding", "UTF-8", "-d", classes, fixture], env=env, owner=owner)
    cp = os.pathsep.join(map(str, [classes, artifact, *dependencies]))
    probe_env = dict(env, PILOT_ONLY_MARKER="LITERAL_EXPANSION_SENTINEL")
    output = run.execute("security", [tools["jdk"]/"bin/java", "-cp", cp, "RegressionProbe", case["check"]], env=probe_env, timeout=45, owner=owner)
    tests = parse_probe(case["check"], output)
    record["security"] = dict(status="EXECUTED", process_exit_code=0, fixture_sha256=digest(fixture), tests=tests,
                               controls_pass=all(t["pass"] for t in tests if t["role"] == "control"),
                               all_security_assertions_pass=all(t["pass"] for t in tests if t["role"] == "security"))
    require(record["security"]["controls_pass"], "Security probe control failed")


def pipeline(cases, args, run, experimental=False):
    retry = None
    if args.retry_from:
        _, retry = read_run(args.retry_from)
        require(retry["command"] == run.report["command"] and retry["dataset_sha256"] == run.report["dataset_sha256"], "Retry requires same command and dataset")
        run.report["retry_of"] = retry["run_id"]
        run.report["inherited_successes"] = [{k:r[k] for k in ("cve_id","phase","commit")} for r in retry["snapshots"] if r["status"] == "PASS"]
    failed = {(r["cve_id"],r["phase"]) for r in retry["snapshots"] if r["status"] != "PASS"} if retry else None
    if retry:
        require(bool(failed), "Previous run has no failed snapshots")
    source_path, previous = read_run(args.from_run) if getattr(args,"from_run", None) else (None, None)
    if previous:
        require(previous["dataset_sha256"] == run.report["dataset_sha256"], "Artifact run uses different dataset")
        run.report["artifacts_from_run"] = previous["run_id"]
    profiles = json.loads((ROOT / "data/experimental-builds.json").read_text()) if experimental else {}
    with tempfile.TemporaryDirectory(prefix="javacve-") as session:
        session = Path(session)
        start = time.perf_counter()
        tools = tool_paths(args.prior.resolve())
        env, mvn = prepare_maven(session, tools["jdk"], tools["maven"], args.prior.resolve())
        if args.offline:
            mvn.append("-o")
        run.report["toolchain_setup_seconds"] = round(time.perf_counter()-start,6)
        run.report["toolchain"] = {"java":run.execute("java-version", [tools["jdk"]/"bin/java","-version"], env=env),
                                   "maven":run.execute("maven-version", [tools["maven"]/"bin/mvn","--version"], env=env)}
        spec = json.loads((ROOT/"data/toolchain.json").read_text())
        require(spec["jdk_version"] in run.report["toolchain"]["java"] and "Apache Maven "+spec["maven_version"] in run.report["toolchain"]["maven"], "Toolchain version mismatch")
        for case in cases:
            for phase in ("before", "after"):
                if failed is not None and (case["cve_id"], phase) not in failed:
                    continue
                record = dict(cve_id=case["cve_id"], phase=phase, commit=case[phase+"_commit"], start_utc=utc(), status="running")
                run.report["snapshots"].append(record)
                owner = (case["cve_id"],phase,record["commit"])
                begin = time.perf_counter()
                try:
                    with tempfile.TemporaryDirectory(dir=session) as workdir:
                        tmp = Path(workdir)
                        if previous:
                            candidates = [r for r in previous["snapshots"] if r["cve_id"] == case["cve_id"] and r["phase"] == phase and r["commit"] == record["commit"] and r.get("build_status") == "PASS"]
                            require(len(candidates) == 1, "No verified source-built artifact for selection")
                            old = candidates[0]
                            artifact = (source_path.parent / old["artifact"]).resolve()
                            require(artifact.is_relative_to(source_path.parent), "Artifact outside its run")
                            require(digest(artifact) == old["artifact_sha256"], "Artifact SHA256 mismatch")
                            dependencies = [Path(d["path"]) for d in old.get("dependencies",[])]
                            require(all(digest(p) == d["sha256"] for p,d in zip(dependencies,old.get("dependencies",[]))), "Dependency SHA256 mismatch")
                            record.update(build_status="REUSED_VERIFIED", artifact_sha256=old["artifact_sha256"])
                        else:
                            repo = fetch_case(case, args.repos, run, args.offline)
                            source = tmp / "source"
                            source.mkdir()
                            archive_source(repo, record["commit"], source)
                            profile = profiles.get(case["cve_id"], {})
                            module = profile.get("module", case["build_module"])
                            command = mvn + profile.get("flags", []) + ["-Dmaven.test.skip=true", "-Dcheckstyle.skip=true", "-Drat.skip=true", "package"]
                            build_cwd = source if profile.get("reactor") else source/module
                            run.execute("build", command, cwd=build_cwd, env=env, timeout=args.timeout, owner=owner)
                            artifact = primary_jar(source/module)
                            record.update(build_status="PASS", artifact_sha256=digest(artifact), module=module)
                            target = run.directory / "artifacts" / case["cve_id"] / phase / artifact.name
                            target.parent.mkdir(parents=True)
                            shutil.copyfile(artifact, target)
                            record["artifact"] = str(target.relative_to(run.directory))
                            dependencies = []
                            if case["check"]:
                                classes = tmp / "api"
                                classes.mkdir()
                                run.execute("api-compile", [tools["jdk"]/"bin/javac", "-cp", artifact, "-d", classes, ROOT/"smoke"/case["check"]/"ApiCheck.java"], env=env, owner=owner)
                                output = run.execute("api", [tools["jdk"]/"bin/java", "-cp", os.pathsep.join(map(str,[classes,artifact])), "ApiCheck"], env=env, owner=owner)
                                require(output.splitlines()[-1:] == ["PASS"], "API check missing PASS")
                                record["api_check"] = "PASS"
                            if run.report["command"] in ("security", "all"):
                                cp_file = tmp / "classpath.txt"
                                run.execute("classpath", mvn+["org.apache.maven.plugins:maven-dependency-plugin:3.6.1:build-classpath", "-DincludeScope=runtime", "-Dmdep.outputFile="+str(cp_file)], cwd=source/module, env=env, owner=owner)
                                dependencies = [Path(p) for p in cp_file.read_text().strip().split(os.pathsep) if p]
                                if case["check"] == "plexus-archiver":
                                    run.execute("provided-logger", mvn+["org.apache.maven.plugins:maven-dependency-plugin:3.6.1:get", "-Dartifact=org.codehaus.plexus:plexus-container-default:1.5.5", "-Dtransitive=false"], cwd=source/module,env=env,owner=owner)
                                    cache_arg = next(x for x in mvn if str(x).startswith("-Dmaven.repo.local="))
                                    dependencies.append(Path(str(cache_arg).split("=",1)[1])/"org/codehaus/plexus/plexus-container-default/1.5.5/plexus-container-default-1.5.5.jar")
                                record["dependencies"] = [dict(path=str(p),sha256=digest(p)) for p in dependencies]
                        if run.report["command"] in ("security", "all"):
                            run_probe(case, record, artifact, dependencies, tools, env, run, tmp)
                        if experimental:
                            record["security_status"] = "BLOCKED_NO_INTEGRATION_FIXTURE"
                            record["remaining_evidence"] = profiles[case["cve_id"]]["remaining_evidence"]
                        record.update(status="PASS", exit_code=0)
                except Exception as exc:
                    record.update(status="FAIL", error=str(exc), error_category=getattr(exc,"category","VALIDATION"), exit_code=getattr(exc,"code",1))
                record.update(end_utc=utc(), seconds=round(time.perf_counter()-begin,6))
                run.save()
                print(case["cve_id"], phase, record["status"], record.get("error", ""), flush=True)
    require(bool(run.report["snapshots"]), "No snapshots selected for execution")
    require(all(r["status"] == "PASS" for r in run.report["snapshots"]), "One or more snapshots failed; inspect run.json and retry with --retry-from")
