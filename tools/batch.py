"""Stage a separately versioned expansion batch without changing the pilot denominators."""
from collections import Counter
import csv
import hashlib
import importlib
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

from .catalog import ROOT, rows
from .observations import require
from .pipeline import git, fetch_case
from .quality import write_json
from .runtime import utc


def parser():
    sys.path.insert(0,str(ROOT/".cache/parser"))
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_java
    except ImportError as exc:
        raise RuntimeError("Install requirements-annotation.txt or run python3 tools/bootstrap_parser.py") from exc
    return Parser(Language(tree_sitter_java.language()))


def callables(content, java):
    tree = java.parse(content)
    require(not tree.root_node.has_error,"Java parse has ERROR nodes")
    found = {}
    anonymous_count = 0
    def walk(node, owners=()):
        nonlocal anonymous_count
        if node.type == "object_creation_expression" and any(c.type == "class_body" for c in node.named_children):
            anonymous_count += 1
            owners += ("anonymous_"+str(anonymous_count),)
        if node.type in ("class_declaration","interface_declaration","enum_declaration","record_declaration","annotation_type_declaration"):
            name = node.child_by_field_name("name")
            owners += (content[name.start_byte:name.end_byte].decode(),) if name else ()
        if node.type in ("method_declaration","constructor_declaration","compact_constructor_declaration"):
            name = node.child_by_field_name("name")
            parameters = node.child_by_field_name("parameters")
            signature = ".".join(owners)+"#"+content[name.start_byte:name.end_byte].decode()+re.sub(rb"\s+",b"",content[parameters.start_byte:parameters.end_byte]).decode() if parameters else ".".join(owners)+"#"+content[name.start_byte:name.end_byte].decode()+"()"
            # Distinguish same-named declarations in anonymous/local scopes.
            # This is a syntactic identity only; all expansion labels stay unconfirmed.
            base_signature = signature
            occurrence = 1
            while signature in found:
                occurrence += 1
                signature = base_signature+"@lexical_occurrence_"+str(occurrence)
            # Whole source lines use the same strip convention as the pilot.
            start,end = node.start_point.row+1,node.end_point.row+1
            code = b"".join(content.splitlines(keepends=True)[start-1:end]).strip()
            tokens = []
            def leaves(n):
                if "comment" in n.type:
                    return
                if n.child_count == 0:
                    tokens.append(content[n.start_byte:n.end_byte])
                else:
                    for child in n.children:
                        leaves(child)
            leaves(node)
            found[signature] = dict(start_line=start,end_line=end,code_sha256=hashlib.sha256(code).hexdigest(),
                                    token_hash=hashlib.sha256(b"\0".join(tokens)).hexdigest(),code=code.decode("utf-8"),
                                    token_hash_algorithm="tree-sitter-java-leaves-exclude-comments-NUL-joined-v2")
        for child in node.named_children:
            walk(child,owners)
    walk(tree.root_node)
    return found


def prepare(args, run):
    java = parser()
    spec = json.loads((ROOT/"data/batch-02-selection.json").read_text())
    revision = spec["benchmark_revision"]
    source_root = "https://raw.githubusercontent.com/iris-sast/iris/"+revision+"/data/"
    upstream = {}
    for name in ("project_info.csv","fix_info.csv","build_info.csv"):
        with urllib.request.urlopen(source_root+name,timeout=30) as response:
            content = response.read()
        require(content == (ROOT/"evidence/inputs"/name).read_bytes(),"Archived upstream input differs at pinned revision: "+name)
        upstream[name] = hashlib.sha256(content).hexdigest()
    seeds = {r["cve_id"]:r for r in csv.DictReader((ROOT/"evidence/inputs/project_info.csv").open(encoding="utf-8",newline=""))}
    selection = spec["cases"]
    require(not ({r["cve_id"] for r in selection} & {r["cve_id"] for r in rows("cases")}),"Batch overlaps pilot")
    destination = args.out or run.directory/"batch-02"
    destination.mkdir(parents=True,exist_ok=False)
    (destination/"advisories").mkdir()
    cases,files,methods,versions = [],[],[],[]
    statuses = []
    for selected in selection:
        cve = selected["cve_id"]
        state = dict(cve_id=cve,start_utc=utc(),status="running",reviewer="AI",independent_human_review=False)
        statuses.append(state)
        try:
            seed = seeds[cve]
            fixes = seed["fix_commit_ids"].split(";")
            require(len(fixes)==1 or "selected_fix_index" in selected,"Multiple seed fixes require a documented choice")
            repo = args.repos.resolve()/cve
            if not repo.exists():
                repo.mkdir(parents=True)
                run.execute("git-init",["git","init","--bare","-q",repo])
            pin = fixes[selected.get("selected_fix_index",0)]
            exists = subprocess.run(["git","-C",str(repo),"cat-file","-e",pin+"^{commit}"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
            if not exists:
                require(not args.offline,"Missing batch commit in offline cache")
                run.execute("fetch",["git","-C",repo,"fetch","--no-tags","--depth=2",seed["github_url"],pin],owner=(cve,"after",pin))
            header = git(repo,"cat-file","-p",pin).decode().split("\n\n",1)[0]
            parents = [l.split()[1] for l in header.splitlines() if l.startswith("parent ")]
            require(len(parents)==1 or "selected_parent_index" in selected,"Expansion merge commit requires explicit parent choice")
            before = parents[selected.get("selected_parent_index",0)]
            with urllib.request.urlopen(urllib.request.Request("https://api.github.com/advisories/"+seed["advisory_id"],headers={"User-Agent":"JavaCVE-academic-dataset"}),timeout=30) as response:
                advisory = json.load(response)
            require(advisory["cve_id"] == cve,"Advisory/CVE mismatch")
            write_json(destination/"advisories"/(cve+".json"),advisory)
            cwe = "CWE-"+str(int(seed["cwe_id"].split("-")[1]))
            advisory_cwes = [c["cwe_id"] for c in advisory.get("cwes",[])]
            case = dict(cve_id=cve,target_cwe=cwe,project=seed["github_username"]+"/"+seed["github_repository_name"],
                        repository_url=seed["github_url"],advisory_url=advisory["html_url"],advisory_cwe_ids=advisory_cwes,
                        cwe_alignment="MATCH" if cwe in advisory_cwes else "SEED_CLASSIFICATION_DIFFERS_OR_ADVISORY_UNSPECIFIED",
                        seed_commit=seed["buggy_commit_id"],seed_fix_commits=fixes,before_commit=before,after_commit=pin,
                        before_tree=git(repo,"rev-parse",before+"^{tree}").decode().strip(),after_tree=git(repo,"rev-parse",pin+"^{tree}").decode().strip(),
                        selected_parent_index=selected.get("selected_parent_index",0),selection_decisions=selected,
                        provenance="seed_fix_selected_parent_verified",benchmark_revision=revision,
                        build_module=selected["module"],check=None,after_label="UNCONFIRMED",evidence_sets=[],archive_sha256={},
                        label_scope="CVE and patch metadata verified; callable semantic labels pending scoped review and behavior evidence.")
            case_files,case_methods,case_versions = [],[],[]
            paths = git(repo,"diff","--name-status","--no-renames",before,pin,"--","*.java").decode().splitlines()
            for line in paths:
                change,path = line.split("\t",1)
                fid = cve+"-file-"+hashlib.sha256(path.encode()).hexdigest()[:12]
                file_row = dict(file_id=fid,cve_id=cve,change_type={"A":"added","D":"removed"}.get(change,"modified"))
                parsed = {}
                for phase,commit in (("before",before),("after",pin)):
                    present = not ((change=="A" and phase=="before") or (change=="D" and phase=="after"))
                    file_row["file_path_"+phase] = path if present else None
                    file_row[phase+"_blob"] = git(repo,"rev-parse",commit+":"+path).decode().strip() if present else None
                    parsed[phase] = callables(git(repo,"show",commit+":"+path),java) if present else {}
                case_files.append(file_row)
                for signature in sorted(parsed["before"].keys() | parsed["after"].keys()):
                    b,a = parsed["before"].get(signature),parsed["after"].get(signature)
                    if b and a and b["code_sha256"]==a["code_sha256"]:
                        continue
                    rid = cve+"-"+hashlib.sha256((path+signature).encode()).hexdigest()[:12]
                    phases = [p for p in ("before","after") if signature in parsed[p]]
                    is_test = "/test/" in path or path.startswith("src/test")
                    case_methods.append(dict(record_id=rid,file_id=fid,cve_id=cve,syntactic_signature=signature,
                                             signature_kind="AST_syntactic_not_resolved_JVM",present_phases=phases,
                                             change_type="modified" if len(phases)==2 else "added" if phases==["after"] else "removed",is_test=is_test))
                    for phase in phases:
                        value = parsed[phase][signature]
                        case_versions.append(dict(sample_id=rid+":"+phase,record_id=rid,file_id=fid,cve_id=cve,phase=phase,
                                                  commit=case[phase+"_commit"],file_path=path,syntactic_signature=signature,
                                                  **{k:v for k,v in value.items() if k!="code"},label="UNCONFIRMED",rule_id="B02_PENDING",
                                                  unknown_reason_group="NEW_BATCH_REQUIRES_CONTEXT_AND_BEHAVIOR",requires_context=True,
                                                  is_test=is_test,split="batch02_pending",reviewer="AI",independent_human_review=False,
                                                  evidence_needed="Independent scoped method review, caller/data flow context and paired security behavior fixture.",
                                                  advisory_url=case["advisory_url"],repository_url=case["repository_url"]))
            require(bool(case_versions),"No changed callable versions extracted")
            cases.append(case)
            prefix = "" if case["build_module"] == "." else case["build_module"].rstrip("/")+"/"
            case["upstream_tests"] = sorted({Path(f["file_path_after"]).stem for f in case_files if f["file_path_after"] and f["file_path_after"].startswith(prefix+"src/test/")})
            files.extend(case_files)
            methods.extend(case_methods)
            versions.extend(case_versions)
            state.update(status="SOURCE_NORMALIZED_LABELS_UNCONFIRMED",files=len(case_files),methods=len(case_methods),versions=len(case_versions),
                         cwe_alignment=case["cwe_alignment"],build_status="NOT_RUN",security_status="BLOCKED_NO_REVIEWED_FIXTURE",fully_completed=False)
        except Exception as exc:
            state.update(status="BLOCKED",reason=str(exc),fully_completed=False)
        state["end_utc"] = utc()
        run.report["batch_status"] = statuses
        run.save()
        print(cve,state["status"],state.get("reason",""),flush=True)
    for name,records in (("cases",cases),("files",files),("methods",methods),("versions",versions)):
        (destination/(name+".jsonl")).write_text("".join(json.dumps(r,ensure_ascii=False)+"\n" for r in records),encoding="utf-8")
    summary = dict(batch_id=spec["batch_id"],benchmark_revision=revision,upstream_sha256=upstream,selected=len(selection),
                   source_normalized=len(cases),fully_completed=0,method_versions=len(versions),labels=dict(Counter(v["label"] for v in versions)),
                   cases=statuses,completion_definition="Verified source, normalized/extracted methods, scoped semantic review, successful builds and reviewed paired security behavior evidence; UNCONFIRMED is never a safe negative.")
    write_json(destination/"summary.json",summary)
    run.report["batch"] = summary
    require(all(s["status"]=="SOURCE_NORMALIZED_LABELS_UNCONFIRMED" for s in statuses),"Expansion contains blocked profiles; summary and completed records retained")
    return destination


def batch_cases(folder,cves=None):
    cases = [json.loads(l) for l in (folder/"cases.jsonl").read_text(encoding="utf-8").splitlines()]
    files = [json.loads(l) for l in (folder/"files.jsonl").read_text(encoding="utf-8").splitlines()]
    for case in cases:
        if case["cve_id"] == "CVE-2022-4244":
            case["check"] = "plexus-expand"
        prefix = "" if case["build_module"] == "." else case["build_module"].rstrip("/")+"/"
        case.setdefault("upstream_tests",sorted({Path(f["file_path_after"]).stem for f in files if f["cve_id"]==case["cve_id"] and f["file_path_after"] and f["file_path_after"].startswith(prefix+"src/test/")}))
    require(not cves or set(cves)<={c["cve_id"] for c in cases},"Unknown batch CVE")
    return [c for c in cases if not cves or c["cve_id"] in cves]


def verify_batch(folder,repos,export_to=None,include_tests=False):
    cases = {c["cve_id"]:c for c in batch_cases(folder)}
    tables = {name:[json.loads(l) for l in (folder/(name+".jsonl")).read_text(encoding="utf-8").splitlines()] for name in ("files","methods","versions")}
    require(len({v["sample_id"] for v in tables["versions"]})==len(tables["versions"]),"Duplicate batch sample")
    methods = {m["record_id"]:m for m in tables["methods"]}
    require({m["record_id"]+":"+p for m in methods.values() for p in m["present_phases"]}=={v["sample_id"] for v in tables["versions"]},"Batch version coverage")
    contents = {}
    absences = 0
    for f in tables["files"]:
        case = cases[f["cve_id"]]
        repo = repos.resolve()/f["cve_id"]
        require(repo.is_relative_to(repos.resolve()),"Invalid batch repository")
        for phase in ("before","after"):
            path = f["file_path_"+phase]
            commit = case[phase+"_commit"]
            if path is None:
                other = f["file_path_"+("after" if phase=="before" else "before")]
                require(not git(repo,"ls-tree",commit,"--",other),"Expected absent batch file")
                absences += 1
                continue
            content = git(repo,"show",commit+":"+path)
            blob = hashlib.sha1(b"blob "+str(len(content)).encode()+b"\0"+content).hexdigest()
            require(blob==f[phase+"_blob"],"Batch source blob mismatch")
            contents[f["file_id"],phase] = content
    exported = []
    for v in tables["versions"]:
        case = cases[v["cve_id"]]
        require(v["commit"]==case[v["phase"]+"_commit"] and v["record_id"] in methods,"Batch mapping mismatch")
        lines = contents[v["file_id"],v["phase"]].splitlines(keepends=True)
        require(0<v["start_line"]<=v["end_line"]<=len(lines),"Invalid batch line range")
        code = b"".join(lines[v["start_line"]-1:v["end_line"]]).strip()
        require(hashlib.sha256(code).hexdigest()==v["code_sha256"],"Batch method SHA256 mismatch")
        if include_tests or not v["is_test"]:
            exported.append({**v,"code":code.decode("utf-8"),"context":case["label_scope"],"benchmark_revision":case["benchmark_revision"]})
    if export_to:
        export_to.parent.mkdir(parents=True,exist_ok=True)
        with export_to.open("x",encoding="utf-8") as stream:
            for v in exported:
                stream.write(json.dumps(v,ensure_ascii=False)+"\n")
    return dict(checked_cases=len(cases),checked_file_versions=len(contents),absent_git_states_checked=absences,
                checked_method_versions=len(tables["versions"]),exported_versions=len(exported) if export_to else 0,
                label_status="UNCONFIRMED: identities verified; semantic labels and paired security evidence pending",reviewer="AI")
