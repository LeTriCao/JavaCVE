"""Join, audit and optionally export a local, already available source collection."""
from collections import Counter
import json
from pathlib import Path
import tempfile
import os
from .build import digest
from .observations import require
import hashlib
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PHASES = ("before", "after")
LABELS = {"VULNERABLE", "RESOLVED_TARGET", "UNCONFIRMED"}


def rows(table):
    return [json.loads(line) for line in (ROOT / "data" / (table + ".jsonl")).read_text(encoding="utf-8").splitlines()]


def unique(records, key):
    index = {r[key]: r for r in records}
    require(len(index) == len(records), f"Duplicate {key}")
    return index


def verify():
    manifest = json.loads((ROOT / "checksums.json").read_text())
    for name, hashed in manifest.items():
        require(digest(ROOT / name) == hashed, f"SHA-256 mismatch: {name}")
    cases = unique(rows("cases"), "cve_id")
    files = unique(rows("files"), "file_id")
    methods = unique(rows("methods"), "record_id")
    versions = unique(rows("versions"), "sample_id")
    reviews, pairs = rows("reviews"), rows("pairs")
    require(bool(cases), "Empty release")
    for f in files.values():
        require(f["cve_id"] in cases, "Unknown case for file")
        for phase in PHASES:
            require(bool(f["file_path_" + phase]) == bool(f[phase + "_blob"]), "Inconsistent file state")
    expected_versions = set()
    for m in methods.values():
        require(files[m["file_id"]]["cve_id"] == m["cve_id"], "Method owner")
        for p in m["present_phases"]:
            require(p in PHASES, "Unknown phase")
            expected_versions.add(m["record_id"] + ":" + p)
    require(expected_versions == versions.keys(), "Method version coverage")
    for sid, v in versions.items():
        c, phase = v["cve_id"], v["phase"]
        m = methods[v["record_id"]]
        require(sid == m["record_id"] + ":" + phase and c == m["cve_id"], "Sample identity")
        require(v["file_id"] == m["file_id"] and v["file_path"] == files[m["file_id"]]["file_path_" + phase], "Sample source")
        require(v["syntactic_signature"] == m["syntactic_signature"] and v["commit"] == cases[c][phase + "_commit"], "Snapshot identity")
        require(0 < v["start_line"] <= v["end_line"] and v["label"] in LABELS, "Invalid version")
    unique(pairs, "record_id")
    for pair in pairs:
        for phase in PHASES:
            v = versions[pair[phase + "_sample_id"]]
            require(v["phase"] == phase and v["cve_id"] == pair["cve_id"] and v["record_id"] == pair["record_id"] and v["label"] == pair[phase + "_label"], "Pair mismatch")
    review_keys = {(r["cve_id"],r["phase"]) for r in reviews}
    require(len(review_keys) == len(reviews) and review_keys == {(c,p) for c in cases for p in PHASES}, "Review coverage")
    for r in reviews:
        c = cases[r["cve_id"]]
        require(r["decision"] in LABELS and r["commit"] == c[r["phase"] + "_commit"], "Review identity")
        if r["phase"] == "after":
            require(r["decision"] == c["after_label"], "Case label mismatch")
    historic = json.loads((ROOT / "evidence/wsl.json").read_text())["observations"]
    historic_ids = {c for c in cases if "wsl" in cases[c]["evidence_sets"]}
    baseline_ids = {c for c in cases if "matched_build" in cases[c]["evidence_sets"]}
    expected = {(c,p) for c in historic_ids for p in PHASES}
    require(len(historic) == len(expected) and {(r["cve_id"],r["phase"]) for r in historic} == expected, "Historical coverage")
    for r in historic:
        require(r["commit"] == cases[r["cve_id"]][r["phase"] + "_commit"], "Historical commit")
    controls = json.loads((ROOT / "evidence/baseline.json").read_text())
    require(unique(controls, "cve_id").keys() == baseline_ids, "Baseline coverage")
    for r in controls:
        require(r["commit"] == cases[r["cve_id"]]["seed_commit"], "Comparison commit")
    release_build = json.loads((ROOT / "evidence/build-run.json").read_text())
    built = release_build["builds"]
    targets = {(c, p) for c in cases if "release_build" in cases[c]["evidence_sets"] for p in PHASES}
    require(release_build["status"] == "PASS" and len(built) == len(targets) and
            {(r["cve_id"], r["phase"]) for r in built} == targets, "Release build coverage")
    for r in built:
        require(r["commit"] == cases[r["cve_id"]][r["phase"] + "_commit"] and
                r["status"] == r["api_check"] == "PASS", "Release API evidence")
    comparison = json.loads((ROOT / "evidence/comparison-run.json").read_text())
    measured = unique(comparison["comparisons"], "cve_id")
    require(measured.keys() == baseline_ids, "Matched comparison coverage")
    for r in controls:
        other = measured[r["cve_id"]]
        require(r["commit"] == other["commit"] and all(r[k]["status"] == other[k]["status"]
                for k in ("upstream", "pilot")), "Mismatch between benchmark runs")
    expansion = verify_expansion()
    return {"release_builds":len(built), "cves":len(cases), "cwe":dict(Counter(c["target_cwe"] for c in cases.values())),
            "files":len(files), "methods":len(methods), "present_versions":len(versions),
            "labels":dict(Counter(v["label"] for v in versions.values())), "paired_core_methods":len(pairs),
            "reviewed_snapshots":len(reviews), "snapshot_labels":dict(Counter(r["decision"] for r in reviews)),
            "independent_human_reviews":sum(r["independent_human_review"] for r in reviews),
            "historical_wsl_builds":len(historic), "wsl_assertions":sum(sum(t.values()) for r in historic for t in r["checks"].values()),
            "wsl_upstream_tests":sum(r["upstream"]["tests"] for r in historic),
            "matched_upstream_pass":sum(r["upstream"]["status"] == "PASS" for r in controls),
            "matched_pilot_pass":sum(r["pilot"]["status"] == "PASS" for r in controls), "matched_cases":len(controls),"expansion":expansion}


def verify_expansion():
    base = ROOT/"data/batch-02"
    if not base.exists():
        return None
    def table(name,key):
        return unique([json.loads(l) for l in (base/(name+".jsonl")).read_text(encoding="utf-8").splitlines()],key)
    cases,files,methods,versions = table("cases","cve_id"),table("files","file_id"),table("methods","record_id"),table("versions","sample_id")
    require(not (cases.keys() & {c["cve_id"] for c in rows("cases")}),"Expansion/pilot overlap")
    expected = set()
    for f in files.values():
        require(f["cve_id"] in cases,"Unknown batch file CVE")
        for phase in PHASES:
            require(bool(f["file_path_"+phase]) == bool(f[phase+"_blob"]),"Inconsistent batch file state")
    for m in methods.values():
        require(m["file_id"] in files and files[m["file_id"]]["cve_id"] == m["cve_id"],"Batch method owner mismatch")
        require(set(m["present_phases"]) <= set(PHASES) and bool(m["present_phases"]),"Invalid batch method phases")
        expected.update(m["record_id"]+":"+p for p in m["present_phases"])
    require(expected == versions.keys(),"Batch method version coverage")
    for sid,v in versions.items():
        m = methods[v["record_id"]]
        require(v["cve_id"]==m["cve_id"] and v["file_id"]==m["file_id"] and sid==v["record_id"]+":"+v["phase"],"Batch sample identity")
        require(v["commit"]==cases[v["cve_id"]][v["phase"]+"_commit"] and v["file_path"]==files[v["file_id"]]["file_path_"+v["phase"]],"Batch sample source mismatch")
        require(v["label"] in LABELS and 0<v["start_line"]<=v["end_line"] and len(v["code_sha256"])==64,"Invalid batch sample")
        require(v["label"]!="UNCONFIRMED" or bool(v["unknown_reason_group"]),"Missing uncertainty reason")
    completion = json.loads((base/"completion.json").read_text())
    require(completion["labels"]==dict(Counter(v["label"] for v in versions.values())),"Batch completion labels differ")
    return dict(cves=len(cases),methods=len(methods),method_versions=len(versions),labels=completion["labels"],fully_completed=completion["fully_completed"],
                cwe=dict(Counter(c["target_cwe"] for c in cases.values())))


def verify_sources(base, export_to=None, git_repositories=False, include_tests=False):
    base = base.resolve()
    files = rows("files")
    versions = rows("versions")
    blobs = {}
    checked_absences = 0
    cases = unique(rows("cases"), "cve_id")
    for f in files:
        for phase in PHASES:
            rel = f["file_path_" + phase]
            if rel is None:
                if git_repositories:
                    repo = (base / f["cve_id"]).resolve()
                    require(repo.is_relative_to(base), "Invalid Git directory")
                    other = "after" if phase == "before" else "before"
                    opposite_path = f["file_path_" + other]
                    commit = cases[f["cve_id"]][phase + "_commit"]
                    present = subprocess.check_output(["git", "-C", str(repo), "ls-tree", "-z", commit, "--", opposite_path], timeout=60)
                    require(not present, "Expected an absent file")
                    checked_absences += 1
                continue
            if git_repositories:
                repo = (base / f["cve_id"]).resolve()
                require(repo.is_relative_to(base), "Invalid Git directory")
                commit = cases[f["cve_id"]][phase + "_commit"]
                data = subprocess.check_output(["git", "-C", str(repo), "cat-file", "blob", commit + ":" + rel], timeout=60)
            else:
                path = (base / f["cve_id"] / phase / rel).resolve()
                require(path.is_relative_to(base), "Invalid source path")
                data = path.read_bytes()
            blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            require(blob == f[phase + "_blob"], f"Git blob mismatch for {f['file_id']} {phase}")
            blobs[f["file_id"],phase] = data.splitlines(keepends=True)
    export = []
    for v in versions:
        buf = blobs[v["file_id"],v["phase"]]
        require(v["end_line"] <= len(buf), "Method line range outside source")
        code = b"".join(buf[v["start_line"]-1:v["end_line"]]).strip()
        require(hashlib.sha256(code).hexdigest() == v["code_sha256"], f"Method hash mismatch {v['sample_id']}")
        if export_to and (include_tests or not v["is_test"]):
            case = cases[v["cve_id"]]
            review = next(r for r in rows("reviews") if r["cve_id"] == v["cve_id"] and r["phase"] == v["phase"])
            export.append({**v,"code":code.decode("utf-8"), "context":review["scope_vi"],
                           "repository_url":case["repository_url"], "advisory_url":case["advisory_url"],
                           "benchmark_revision":case["benchmark_revision"], "provenance":case["provenance"],
                           "evidence_sets":case["evidence_sets"], "evidence_review":review,
                           "source_url":case["repository_url"]+"/blob/"+v["commit"]+"/"+v["file_path"]+"#L"+str(v["start_line"])})
    if export_to:
        export_to.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive create prevents accidental replacement. Prepare everything before publication.
        with tempfile.NamedTemporaryFile(dir=export_to.parent, mode="w",encoding="utf-8",delete=False) as stream:
            tmp = Path(stream.name)
            for r in export:
                stream.write(json.dumps(r,ensure_ascii=False) + "\n")
        try:
            os.link(tmp, export_to)
        finally:
            tmp.unlink()
    return {"checked_file_versions":len(blobs), "absent_git_states_checked":checked_absences, "checked_method_versions":len(versions),"exported_versions":len(export), "included_tests":include_tests}
