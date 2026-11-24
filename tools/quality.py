"""Recomputable metrics, scoped AI review and leakage-aware research partitions."""
from collections import Counter, defaultdict
import csv
import hashlib
import io
import json
from pathlib import Path

from .catalog import ROOT, rows
from .observations import require
from .runtime import read_run


def write_json(path, value):
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")


def list_cases(args):
    result = []
    for c in rows("cases"):
        status = "HISTORICAL_BUILD_AND_BEHAVIOR" if "wsl" in c["evidence_sets"] else "STATIC_REVIEW_ONLY"
        if args.project and args.project.lower() not in c["project"].lower():
            continue
        if args.cwe and args.cwe != c["target_cwe"]:
            continue
        if args.status and args.status != status:
            continue
        result.append({**c,"verification_status":status})
    return result


def measure_files(cases, repos, run):
    from .pipeline import git
    measurements = []
    for c in cases:
        repo = repos/c["cve_id"]
        def changed(start,end):
            return sorted(set(git(repo,"diff","--name-only","--no-renames",start,end,"--","*.java").decode().splitlines()))
        same_fix = c["seed_fix_commits"] == [c["after_commit"]]
        original = changed(c["seed_commit"],c["after_commit"]) if same_fix else None
        normalized = changed(c["before_commit"],c["after_commit"])
        indexed = sorted({f["file_path_after"] or f["file_path_before"] for f in rows("files") if f["cve_id"] == c["cve_id"]})
        require(normalized == indexed, "Changed Java paths differ from indexed files: "+c["cve_id"])
        measurements.append(dict(cve_id=c["cve_id"],same_fix=same_fix,seed_commit=c["seed_commit"],
                                 before_commit=c["before_commit"],after_commit=c["after_commit"],
                                 original_paths=original,normalized_paths=normalized,
                                 original_count=len(original) if original is not None else None,normalized_count=len(normalized)))
    matched = [r for r in measurements if r["same_fix"]]
    before = sum(r["original_count"] for r in matched)
    after = sum(r["normalized_count"] for r in matched)
    result = dict(scope="unique changed .java paths per CVE; no rename detection; identical fix commit",
                  cases=measurements,matched_cves=len(matched),original_java_files=before,normalized_java_files=after,
                  reduction_percent=round(100*(before-after)/before,6) if before else None,
                  corrected_fix_mappings=sum(not r["same_fix"] for r in measurements),normalized_pairs=len(measurements),
                  reported_60_to_33_verified=(len(matched),before,after)==(9,60,33))
    write_json(run.directory/"file-comparison.json",result)
    return result


def quality_review(run):
    versions = rows("versions")
    reviews = {(r["cve_id"],r["phase"]):r for r in rows("reviews")}
    unknown = []
    for v in versions:
        if v["label"] != "UNCONFIRMED":
            continue
        group = v["unknown_reason_group"]
        need = "Independent reviewer must assess the callable's data flow, callers and CVE scope before assigning a binary label."
        if v["requires_context"]:
            need += " Resolve caller reachability, trust boundary and execution preconditions; add a paired behavior fixture if feasible."
        unknown.append(dict(sample_id=v["sample_id"],reason_group=group,rule_id=v["rule_id"],
                            requires_context=v["requires_context"],evidence_needed=need,
                            scope=reviews[v["cve_id"],v["phase"]]["scope_vi"],reviewer="AI",independent_human_review=False))
    duplicates = defaultdict(list)
    for v in versions:
        duplicates[v["token_hash"]].append(v["sample_id"])
    result = dict(reviewer="AI",independent_human_reviews=0,
                  identity_checks=run.report["source_review"],
                  semantic_review="Inherited scoped decisions re-examined for linkage and uncertainty; identities do not establish semantic correctness.",
                  unknown_versions=len(unknown),unknown_reasons=dict(Counter(v["unknown_reason_group"] for v in versions if v["label"] == "UNCONFIRMED")),
                  distinct_token_hashes=len(duplicates),duplicate_token_groups=[dict(token_hash=h,samples=s) for h,s in duplicates.items() if len(s)>1],
                  independent_review_required=["All non-UNCONFIRMED method labels", "Advisory scope and exploit preconditions", "Docker Commons caller chain", "NiFi optional provider and cross-module reachability", "Reconstructed zip4j source/license provenance"])
    write_json(run.directory/"unconfirmed.json",unknown)
    write_json(run.directory/"quality-review.json",result)
    return result


def ratio(n,d,unit,scope):
    return dict(numerator=n,denominator=d,unit=unit,scope=scope,percent=round(100*n/d,6) if d else None)


def generate_report(args, run):
    destination = args.out or run.directory/"report"
    destination.mkdir(parents=True,exist_ok=False)
    cases, versions = rows("cases"), rows("versions")
    historic = json.loads((ROOT/"evidence/wsl.json").read_text())["observations"]
    baseline = json.loads((ROOT/"evidence/baseline.json").read_text())
    input_runs = [read_run(p) for p in args.run]
    observed = [r for _,data in input_runs for r in data.get("snapshots",[])]
    require(len({(r["cve_id"],r["phase"]) for r in observed}) == len(observed), "Reports require disjoint snapshot observations; choose one experiment per snapshot")
    measurements = [data["file_comparison"] for _,data in input_runs if "file_comparison" in data]
    integrity = [data["source_review"] for _,data in input_runs if "source_review" in data]
    behavior = [r for r in observed if r.get("security",{}).get("status") == "EXECUTED"]
    behavior_ids = {r["cve_id"] for r in behavior}
    reproduced = 0
    for c in behavior_ids:
        pair = {r["phase"]:r for r in behavior if r["cve_id"] == c}
        if pair.keys() != {"before","after"}:
            continue
        b = {t["name"]:t for t in pair["before"]["security"]["tests"]}
        a = {t["name"]:t for t in pair["after"]["security"]["tests"]}
        if pair["before"]["security"]["controls_pass"] and pair["after"]["security"]["controls_pass"] and any(t["role"] == "security" and not t["pass"] and a.get(n,{}).get("pass") for n,t in b.items()):
            reproduced += 1
    paired_ids = {r["cve_id"] for r in observed if r.get("build_status") == "PASS" and all(any(x["cve_id"]==r["cve_id"] and x["phase"]==p and x.get("build_status")=="PASS" for x in observed) for p in ("before","after"))}
    after_fail = sum(r["phase"] == "after" and not r["security"]["all_security_assertions_pass"] for r in behavior)
    result = dict(catalog=run.report["catalog"], input_runs=[dict(run_id=d["run_id"],command=d["command"],sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p,d in input_runs],
                  historical=dict(matched_upstream_build=ratio(sum(r["upstream"]["status"]=="PASS" for r in baseline),len(baseline),"seed snapshots","Same original commits, JDK8, Maven3.5.0 and module scope"),
                                  matched_pilot_build=ratio(sum(r["pilot"]["status"]=="PASS" for r in baseline),len(baseline),"seed snapshots","Same original commits and conditions"),
                                  paired_build=ratio(len(historic)//2,len(cases),"CVEs","Pilot coverage with both snapshots source-built; four CVEs unmeasured"),
                                  security_assertions=dict(passed=sum(r["checks"]["security"]["pass"] for r in historic),failed=sum(r["checks"]["security"]["fail"] for r in historic)),
                                  after_security_failing_snapshots=sum(r["phase"]=="after" and r["checks"]["security"]["fail"]>0 for r in historic)),
                  current=dict(build_snapshots=ratio(sum(r.get("build_status")=="PASS" for r in observed),len(observed),"snapshots","Explicit input runs; excludes reused artifacts"),
                               paired_build_pilot=ratio(len(paired_ids),len(cases),"CVEs","All 10 pilot CVEs; selected module scope"),
                               behavior_reproduction=ratio(reproduced,len(behavior_ids),"CVEs","At least one security FAIL to PASS with passing controls on both sides"),
                               behavior_pilot_coverage=ratio(reproduced,len(cases),"CVEs","All pilot CVEs"),
                               after_security_failing_snapshots=after_fail,
                               after_security_measured_snapshots=sum(r["phase"]=="after" for r in behavior),
                               integrity=ratio(max((r["checked_method_versions"] for r in integrity),default=0),len(versions),"present method versions","Byte hashes and line ranges verified from actual source in input runs")),
                  file_comparison=measurements[0] if len(measurements)==1 else None,
                  measured_stage_seconds=dict(Counter({name:round(sum(s["seconds"] for _,d in input_runs for s in d.get("steps",[]) if s["stage"]==name),6) for name in ("fetch","build","classpath","api","security")})),
                  timing_conditions="Wall-clock subprocess durations; current cache/network and toolchain. No matched timing baseline or measured human annotation time.",
                  manual_interventions="Not comprehensively timed; see docs/EXPERIMENTS.md. No labor saving or model accuracy claim.",
                  independent_human_reviews=0)
    write_json(destination/"metrics.json",result)
    with (destination/"cases.csv").open("w",encoding="utf-8",newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["cve_id","project","cwe","before_commit","after_commit","after_label","historical_build_pair","current_build_pair"])
        for c in cases:
            writer.writerow([c["cve_id"],c["project"],c["target_cwe"],c["before_commit"],c["after_commit"],c["after_label"],"wsl" in c["evidence_sets"],c["cve_id"] in paired_ids])
    lines = ["# Báo cáo JavaCVE v0.2.0", "", "Bảng được sinh bằng `python3 run.py report`; số liệu lịch sử và lượt chạy mới được ghi riêng.", "", "| Chỉ tiêu | Kết quả | Phạm vi |", "|---|---:|---|",
             f"| CVE / phương thức / phiên bản | {len(cases)} / {run.report['catalog']['methods']} / {len(versions)} | Pilot |",
             f"| Nhãn | {json.dumps(Counter(v['label'] for v in versions))} | Phiên bản phương thức |",
             f"| Build đối chứng IRIS / pilot | {result['historical']['matched_upstream_build']['numerator']}/{len(baseline)} / {result['historical']['matched_pilot_build']['numerator']}/{len(baseline)} | Cùng seed, JDK, Maven, mô-đun; lịch sử |",
             f"| Build mới | {result['current']['build_snapshots']['numerator']}/{len(observed)} | Snapshot trong các run đầu vào |",
             f"| Tái hiện hành vi mới | {reproduced}/{len(behavior_ids)} | CVE có đo hành vi; yêu cầu đối chứng đạt |",
             f"| Phủ hành vi trên pilot | {reproduced}/{len(cases)} | Toàn bộ pilot |",
             f"| Bản sau còn assertion bảo mật FAIL | {after_fail}/{result['current']['after_security_measured_snapshots']} | Bản sau đã đo |",
             f"| Toàn vẹn phương thức mới | {result['current']['integrity']['numerator']}/{len(versions)} | Phiên bản hiện diện |", "| Người đánh giá độc lập | 0 | Lượt rà soát hiện do AI |"]
    if result["file_comparison"]:
        f = result["file_comparison"]
        lines += [f"| Tệp Java trước → sau chuẩn hóa | {f['original_java_files']} → {f['normalized_java_files']} | {f['matched_cves']} CVE giữ commit sửa; giảm {f['reduction_percent']}% |", f"| Ánh xạ commit sửa hiệu chỉnh | {f['corrected_fix_mappings']}/{len(f['cases'])} | So SHA gốc với SHA đã chọn |", f"| Cặp chuẩn hóa | {f['normalized_pairs']}/{len(cases)} | Git xác nhận parent được chọn |"]
    lines += ["", "Thời gian từng bước (giây): `"+json.dumps(result["measured_stage_seconds"])+"`.", "", "Giới hạn: thời gian mạng/cache không được kiểm soát giữa hai quy trình; chưa đo lao động theo CVE hoặc độ chính xác mô hình. Không suy ra tiết kiệm thời gian hay tăng độ chính xác từ số tệp giảm. RESOLVED_TARGET chỉ áp dụng cho cơ chế và điều kiện trong hồ sơ. UNCONFIRMED cần thêm ngữ cảnh và người đánh giá độc lập.", "", "Nguồn: CWE-Bench-Java trong [IRIS tại revision khóa](https://github.com/iris-sast/iris/tree/d2059f299a80a68ea4a0b0315eec2f42b8743776).", ""]
    (destination/"REPORT.md").write_text("\n".join(lines),encoding="utf-8")
    print(destination)
    return result


def make_split(args,run):
    cases = {c["cve_id"]:c for c in rows("cases")}
    versions = rows("versions")
    units = {c:(c if args.unit=="cve" else cases[c]["repository_url"].lower().removesuffix(".git")) for c in cases}
    parent = {u:u for u in units.values()}
    def find(u):
        while parent[u]!=u:
            parent[u] = parent[parent[u]]
            u = parent[u]
        return u
    by_hash = defaultdict(set)
    for v in versions:
        by_hash[v["token_hash"]].add(units[v["cve_id"]])
    for group in by_hash.values():
        first = min(group)
        for unit in group:
            parent[find(unit)] = find(first)
    components = defaultdict(list)
    for unit in parent:
        components[find(unit)].append(unit)
    assignment = {}
    for group in components.values():
        key = "|".join(sorted(group))
        bucket = int(hashlib.sha256(("JavaCVE-v0.2.0:"+key).encode()).hexdigest(),16)%10
        name = "test" if bucket==0 else "validation" if bucket==1 else "train"
        assignment.update({u:name for u in group})
    output = [dict(sample_id=v["sample_id"],cve_id=v["cve_id"],unit=units[v["cve_id"]],split=assignment[units[v["cve_id"]]],token_hash=v["token_hash"]) for v in versions]
    require(all(len({assignment[u] for u in group})==1 for group in by_hash.values()), "Token leakage across split")
    destination = args.out or run.directory/"split"
    destination.mkdir(parents=True,exist_ok=False)
    (destination/"assignments.jsonl").write_text("".join(json.dumps(r)+"\n" for r in output),encoding="utf-8")
    result = dict(unit=args.unit,seed="JavaCVE-v0.2.0",policy="Group by project/CVE, union groups sharing exact token hashes, deterministic hash buckets 80/10/10 in expectation",counts=dict(Counter(r["split"] for r in output)),components=len(components),cross_split_exact_token_duplicates=0,
                  caveat="Tiny pilot can have empty partitions. Hash equality detects exact token duplicates only; review approximate clones before ML. Labels and original pilot_only fields are unchanged.")
    write_json(destination/"summary.json",result)
    return result
