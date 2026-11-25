"""Audit saved evidence under one acceptance policy; never build or run Java probes.

Run: python3 -m tools.acceptance --out data/acceptance-review.json
This is a scoped AI assessment, not independent human review or a release seal.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from .catalog import ROOT
from .observations import require
from .security import parse_probe

PHASES = ("before", "after")
PILOT_RUN = "5cd2e8809e084ef1bb9530b2f00f8722"
PILOT_RETRY = "aab27812edb14b81912ac90b458e48e5"
SOURCE = {"pilot": "ed97b42890524847a80085211e91b217",
          "batch02": "2dc3374df54a4ed5b04e2894f1cb59f6"}
CRITERIA = {
    "source_identity": "Advisory/repository, pinned commits/trees and selected parent; reconstructed history disclosed",
    "extraction": "Git blob, line range, SHA-256 and AST identity of every indexed callable version",
    "advisory_patch_context": "Scoped advisory/patch/caller context recorded",
    "scoped_ai_method_review": "Scoped review of target callables; unsupported labels remain UNCONFIRMED",
    "paired_source_builds": "Both pinned source builds have PASS stages, exit 0, logs and artifact hashes",
    "ordinary_controls": "Same fixture and ordinary control names, all controls PASS in both phases",
    "paired_security_behavior": "Same input/oracle, target FAIL before and PASS after, with scoped interpretation and residual failures disclosed",
}
LIMITS = {
    "CVE-2017-1000487": "Chỉ API/đường dẫn executable trong shell đã đo; chưa đo ứng dụng đầu cuối.",
    "CVE-2018-1002200": "Chỉ nhánh ZIP; sibling_prefix_containment vẫn FAIL sau vá; dùng cha thứ nhất của merge.",
    "CVE-2018-1002201": "Chỉ nhánh giải nén ZIP; sibling_prefix_containment vẫn FAIL sau vá.",
    "CVE-2018-1002202": "Lịch sử benchmark_reconstruction; sibling_prefix_containment vẫn FAIL sau vá.",
    "CVE-2018-17297": "Chỉ API giải nén đã đo; sibling_prefix_containment vẫn FAIL sau vá.",
    "CVE-2021-29425": "Chỉ giá trị trả về của normalize với prefix đã thử; chưa đo mọi caller.",
    "CVE-2016-9177": "Chỉ external static files; classpath/JAR, symlink và sibling cùng prefix chưa đo.",
    "CVE-2022-4244": "Chỉ Expand.extractFile; sibling_prefix_containment vẫn FAIL sau vá, giữ VULNERABLE.",
    "CVE-2013-7285": "Thiếu hành vi caller: cả hai dừng ở converter lookup trước khi trả proxy; legacy assertion PASS/PASS không chứng minh sửa lỗi.",
    "CVE-2020-26217": "Thiếu fixture hành vi đúng advisory/caller/policy; API round-trip thông thường và upstream 7→9 test không thay thế C7.",
    "CVE-2021-21345": "Thiếu fixture hành vi cho chuỗi advisory/caller/policy; API round-trip và upstream 11→13 test không chứng minh cơ chế CVE riêng.",
    "CVE-2023-37460": "Thiếu hành vi symlink theo advisory và rà soát callable; đối chứng ZIP cục bộ chưa công bố không đủ để hoàn tất.",
    "CVE-2018-1000850": "Thiếu cặp build: before TIMEOUT, after compiler/JDK không phù hợp; thiếu fixture/control và rà soát callable.",
    "CVE-2022-25842": "Thiếu phụ thuộc bytekit SNAPSHOT có provenance xác minh được; thiếu build, fixture/control và rà soát callable.",
    "CVE-2022-25174": "Maven dependency resolution TIMEOUT; thiếu build, fixture/control Jenkins và rà soát callable.",
    "CVE-2022-25175": "Maven dependency resolution TIMEOUT; thiếu build, fixture/control Jenkins và rà soát callable.",
    "CVE-2019-10392": "Thiếu build do phụ thuộc/timeout; thiếu đối chứng và hành vi tích hợp Jenkins/caller.",
    "CVE-2020-2261": "Thiếu build do phụ thuộc/timeout; thiếu đối chứng và hành vi controller/agent Jenkins.",
    "CVE-2022-20617": "Thiếu build, fixture/control và đường gọi DockerRegistryEndpoint; giữ nhãn sau UNCONFIRMED.",
    "CVE-2022-33140": "Thiếu cặp build và tích hợp cả NiFi/Registry, mock OS command/provider và đối chứng.",
}


def paired_behavior(pair):
    """A successful process or PASS/PASS assertion is insufficient evidence."""
    if set(pair) != set(PHASES):
        return False, False, []
    security = [pair[p].get("security", {}) for p in PHASES]
    if not all(s.get("status") == "EXECUTED" and s.get("process_exit_code") == 0
               and s.get("fixture_sha256") for s in security):
        return False, False, []
    if security[0]["fixture_sha256"] != security[1]["fixture_sha256"]:
        return False, False, []
    tests = [{t["name"]: t for t in s.get("tests", [])} for s in security]
    if any(len(ts) != len(s.get("tests", [])) for ts, s in zip(tests, security)):
        return False, False, []
    controls = [{n for n, t in ts.items() if t["role"] == "control"} for ts in tests]
    controls_ok = (bool(controls[0]) and controls[0] == controls[1]
                   and all(s.get("controls_pass") is True for s in security)
                   and all(ts[n]["pass"] is True for ts in tests for n in controls[0]))
    target_names = [{n for n, t in ts.items() if t["role"] == "security"} for ts in tests]
    improved = [n for n in sorted(target_names[0] & target_names[1])
                if tests[0][n]["pass"] is False and tests[1][n]["pass"] is True]
    behavior_ok = bool(controls_ok and target_names[0] == target_names[1] and improved)
    return bool(controls_ok), behavior_ok, improved


def local_ordinary_controls(case, record):
    """A separate ordinary upstream test can support C6, never C7."""
    if not record or record.get("cve_id") != case["cve_id"] or record.get("status") != "PASS":
        return False
    pair = {s["phase"]: s for s in record.get("snapshots", [])}
    if set(pair) != set(PHASES):
        return False
    identities = ("test_file_sha256", "archive_sha256", "input_member_sha256")
    for phase, s in pair.items():
        if (s.get("commit") != case[phase + "_commit"] or s.get("tree") != case[phase + "_tree"]
                or s.get("status") != "PASS" or s.get("maven_exit") != 0
                or s.get("tracked_files_changed") is not False
                or s.get("surefire") != {"tests": 1, "failures": 0, "errors": 0, "skipped": 0}
                or s.get("output_sha256") != s.get("input_member_sha256")
                or not all(len(s.get(k, "")) == 64 for k in identities)):
            return False
    return all(pair["before"][k] == pair["after"][k] for k in identities)


def ordinary_api_pair(case, snapshots, source_artifacts):
    selected = [s for s in snapshots if s["cve_id"] == case["cve_id"]]
    pair = {s["phase"]: s for s in selected}
    if len(selected) != 2 or set(pair) != set(PHASES):
        return False
    for phase, s in pair.items():
        controls = s.get("controls", [])
        if (s.get("commit") != case[phase + "_commit"] or s.get("status") != "PASS"
                or s.get("exit_code") != 0 or s.get("build_status") != "REUSED_VERIFIED"
                or s.get("source_built_in_this_run") is not False
                or s.get("artifact_sha256") != source_artifacts[phase]["artifact_sha256"]
                or len(controls) != 3 or not all(c["pass"] for c in controls)
                or {c["name"] for c in controls} != {"string_roundtrip", "empty_string_roundtrip", "integer_roundtrip"}):
            return False
    return (len(pair["before"].get("fixture_sha256", "")) == 64
            and pair["before"]["fixture_sha256"] == pair["after"].get("fixture_sha256"))


def assess():
    inputs = {}

    def read(path, lines=False):
        path = Path(path)
        content = (ROOT / path).read_bytes()
        inputs[path.as_posix()] = hashlib.sha256(content).hexdigest()
        return ([json.loads(s) for s in content.decode("utf-8").splitlines()]
                if lines else json.loads(content))

    def receipt(rid):
        return read(f"evidence/v0.2.0/{rid}/run.json")

    def log_for(run, cve, phase, stage, commit):
        steps = [s for s in run["steps"] if s.get("cve_id") == cve
                 and s.get("phase") == phase and s.get("stage") == stage]
        require(len(steps) == 1, f"Missing/ambiguous {stage}: {cve}/{phase}")
        step = steps[0]
        require(step["commit"] == commit, "Step commit mismatch")
        path = Path("evidence/v0.2.0") / run["run_id"] / step["log"]
        content = (ROOT / path).read_bytes()
        inputs[path.as_posix()] = hashlib.sha256(content).hexdigest()
        return step, path.as_posix(), content.decode("utf-8")

    builds = {c["cve_id"]: c for c in read("data/batch-02/build-status.json")["cases"]}
    prior_review = {c["cve_id"]: c for c in read("data/batch-02/completion-review.json")["cases"]}
    batch_reviews = read("data/batch-02/reviews.jsonl", True)
    pilot_reviews = read("data/reviews.jsonl", True)
    read("data/batch-02/snapshot-reviews.jsonl", True)
    read("evidence/inputs/case_annotations-step2.json")
    read("data/batch-02/xstream-diagnosis.json")
    read("data/batch-02/completion.json")
    # Inspect existing local control without promoting it to published target behavior.
    ordinary_index = read("data/ordinary-checks.json") if (ROOT / "data/ordinary-checks.json").exists() else {"cases": []}
    local_path = ordinary_index.get("plexus_control_receipt", "evidence/plexus-control/run.json")
    local_control = read(local_path) if (ROOT / local_path).exists() else None
    records = []
    for batch, folder in [("pilot", Path("data")), ("batch02", Path("data/batch-02"))]:
        cases = read(folder / "cases.jsonl", True)
        versions = read(folder / "versions.jsonl", True)
        read(folder / "methods.jsonl", True)
        read(folder / "files.jsonl", True)
        source = receipt(SOURCE[batch])
        require(source["status"] == "PASS" and not source["ast_review"]["failures"], "Source/AST receipt failed")
        require(source["source_review"]["checked_method_versions"] == len(versions)
                == source["ast_review"]["matched_versions"], "Incomplete source audit")
        for case in cases:
            cve = case["cve_id"]
            vs = [v for v in versions if v["cve_id"] == cve]
            if batch == "pilot":
                rid = PILOT_RUN if case["build_module"] is not None else PILOT_RETRY
            else:
                rid = builds[cve]["build_run_id"]
                read(folder / "advisories" / (cve + ".json"))
            run = receipt(rid)
            pair = {s["phase"]: s for s in run["snapshots"] if s["cve_id"] == cve}
            require(len(pair) == 2, "Missing snapshot pair")
            snapshots = {}
            for phase in PHASES:
                snap = pair[phase]
                require(snap["commit"] == case[phase + "_commit"], "Snapshot commit mismatch")
                step, log, _ = log_for(run, cve, phase, "build", snap["commit"])
                passed = (snap.get("build_status") == step["status"] == "PASS"
                          and step["exit_code"] == 0 and len(snap.get("artifact_sha256", "")) == 64)
                require(not snap.get("source_integrity", {}).get("changed_files"), "Source changed during build")
                sec = snap.get("security", {})
                security_log = None
                if sec.get("status") == "EXECUTED":
                    security_step, security_log, output = log_for(run, cve, phase, "security", snap["commit"])
                    require(security_step["status"] == "PASS" and security_step["exit_code"] == 0,
                            "Security process failed")
                    kind = ("spark-local" if cve == "CVE-2016-9177" else "xstream-local"
                            if cve == "CVE-2013-7285" else "plexus-archiver"
                            if cve == "CVE-2022-4244" else case["check"])
                    require(parse_probe(kind, output) == sec["tests"], "Assertions differ from saved log")
                    fixture = ("SparkLocalProbe.java" if kind == "spark-local" else
                               "XStreamLocalProbe.java" if kind == "xstream-local" else
                               "ExpandProbe.java" if cve == "CVE-2022-4244" else "RegressionProbe.java")
                    fixture_path = "fixtures/" + fixture
                    fixture_hash = hashlib.sha256((ROOT / fixture_path).read_bytes()).hexdigest()
                    inputs[fixture_path] = fixture_hash
                    require(fixture_hash == sec["fixture_sha256"], "Fixture identity differs from recorded behavior")
                snapshots[phase] = {
                    "commit": snap["commit"], "build_status": "PASS" if passed else "FAIL",
                    "error_category": step.get("error_category"), "build_log": log,
                    "artifact_sha256": snap.get("artifact_sha256"), "security_log": security_log,
                    "security": sec, "upstream_tests": snap.get("upstream_tests"),
                    "build_config_overrides": snap.get("build_config_overrides", []),
                    "source_integrity": snap.get("source_integrity"),
                }
            controls, behavior, improved = paired_behavior(pair)
            control_receipt = None
            if local_ordinary_controls(case, local_control):
                verifier = "evidence/plexus-control/verify.py"
                inputs[verifier] = hashlib.sha256((ROOT / verifier).read_bytes()).hexdigest()
                require(inputs[verifier] == local_control["verifier_sha256"], "Local control verifier changed")
                controls = True
                control_receipt = local_path
            extra = next((x for x in ordinary_index["cases"] if x["cve_id"] == cve), None)
            functional_pair = []
            if extra:
                functional = read(extra["receipt"])
                functional_pair = [s for s in functional["snapshots"] if s["cve_id"] == cve]
                if ordinary_api_pair(case, functional_pair, snapshots):
                    from .ordinary_replay import parse_controls
                    fixture = "fixtures/OrdinaryXStreamProbe.java"
                    inputs[fixture] = hashlib.sha256((ROOT / fixture).read_bytes()).hexdigest()
                    for s in functional_pair:
                        require(s["fixture_sha256"] == inputs[fixture], "Ordinary fixture hash differs")
                        compile_step, _, _ = log_for(functional, cve, s["phase"], "ordinary-compile", s["commit"])
                        step, _, output = log_for(functional, cve, s["phase"], "ordinary-tests", s["commit"])
                        require(all(t["status"] == "PASS" and t["exit_code"] == 0 for t in [compile_step, step]), "Ordinary process failed")
                        require(parse_controls(output) == s["controls"], "Ordinary controls differ from log")
                    controls = True
                    control_receipt = extra["receipt"]
            if cve in prior_review:
                # Semantic review can veto a syntactically passing assertion (XStream 2013).
                prior_gates = {g["id"]: g["status"] == "MET" for g in prior_review[cve]["criteria"]}
                behavior = behavior and prior_gates["paired_security_behavior"]
            reviewed = (len([r for r in pilot_reviews if r["cve_id"] == cve]) == 2
                        if batch == "pilot" else
                        {v["sample_id"] for v in vs} <= {r["sample_id"] for r in batch_reviews})
            gates = {"source_identity": True, "extraction": True,
                     "advisory_patch_context": True, "scoped_ai_method_review": reviewed,
                     "paired_source_builds": all(s["build_status"] == "PASS" for s in snapshots.values()),
                     "ordinary_controls": controls, "paired_security_behavior": behavior}
            remaining = LIMITS[cve]
            if cve == "CVE-2018-1000850" and gates["paired_source_builds"]:
                remaining = "Build PASS/PASS với overlay POM tạm khóa Kotlin plugin 1.2.60 theo POM gốc; thiếu rà soát callable, đối chứng và hành vi mục tiêu. Mã Java và nhãn UNCONFIRMED giữ nguyên."
            if cve == "CVE-2022-25174" and gates["paired_source_builds"]:
                remaining = "Build PASS/PASS trong profile package bỏ test harness dependency staging của HPI 3.22; overlay POM và vận chuyển dependency được ghi rõ. Thiếu rà soát callable và đối chứng/hành vi tích hợp Jenkins; giữ UNCONFIRMED."
            records.append({"cve_id": cve, "batch": batch, "project": case["project"],
                            "repository_url": case["repository_url"], "advisory_url": case["advisory_url"],
                            "before_commit": case["before_commit"], "after_commit": case["after_commit"],
                            "provenance": case["provenance"], "selected_parent_index": case["selected_parent_index"],
                            "source_receipt": f"evidence/v0.2.0/{SOURCE[batch]}/run.json",
                            "build_receipt": f"evidence/v0.2.0/{rid}/run.json", "snapshots": snapshots,
                            "additional_ordinary_control_receipt": control_receipt,
                            "ordinary_functional_observations": functional_pair,
                            "criteria": {k: "MET" if v else "NOT_MET" for k, v in gates.items()},
                            "accepted_common": all(gates.values()), "improved_assertions": improved,
                            "after_label": case["after_label"], "callable_labels": dict(Counter(v["label"] for v in vs)),
                            "scope_and_remaining_work": remaining})
    # Review the original eight candidates first, then every other case, with identical gates.
    records.sort(key=lambda c: (not c["accepted_common"], c["batch"] != "pilot", c["cve_id"]))
    return {"policy_id": "common-scoped-v1", "review_date_local": "2026-11-25",
            "reviewer": "AI", "independent_human_reviews": 0, "criteria": CRITERIA,
            "scope": "Review of recorded source builds, functional tests and existing security evidence. Functional tests never establish target security behavior or general safety.",
            "proposed_target": {"accepted_cases": 12, "total_cases": 20, "instructor_confirmed": False},
            "summary": {"cases": len(records), "accepted_common": sum(c["accepted_common"] for c in records),
                        "paired_builds": sum(c["criteria"]["paired_source_builds"] == "MET" for c in records),
                        "by_batch": {b: sum(c["accepted_common"] for c in records if c["batch"] == b) for b in SOURCE},
                        "labels": dict(sum((Counter(c["callable_labels"]) for c in records), Counter()))},
            "local_plexus_control_present": local_control is not None,
            "input_sha256": dict(sorted(inputs.items())), "cases": records}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="New JSON file; never overwrite an existing assessment")
    args = parser.parse_args()
    result = assess()
    with args.out.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result["summary"], ensure_ascii=False))
