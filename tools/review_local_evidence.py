"""Apply the AI review of existing Spark/XStream evidence; never execute payloads.

The decisions below are a scoped semantic review, not inferred from build success.
Historical receipts and the intake summary remain immutable.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.catalog import ROOT
from tools.observations import require
from tools.quality import write_json
from tools.security import parse_probe
from tools.runtime import utc

BEHAVIOR = "4063ba008c3644f5ad4d015ccd4cbcc4"
DIAGNOSTIC = "a4e197b267ca44baa4896be94b9f65b5"
SOURCE = "2dc3374df54a4ed5b04e2894f1cb59f6"
TARGETS = ("CVE-2016-9177", "CVE-2013-7285")
SPARK_SCOPE = (
    "Pinned Spark snapshots on Linux/JDK8, externalStaticFileLocation(public), "
    "an HTTP caller supplying /..%5coutside.txt or /%2e%2e%5coutside.txt, "
    "and a process-readable sibling marker outside public. Before returns 200 with "
    "the marker; after returns 404. Only this external-file caller path is established. "
    "Classpath/JAR resources, symlinks and sibling names sharing the public prefix are unmeasured."
)
XSTREAM_SCOPE = (
    "Both pinned XStream artifacts, DomDriver, default configuration and identical input. "
    "Both ordinary controls passed. Converter lookup failed during fromXML on each snapshot, "
    "before a proxy was returned or a callback attempted. Security behavior remains UNCONFIRMED."
)
XSTREAM_MISSING = (
    "Missing paired observations of the advisory behavior under a common input, control and "
    "caller policy on these commits, with evidence linking that behavior to the indexed callable."
)


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def rows(folder, name):
    return [json.loads(line) for line in (folder / (name + ".jsonl")).read_text(encoding="utf-8").splitlines()]


def write_rows(folder, name, values):
    (folder / (name + ".jsonl")).write_text(
        "".join(json.dumps(v, ensure_ascii=False) + "\n" for v in values), encoding="utf-8")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def receipt(run_id):
    path = ROOT / "evidence/v0.2.0" / run_id / "run.json"
    return path, read(path)


def check_pair(case, run, path):
    pair = [r for r in run["snapshots"] if r["cve_id"] == case["cve_id"]]
    require(len(pair) == 2 and {r["phase"] for r in pair} == {"before", "after"}, "Missing unique pair")
    kind, fixture = ("spark-local", "SparkLocalProbe") if case["cve_id"] == TARGETS[0] else ("xstream-local", "XStreamLocalProbe")
    logs = {}
    for r in pair:
        require(r["commit"] == case[r["phase"] + "_commit"], "Receipt commit mismatch")
        require(r["status"] == r["build_status"] == "PASS" and r["exit_code"] == 0, "Build/fixture failed")
        require(r["source_integrity"]["changed_files"] == [], "Source changed during build")
        security = r["security"]
        require(security["status"] == "EXECUTED" and security["process_exit_code"] == 0, "Fixture not executed")
        require(security["fixture_sha256"] == sha(ROOT / "fixtures" / (fixture + ".java")), "Fixture identity differs")
        steps = [s for s in run["steps"] if s.get("cve_id") == case["cve_id"] and s.get("phase") == r["phase"]]
        for stage in ("build", "upstream-tests", "probe-compile", "security"):
            chosen = [s for s in steps if s["stage"] == stage]
            require(len(chosen) == 1 and chosen[0]["exit_code"] == 0 and chosen[0]["status"] == "PASS"
                    and chosen[0]["commit"] == r["commit"], "Invalid stage evidence: " + stage)
        log = path.parent / next(s["log"] for s in steps if s["stage"] == "security")
        output = log.read_text(encoding="utf-8")
        require(parse_probe(kind, output) == security["tests"], "Assertions differ from raw log")
        require(security["controls_pass"] and all(t["pass"] for t in security["tests"] if t["role"] == "control"), "Control failed")
        logs[r["phase"]] = dict(path=log.relative_to(ROOT).as_posix(), sha256=sha(log), output=output)
    before, after = (next(r for r in pair if r["phase"] == p) for p in ("before", "after"))
    require(before["security"]["fixture_sha256"] == after["security"]["fixture_sha256"], "Unequal fixtures")
    require([(t["name"], t["role"]) for t in before["security"]["tests"]] ==
            [(t["name"], t["role"]) for t in after["security"]["tests"]], "Unequal oracle")
    return pair, logs


def method_decision(v):
    sig = v["syntactic_signature"]
    if v["is_test"]:
        return "UNCONFIRMED", "TEST_OUTSIDE_TARGET", "Test/setup code is evidence support, not an advisory vulnerability sample.", "No promotion of test code to a security label."
    if v["cve_id"] == TARGETS[1]:
        if sig.startswith(("XStream#", "SecurityMapper#", "CachingMapper#")):
            reason = "Mapper and permission behavior depends on the caller policy. The observed conversion failure precedes the caller action on both snapshots."
        else:
            reason = "Permission/helper API or policy predicate requires an installed mapper and a caller policy; no paired advisory behavior is established for this callable."
        return "UNCONFIRMED", "XSTREAM_CALLER_BEHAVIOR_MISSING", reason, XSTREAM_MISSING
    if sig.startswith(("ExternalResourceHandler#getResource(", "StaticFilesConfiguration#consume(",
                       "StaticFilesConfiguration#consumeWithFileResourceHandlers(")):
        label = "VULNERABLE" if v["phase"] == "before" else "RESOLVED_TARGET"
        reason = "The reviewed external-handler call chain resolves and streams the outside marker before; the new external guard rejects it after."
        if sig.startswith("StaticFilesConfiguration#"):
            reason += " This decision requires the external handler configured by the fixture; it is not a standalone property of this consumer."
        return label, "B02_SPARK_EXTERNAL_CONTEXT", reason, "Independent human review; broader resource modes and path classes remain unmeasured."
    if sig.startswith("DirectoryTraversal#protectAgainstForExternal("):
        return "RESOLVED_TARGET", "B02_SPARK_EXTERNAL_CONTEXT", "The new guard rejects the tested resolved paths when called by ExternalResourceHandler with StaticFilesFolder.external configured to public.", "Independent human review; prefix-boundary and other path classes are unmeasured."
    if sig.startswith(("ClassPathResourceHandler#", "DirectoryTraversal#protectAgainstInClassPath(",
                       "StaticFilesConfiguration#configure(", "StaticFilesConfiguration#configureJarCase(",
                       "StaticFilesFolder#local")):
        return "UNCONFIRMED", "RESOURCE_MODE_UNMEASURED", "Classpath/JAR caller path is outside the external-file fixture; an upstream test passing does not transfer the external-path label.", "A reviewed paired fixture for this resource mode and its class-loader/caller conditions."
    return "UNCONFIRMED", "SUPPORTING_CALLABLE_CONTEXT", "Configuration, accessor, exception or string helper has no standalone advisory security decision; the end-to-end result belongs to its configured caller chain.", "Callable-specific data flow and behavior before assigning a standalone security label."


def apply(folder, repos, targets=TARGETS):
    behavior_path, behavior = receipt(BEHAVIOR)
    source_path, source = receipt(SOURCE)
    require(behavior["status"] == source["status"] == "PASS", "Unfinished evidence")
    require(source["source_review"]["checked_method_versions"] == 222 and not source["ast_review"]["failures"], "Incomplete source audit")
    versions, cases = rows(folder, "versions"), rows(folder, "cases")
    require(source["ast_review"]["matched_versions"] == len(versions), "AST coverage differs")
    previous_review = folder / "completion-review.json"
    previous = read(previous_review) if previous_review.exists() else {}
    review_time = previous.get("review_utc") or utc()
    assessments = []
    snapshot_path = folder / "snapshot-reviews.jsonl"
    previous_snapshots = rows(folder, "snapshot-reviews") if snapshot_path.exists() else []
    snapshots = []
    replay_path, replay = receipt(DIAGNOSTIC)
    replay_logs = [(replay_path.parent / s["log"]).relative_to(ROOT).as_posix() for s in replay["steps"] if s["stage"] == "diagnostic"]
    require(replay["diagnostic_of"] == BEHAVIOR and replay["previous_receipt_sha256"] == behavior["original_run_sha256"] and
            replay["status"] == "PASS" and len(replay_logs) == 2, "Unlinked diagnostic receipt")
    diagnostic_time = previous.get("diagnostic_review_utc") or utc()
    decisions = []
    for case in cases:
        cve = case["cve_id"]
        if cve not in targets:
            continue
        pair, logs = check_pair(case, behavior, behavior_path)
        repo = repos / cve
        def git(*args):
            return subprocess.check_output(["git", "-C", str(repo), *args])
        require(git("rev-parse", case["after_commit"] + "^1").decode().strip() == case["before_commit"], "Selected parent differs")
        for phase in ("before", "after"):
            require(git("rev-parse", case[phase + "_commit"] + "^{tree}").decode().strip() == case[phase + "_tree"], "Tree differs")
        patch = git("diff", "--no-ext-diff", case["before_commit"], case["after_commit"], "--", "src/main" if cve == TARGETS[0] else "xstream/src/java")
        spark = cve == TARGETS[0]
        stamp = next((r["review_utc"] for r in previous_snapshots if r["cve_id"] == cve), review_time) if spark else diagnostic_time
        scope = SPARK_SCOPE if spark else XSTREAM_SCOPE
        if spark:
            for phase, expected in (("before", [False, False, True]), ("after", [True, True, True])):
                r = next(r for r in pair if r["phase"] == phase)
                require([t["pass"] for t in r["security"]["tests"] if t["role"] == "security"] == expected, "Unexpected Spark behavior")
                require(("200 LOCAL_OUTSIDE_MARKER" if phase == "before" else "OBSERVED_0=404") in logs[phase]["output"], "Missing raw marker/status evidence")
        else:
            for phase in ("before", "after"):
                require("OBSERVED_CALLBACKS=0" in logs[phase]["output"] and
                        "OBSERVED_EXCEPTION=com.thoughtworks.xstream.converters.ConversionException" in logs[phase]["output"], "XStream observation differs")
        criteria = [
            ("source_identity", "Source identity", True, "Pinned commits/trees and selected first parent match Git; source files unchanged in the build receipt."),
            ("extraction", "Extraction", True, "Source audit verifies Git blobs, line ranges, SHA256 and AST names/boundaries for all 222 batch callable versions."),
            ("advisory_patch_context", "Advisory and patch context", True, "External-resource traversal matches the advisory and added guard." if spark else "Advisory requires successful unmarshal plus a later proxy method call; the patch adds permission APIs with an allow-all default. No default mitigation is inferred."),
            ("scoped_ai_method_review", "Scoped AI method review", True, "Every indexed callable version in this CVE has an AI decision, caller scope and missing-evidence reason; UNCONFIRMED is retained where needed."),
            ("paired_source_builds", "Paired source builds", True, "Both pinned source builds PASS; JAR hashes, commands, exit codes and original-source integrity are in the receipt."),
            ("ordinary_controls", "Ordinary controls", True, "Same fixture bytes and oracle in both snapshots; ordinary_static_file PASS/PASS." if spark else "Same fixture bytes and oracle in both snapshots; string_roundtrip PASS/PASS. AliasTest: 27 tests per snapshot, zero failures/errors/skips; functional evidence only."),
            ("paired_security_behavior", "Reviewed paired security behavior", spark, "Two encoded traversal cases return the outside marker before and 404 after; literal /../ returns 400 on both and does not demonstrate a regression." if spark else "Converter lookup failed during fromXML on both snapshots. Each legacy assertion passed before the caller action was attempted. " + XSTREAM_MISSING),
        ]
        assessment = dict(cve_id=cve, fully_completed=all(c[2] for c in criteria), reviewer="AI", independent_human_review=False,
                          scope=scope, behavior_run_id=BEHAVIOR, source_run_id=SOURCE,
                          patch_sha256=hashlib.sha256(patch).hexdigest(),
                          fixture_sha256=pair[0]["security"]["fixture_sha256"],
                          observations=[dict(phase=r["phase"], commit=r["commit"], artifact_sha256=r["artifact_sha256"],
                                             tests=r["security"]["tests"], log=logs[r["phase"]]["path"],
                                             log_sha256=logs[r["phase"]]["sha256"]) for r in pair],
                          criteria=[dict(id=i, criterion=n, status="MET" if ok else "NOT_MET", required=True, reason=why,
                                         evidence=[source_path.relative_to(ROOT).as_posix()] if i in {"source_identity", "extraction"} else
                                         ["data/batch-02/reviews.jsonl", "data/batch-02/snapshot-reviews.jsonl"] if i == "scoped_ai_method_review" else
                                         ["data/batch-02/advisories/" + cve + ".json", case["repository_url"] + "/commit/" + case["after_commit"]] if i == "advisory_patch_context" else
                                         [behavior_path.relative_to(ROOT).as_posix()] + [logs[p]["path"] for p in ("before", "after")]) for i, n, ok, why in criteria],
                          missing_required_evidence=[] if spark else [XSTREAM_MISSING],
                          independent_human_review_status="PENDING; separately tracked, not a completion gate in the current definition")
        if not spark:
            assessment["diagnostic_run_id"] = DIAGNOSTIC
            assessment["criteria"][-1]["evidence"] += [replay_path.relative_to(ROOT).as_posix(), *replay_logs]
            assessment["status_summary"] = "Đối chứng chuỗi đạt cả hai bản. Cả hai dừng khi tìm converter trong fromXML, trước khi caller có thể gọi callback. Hai snapshot và 68 phiên bản callable giữ UNCONFIRMED."
        assessments.append(assessment)
        diagnostic_ref = {} if spark else {"diagnostic_run_id": DIAGNOSTIC}
        for r in pair:
            label = ("VULNERABLE" if r["phase"] == "before" else "RESOLVED_TARGET") if spark else "UNCONFIRMED"
            snapshots.append(dict(cve_id=cve, phase=r["phase"], commit=r["commit"], decision=label, reviewer="AI",
                                  independent_human_review=False, review_utc=stamp, scope=scope,
                                  evidence_run_id=BEHAVIOR, reason=criteria[-1][3], **diagnostic_ref))
            case[r["phase"] + "_label"] = label
        case.update(label_scope=scope, check="spark-local" if spark else "xstream-local", evidence_run_id=BEHAVIOR, **diagnostic_ref,
                    evidence_sets=["batch02_source_build_security"] if spark else ["batch02_source_build", "batch02_fixture_inconclusive"])
        for v in versions:
            if v["cve_id"] != cve:
                continue
            label, group, reason, needed = method_decision(v)
            v.update(label=label, rule_id=group, unknown_reason_group=group if label == "UNCONFIRMED" else None,
                     label_scope=scope + " " + reason, evidence_needed=needed, evidence_run_id=BEHAVIOR,
                     caller_context_required=True, **diagnostic_ref)
            decisions.append(dict(sample_id=v["sample_id"], cve_id=cve, phase=v["phase"], commit=v["commit"],
                                  previous_label="UNCONFIRMED", decision=label, reviewer="AI", independent_human_review=False,
                                  review_utc=stamp, scope=v["label_scope"], reason=reason, evidence_needed=needed, **diagnostic_ref,
                                  caller_context_required=True, evidence_run_id=BEHAVIOR, source_run_id=SOURCE,
                                  fixture_sha256=assessment["fixture_sha256"], source_lines=[v["start_line"], v["end_line"]]))
    completion = read(folder / "completion.json")
    completed = [c for c in completion["completed_cves"] if c not in targets]
    completed += [a["cve_id"] for a in assessments if a["fully_completed"]]
    completion.update(fully_completed=len(completed), completed_cves=completed,
                      labels=dict(Counter(v["label"] for v in versions)),
                      evidence_runs={**completion.get("evidence_runs", {}), **{a["cve_id"]: a["behavior_run_id"] for a in assessments if a["fully_completed"]}},
                      assessment_path="data/batch-02/completion-review.json")
    def merge(existing, updated, fields):
        return list({tuple(row[name] for name in fields): row for row in [*existing, *updated]}.values())
    assessments = merge(previous.get("cases", []), assessments, ["cve_id"])
    decisions = merge(rows(folder, "reviews"), decisions, ["sample_id"])
    snapshots = merge(previous_snapshots, snapshots, ["cve_id", "phase"])
    assessed = {a["cve_id"] for a in assessments}
    review = dict(previous, reviewer="AI", independent_human_reviews=0, policy=completion["definition"],
                  evidence_policy="AI review of published receipts, source identity and diagnostic logs.",
                  receipt_sha256={**previous.get("receipt_sha256", {}), BEHAVIOR: sha(behavior_path), SOURCE: sha(source_path)}, cases=assessments,
                  reviewed_callable_versions=sum(r.get("cve_id") in assessed for r in decisions), reviewed_snapshot_count=len(snapshots))
    if TARGETS[1] in targets:
        review.update(review_basis_commit="0280b7d", review_utc=diagnostic_time, diagnostic_review_utc=diagnostic_time)
        if "xstream_followup_review_utc" in previous:
            review.update(previous_review_basis_commit="8fefbe9", previous_review_utc=previous["xstream_followup_review_utc"])
        review["receipt_sha256"][DIAGNOSTIC] = sha(replay_path)
    write_rows(folder, "versions", versions)
    write_rows(folder, "cases", cases)
    write_rows(folder, "reviews", decisions)
    write_rows(folder, "snapshot-reviews", snapshots)
    write_json(folder / "completion-review.json", review)
    write_json(folder / "completion.json", completion)
    generate_docs(review, versions)
    print(f"Batch reviews: {len(decisions)} callable versions, {len(snapshots)} snapshots, {len(completed)}/{len(cases)} complete")


def generate_docs(review, versions):
    lines = ["# Rà soát tiêu chí Batch02 cho Spark và XStream", "", "**AI** rà soát bốn hồ sơ theo tiêu chí của đợt. Số người đánh giá độc lập là 0. [Định nghĩa hoàn tất](../data/batch-02/completion.json) · [Quyết định và bằng chứng](../data/batch-02/completion-review.json).", "",
             "| CVE | Điều kiện áp dụng | Before / after | Phạm vi đã chứng minh | Còn thiếu |", "|---|---|---|---|---|",
             "| CVE-2016-9177 | HTTP vào externalStaticFileLocation; process đọc được marker ngoài public, trong cây tạm do fixture quản lý | Control PASS/PASS; hai URI mã hóa: 200 + marker → 404; literal /../: 400/400 | Đọc file ngoài external root trước, chặn hai đầu vào đó sau; **hoàn tất theo phạm vi** | Classpath/JAR, symlink, tên sibling cùng prefix chưa đo; đánh giá độc lập còn chờ |",
             "| CVE-2013-7285 | Caller cần nhận được proxy sau khi đọc XML | Đối chứng đạt ở cả hai bản. Cả hai dừng ở bước tìm converter trong fromXML | 27 AliasTest đạt mỗi bản. Log ghi 0 lần gọi callback | Chưa quan sát được hành vi theo advisory và chưa quy được hành vi cho callable. **Chưa hoàn tất** |"]
    for a in review["cases"]:
        if "overview_row" in a:
            lines.append(a["overview_row"])
    lines += ["",
             "Fixture Spark chỉ tạo/đọc marker trong cây tạm và bind 127.0.0.1. XStream dùng Marker.touch, không chạy shell. Cùng hash fixture trong hai snapshot xác nhận cùng mã tạo đầu vào và cùng oracle; địa chỉ port và thư mục tạm được tạo riêng mỗi lần.", ""]
    for a in review["cases"]:
        lines += ["## " + a["cve_id"], "", "| Tiêu chí hiện hành | Bằng chứng | Đạt/chưa đạt | Lý do |", "|---|---|---|---|"]
        for c in a["criteria"]:
            links = ", ".join("[" + (Path(p).name if not p.startswith("https:") else "advisory chính thức" if "x-stream.github.io" in p else "bản vá") + "](" + (p if p.startswith("https:") else "../" + p) + ")" for p in c["evidence"])
            lines.append("| " + c["criterion"] + " | " + links + " | " + ("Đạt" if c["status"] == "MET" else "Chưa đạt") + " | " + c["reason"] + " |")
        lines += ["", "Phạm vi nhãn: " + a["scope"], ""]
        if "upstream_scope_notes" in a:
            lines += ["Giới hạn upstream test: " + a["upstream_scope_notes"], ""]
    lines += ["## Diễn giải và giới hạn", "", "Bản vá Spark thêm guard ở ExternalResourceHandler.getResource và bắt DirectoryTraversalDetection ở StaticFilesConfiguration.consume. consumeWithFileResourceHandlers chỉ đổi khoảng trắng; nhãn của callable này phụ thuộc handler và caller, không phải thuộc tính an toàn độc lập. Guard external mới cũng chỉ được xác nhận cùng cấu hình StaticFilesFolder.external. Các callable classpath/JAR, cấu hình và helper không đủ bằng chứng riêng vẫn UNCONFIRMED.", "",
              "Ở XStream 2013, assertion cũ đạt khi có XStreamException và số callback bằng 0. Log mới ghi lỗi tìm converter trước khi fromXML trả về ở cả hai bản. Hai snapshot và 68 phiên bản callable giữ UNCONFIRMED vì chưa quan sát được hành vi cần phân biệt. [Đối chiếu exception, cấu hình và classpath](XSTREAM_DIAGNOSIS.md).", "",
              "Advisory chính thức mô tả cần caller gọi method trên proxy sau unmarshalling: [XStream CVE-2013-7285](https://x-stream.github.io/CVE-2013-7285.html). Nguồn Spark: [issue #700](https://github.com/perwendel/spark/issues/700). Bản vá, advisory JSON lưu trong repo và hành vi được đối chiếu cho đúng cặp commit; không mở rộng sang XStream 1.4.10 hay mọi đầu vào/formats.", "",
              "Upstream tests là bằng chứng chức năng hỗ trợ, không phải điều kiện thay thế paired security behavior. Đánh giá độc lập còn chờ được theo dõi riêng theo định nghĩa hiện hành. Receipt CI success ghi trong BUILD_RECOVERY.md chỉ xác nhận lệnh/job chạy đạt, không tự chứng minh fixture phân biệt được lỗi. Trạng thái Batch02 hiện là **2/10**, không phải 3/10.", "",
              "Danh sách đầy đủ từng callable: [BATCH02_CALLABLE_REVIEW.md](BATCH02_CALLABLE_REVIEW.md); [quyết định snapshot](../data/batch-02/snapshot-reviews.jsonl); [quyết định callable](../data/batch-02/reviews.jsonl). Intake summary.json giữ nguyên trạng thái lúc nhập; completion.json là trạng thái sau rà soát.", ""]
    (ROOT / "docs/BATCH02_REVIEW.md").write_text("\n".join(lines), encoding="utf-8")
    lines = ["# Quyết định từng callable Spark/XStream", "", "Người rà soát: AI; mọi nhãn có phạm vi và yêu cầu ngữ cảnh gọi. Quyết định đầy đủ, commit, khoảng dòng, hash fixture và phần thiếu nằm trong [reviews.jsonl](../data/batch-02/reviews.jsonl). RESOLVED_TARGET chỉ áp dụng các đầu vào external đã đo; UNCONFIRMED không phải mẫu âm an toàn.", ""]
    decisions = {r["sample_id"]:r for r in rows(ROOT / "data/batch-02", "reviews")}
    for cve in (a["cve_id"] for a in review["cases"]):
        lines += ["## " + cve, "", "| Sample | Callable | Phía | Nhãn | Căn cứ / phần thiếu |", "|---|---|---|---|---|"]
        for v in versions:
            if v["cve_id"] == cve:
                reason, needed = decisions[v["sample_id"]]["reason"], decisions[v["sample_id"]]["evidence_needed"]
                lines.append(f"| {v['sample_id']} | `{v['syntactic_signature']}` | {v['phase']} | {v['label']} | {reason} {needed} |")
        lines.append("")
    (ROOT / "docs/BATCH02_CALLABLE_REVIEW.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--cve", action="append", choices=TARGETS)
    parser.add_argument("--repos", type=Path, default=ROOT / ".cache/batch02-repos")
    args = parser.parse_args()
    apply(args.folder, args.repos, args.cve or TARGETS)
