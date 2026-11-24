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
    "Pinned XStream snapshots, DomDriver, default XStream configuration, untrusted XML "
    "requesting a Runnable dynamic proxy with java.beans.EventHandler and a harmless Marker.touch target; "
    "the caller would invoke run() only after successful unmarshalling. Both logs show "
    "ConversionException and zero callbacks. No root cause or successful proxy construction is recorded. "
    "This does not establish advisory callback execution or its prevention by the patch."
)
XSTREAM_MISSING = (
    "A bounded fixture must first demonstrate successful proxy construction and a harmless callback "
    "on before, record the exception cause and conversion stage, then evaluate the same input/oracle "
    "on after with any security configuration stated explicitly and ordinary controls passing. "
    "The pinned patch's setupSecurity adds AnyTypePermission.ANY; new permission APIs alone "
    "do not prove default rejection. Map the result to the actual caller and affected callable. "
    "No shell execution is needed. Version 1.4.10, JSON and other gadget chains are outside this pair."
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
            reason = "Mapper/permission behavior depends on caller configuration; the existing fixture cannot distinguish mitigation from conversion failure. setupSecurity defaults to AnyTypePermission.ANY."
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


def apply(folder, repos):
    behavior_path, behavior = receipt(BEHAVIOR)
    source_path, source = receipt(SOURCE)
    require(behavior["status"] == source["status"] == "PASS", "Unfinished evidence")
    require(source["source_review"]["checked_method_versions"] == 222 and not source["ast_review"]["failures"], "Incomplete source audit")
    versions, cases = rows(folder, "versions"), rows(folder, "cases")
    require(source["ast_review"]["matched_versions"] == len(versions), "AST coverage differs")
    previous_review = folder / "completion-review.json"
    review_time = read(previous_review)["review_utc"] if previous_review.exists() else utc()
    assessments, snapshots, decisions = [], [], []
    for case in cases:
        cve = case["cve_id"]
        if cve not in TARGETS:
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
            ("paired_security_behavior", "Reviewed paired security behavior", spark, "Two encoded traversal cases return the outside marker before and 404 after; literal /../ returns 400 on both and does not demonstrate a regression." if spark else "Assertion PASS/PASS means only that an XStreamException occurred and callbacks stayed zero. ConversionException cause is absent; this is not evidence of advisory mitigation. " + XSTREAM_MISSING),
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
        assessments.append(assessment)
        for r in pair:
            label = ("VULNERABLE" if r["phase"] == "before" else "RESOLVED_TARGET") if spark else "UNCONFIRMED"
            snapshots.append(dict(cve_id=cve, phase=r["phase"], commit=r["commit"], decision=label, reviewer="AI",
                                  independent_human_review=False, review_utc=review_time, scope=scope,
                                  evidence_run_id=BEHAVIOR, reason=criteria[-1][3]))
            case[r["phase"] + "_label"] = label
        case.update(label_scope=scope, check="spark-local" if spark else "xstream-local", evidence_run_id=BEHAVIOR,
                    evidence_sets=["batch02_source_build_security"] if spark else ["batch02_source_build", "batch02_fixture_inconclusive"])
        for v in versions:
            if v["cve_id"] != cve:
                continue
            label, group, reason, needed = method_decision(v)
            v.update(label=label, rule_id=group, unknown_reason_group=group if label == "UNCONFIRMED" else None,
                     label_scope=scope + " " + reason, evidence_needed=needed, evidence_run_id=BEHAVIOR,
                     caller_context_required=True)
            decisions.append(dict(sample_id=v["sample_id"], cve_id=cve, phase=v["phase"], commit=v["commit"],
                                  previous_label="UNCONFIRMED", decision=label, reviewer="AI", independent_human_review=False,
                                  review_utc=review_time, scope=v["label_scope"], reason=reason, evidence_needed=needed,
                                  caller_context_required=True, evidence_run_id=BEHAVIOR, source_run_id=SOURCE,
                                  fixture_sha256=assessment["fixture_sha256"], source_lines=[v["start_line"], v["end_line"]]))
    completion = read(folder / "completion.json")
    completed = [c for c in completion["completed_cves"] if c not in TARGETS]
    completed += [a["cve_id"] for a in assessments if a["fully_completed"]]
    completion.update(fully_completed=len(completed), completed_cves=completed,
                      labels=dict(Counter(v["label"] for v in versions)),
                      evidence_runs={"CVE-2022-4244": completion["evidence_run_id"], **{a["cve_id"]: BEHAVIOR for a in assessments if a["fully_completed"]}},
                      assessment_path="data/batch-02/completion-review.json")
    review = dict(review_basis_commit="a7e6abd", review_utc=review_time, reviewer="AI", independent_human_reviews=0,
                  policy=completion["definition"], evidence_policy="Existing receipts only; no new security fixture or payload execution in this review.",
                  receipt_sha256={BEHAVIOR: sha(behavior_path), SOURCE: sha(source_path)}, cases=assessments,
                  reviewed_callable_versions=len(decisions), reviewed_snapshot_count=len(snapshots))
    write_rows(folder, "versions", versions)
    write_rows(folder, "cases", cases)
    old = [r for r in rows(folder, "reviews") if r.get("cve_id") not in TARGETS and not any(r["sample_id"].startswith(c) for c in TARGETS)]
    write_rows(folder, "reviews", old + decisions)
    write_rows(folder, "snapshot-reviews", snapshots)
    write_json(folder / "completion-review.json", review)
    write_json(folder / "completion.json", completion)
    generate_docs(review, versions)
    print(f"Reviewed {len(decisions)} callable versions and {len(snapshots)} snapshots; completion {len(completed)}/{len(cases)}")


def generate_docs(review, versions):
    lines = ["# Rà soát Spark và XStream từ a7e6abd", "", "Người rà soát: **AI**; 0 người đánh giá độc lập. Đối chiếu định nghĩa hiện hành trong [completion.json](../data/batch-02/completion.json); quyết định có cấu trúc ở [completion-review.json](../data/batch-02/completion-review.json). Lượt này dùng receipt có sẵn và chạy lại kiểm tra toàn vẹn nguồn; không chạy fixture bảo mật mới.", "",
             "| CVE | Điều kiện áp dụng | Before / after | Phạm vi đã chứng minh | Còn thiếu |", "|---|---|---|---|---|",
             "| CVE-2016-9177 | HTTP vào externalStaticFileLocation; process đọc được marker ngoài public, trong cây tạm do fixture quản lý | Control PASS/PASS; hai URI mã hóa: 200 + marker → 404; literal /../: 400/400 | Đọc file ngoài external root trước, chặn hai đầu vào đó sau; **hoàn tất theo phạm vi** | Classpath/JAR, symlink, tên sibling cùng prefix chưa đo; đánh giá độc lập còn chờ |",
             "| CVE-2013-7285 | XML không tin cậy → dynamic proxy/EventHandler; cần unmarshal thành công rồi caller gọi method; policy phải ghi rõ | Control PASS/PASS; ConversionException, 0 callback cả hai; assertion PASS/PASS | JAR build được; 27 AliasTest mỗi bản đạt; phép thử hiện tại không chạy được callback | Nguyên nhân exception và giai đoạn lỗi; callback vô hại trên before; cùng input/oracle sau với policy rõ ràng; ánh xạ callable. **Chưa hoàn tất** |", "",
             "Fixture Spark chỉ tạo/đọc marker trong cây tạm và bind 127.0.0.1. XStream dùng Marker.touch, không chạy shell. Cùng hash fixture trong hai snapshot xác nhận cùng mã tạo đầu vào và cùng oracle; địa chỉ port và thư mục tạm được tạo riêng mỗi lần.", ""]
    for a in review["cases"]:
        lines += ["## " + a["cve_id"], "", "| Tiêu chí hiện hành | Bằng chứng | Đạt/chưa đạt | Lý do |", "|---|---|---|---|"]
        for c in a["criteria"]:
            links = ", ".join("[" + (Path(p).name if not p.startswith("https:") else "bản vá") + "](" + (p if p.startswith("https:") else "../" + p) + ")" for p in c["evidence"])
            lines.append("| " + c["criterion"] + " | " + links + " | " + ("Đạt" if c["status"] == "MET" else "Chưa đạt") + " | " + c["reason"] + " |")
        lines += ["", "Phạm vi nhãn: " + a["scope"], ""]
    lines += ["## Diễn giải và giới hạn", "", "Bản vá Spark thêm guard ở ExternalResourceHandler.getResource và bắt DirectoryTraversalDetection ở StaticFilesConfiguration.consume. consumeWithFileResourceHandlers chỉ đổi khoảng trắng; nhãn của callable này phụ thuộc handler và caller, không phải thuộc tính an toàn độc lập. Guard external mới cũng chỉ được xác nhận cùng cấu hình StaticFilesFolder.external. Các callable classpath/JAR, cấu hình và helper không đủ bằng chứng riêng vẫn UNCONFIRMED.", "",
              "XStreamLocalProbe coi mọi XStreamException kèm 0 callback là assertion đạt. Log chỉ ghi tên ConversionException, không ghi message/cause hay giai đoạn; do đó không thể xác định lỗi do type policy, dựng object hay mapper. Bản vá được ghim thêm SecurityMapper và setupSecurity với AnyTypePermission.ANY. Không suy ra cấu hình mặc định đã từ chối EventHandler. 68 phiên bản callable XStream và hai snapshot giữ UNCONFIRMED; việc rà soát xong một tiêu chí không làm cả hồ sơ hoàn tất.", "",
              "Advisory chính thức mô tả cần caller gọi method trên proxy sau unmarshalling: [XStream CVE-2013-7285](https://x-stream.github.io/CVE-2013-7285.html). Nguồn Spark: [issue #700](https://github.com/perwendel/spark/issues/700). Bản vá, advisory JSON lưu trong repo và hành vi được đối chiếu cho đúng cặp commit; không mở rộng sang XStream 1.4.10 hay mọi đầu vào/formats.", "",
              "Upstream tests là bằng chứng chức năng hỗ trợ, không phải điều kiện thay thế paired security behavior. Đánh giá độc lập còn chờ được theo dõi riêng theo định nghĩa hiện hành. Receipt CI success ghi trong BUILD_RECOVERY.md chỉ xác nhận lệnh/job chạy đạt, không tự chứng minh fixture phân biệt được lỗi. Trạng thái Batch02 hiện là **2/10**, không phải 3/10.", "",
              "Danh sách đầy đủ từng callable: [BATCH02_CALLABLE_REVIEW.md](BATCH02_CALLABLE_REVIEW.md); [quyết định snapshot](../data/batch-02/snapshot-reviews.jsonl); [quyết định callable](../data/batch-02/reviews.jsonl). Intake summary.json giữ nguyên trạng thái lúc nhập; completion.json là trạng thái sau rà soát.", ""]
    (ROOT / "docs/BATCH02_REVIEW.md").write_text("\n".join(lines), encoding="utf-8")
    lines = ["# Quyết định từng callable Spark/XStream", "", "Người rà soát: AI; mọi nhãn có phạm vi và yêu cầu ngữ cảnh gọi. Quyết định đầy đủ, commit, khoảng dòng, hash fixture và phần thiếu nằm trong [reviews.jsonl](../data/batch-02/reviews.jsonl). RESOLVED_TARGET chỉ áp dụng các đầu vào external đã đo; UNCONFIRMED không phải mẫu âm an toàn.", ""]
    for cve in TARGETS:
        lines += ["## " + cve, "", "| Sample | Callable | Phía | Nhãn | Căn cứ / phần thiếu |", "|---|---|---|---|---|"]
        for v in versions:
            if v["cve_id"] == cve:
                _, _, reason, needed = method_decision(v)
                lines.append(f"| {v['sample_id']} | `{v['syntactic_signature']}` | {v['phase']} | {v['label']} | {reason} {needed} |")
        lines.append("")
    (ROOT / "docs/BATCH02_CALLABLE_REVIEW.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--repos", type=Path, default=ROOT / ".cache/batch02-repos")
    args = parser.parse_args()
    apply(args.folder, args.repos)
