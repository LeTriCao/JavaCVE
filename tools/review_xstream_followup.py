"""Review existing XStream receipts and diagnose logging gaps, without Java replay."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.catalog import ROOT
from tools.observations import require
from tools.quality import write_json
from tools.review_local_evidence import read, rows, write_rows, sha, receipt, generate_docs
from tools.runtime import utc

BATCH = "2b54f962ab544cb789aaf746c087715e"
LOCAL = "4063ba008c3644f5ad4d015ccd4cbcc4"
SOURCE = "2dc3374df54a4ed5b04e2894f1cb59f6"
TARGETS = ("CVE-2020-26217", "CVE-2021-21345")
SUMMARY = re.compile(r"Tests run: (\d+), Failures: (\d+), Errors: (\d+), Skipped: (\d+)")
SCOPES = {
    TARGETS[0]: "Untrusted input unmarshalled by pinned XStream with its default blacklist, without an application allowlist. The patch denies javax.imageio.ImageIO$ContainsFilter. Advisory behavior requires runtime classes plus either unmarshalling side effects or a later Iterator.next call. No common external fixture/ordinary control was executed in the receipt.",
    TARGETS[1]: "Untrusted input unmarshalled by pinned XStream with its default blacklist, without a minimal allowlist. The multi-CVE patch denies ServerTableEntry, IndexOrderComparator, GetterSetterReflection and several hierarchies. The advisory uses a PriorityQueue/JAX-WS/JAXB/CORBA caller chain during unmarshalling; added ByteArrayInputStream tests alone do not establish this RCE chain.",
}
MISSING = {
    TARGETS[0]: "A reviewed common bounded fixture with identical input/oracle and an ordinary control on both commits; document actual driver, blacklist/allowlist, runtime class availability, successful harmless callback before and its prevention after. Do not substitute the EventHandler fixture of CVE-2013-7285 or an explicit allowTypes override for default-policy evidence.",
    TARGETS[1]: "A reviewed common bounded fixture for the advisory PriorityQueue/JAX-WS/JAXB/CORBA caller path, with ordinary controls, runtime class availability, default policy and harmless observable behavior before/after. The pinned commit fixes multiple CVEs; ByteArrayInputStream zero-byte reads and blacklist entries do not prove this advisory's command-execution mechanism.",
}


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


def stage(run, cve, phase, name):
    steps = [s for s in run["steps"] if s.get("cve_id") == cve and s.get("phase") == phase and s["stage"] == name]
    require(len(steps) == 1 and steps[0]["status"] == "PASS" and steps[0]["exit_code"] == 0, "Missing successful stage: " + name)
    return steps[0]


def method_review(v):
    if v["is_test"]:
        return "TEST_OUTSIDE_TARGET", "Upstream test/setup code is supporting evidence, not a vulnerable production callable. Test bodies differ between snapshots.", "Keep outside standalone target labels; use a common reviewed fixture for behavior evidence."
    sig = v["syntactic_signature"]
    if "#setupSecurity(" in sig:
        reason = "Static default-blacklist change is verified. Application allowlists, later permission overrides and actual unmarshalling/caller behavior are not established by the existing paired tests."
    elif "#setupMappers(" in sig or "#unmarshal(" in sig:
        reason = "The indexed patch changes formatting/warning text in this callable, not the advisory security decision. Participation in a broad unmarshal path does not prove a callable-level vulnerability or fix."
    else:
        reason = "Dynamic hierarchy denial depends on loadable runtime classes, configured SecurityMapper and policy order; it is a helper shared by multiple fixes, without callable-specific paired advisory behavior."
    return "XSTREAM_DEFAULT_POLICY_CONTEXT_MISSING", reason, MISSING[v["cve_id"]]


def diagnose(folder, repos):
    path, run = receipt(LOCAL)
    case = next(c for c in rows(folder, "cases") if c["cve_id"] == "CVE-2013-7285")
    pair = {r["phase"]:r for r in run["snapshots"] if r["cve_id"] == case["cve_id"]}
    fixture = ROOT / "fixtures/XStreamLocalProbe.java"
    deps = {p:[(d["path"], d["sha256"]) for d in r["dependencies"]] for p, r in pair.items()}
    require(deps["before"] == deps["after"], "Dependency sequence differs")
    require(len(deps["before"]) == 15, "Dependency inventory differs")
    inventory = []
    for name, digest in deps["before"]:
        local = ROOT / name.removeprefix("<workspace>/")
        require(local.is_relative_to(ROOT) and sha(local) == digest, "Local dependency differs")
        inventory.append(dict(path=name, sha256=digest, local_bytes_verified=True))
    logs, observations = {}, []
    for phase, r in pair.items():
        require(r["commit"] == case[phase + "_commit"], "Diagnostic identity mismatch")
        require(r["security"]["fixture_sha256"] == sha(fixture), "Diagnostic fixture changed")
        step = stage(run, case["cve_id"], phase, "security")
        log = path.parent / step["log"]
        text = log.read_text(encoding="utf-8")
        require(text.splitlines() == ["ASSERT|control|string_roundtrip|true", "OBSERVED_EXCEPTION=com.thoughtworks.xstream.converters.ConversionException", "OBSERVED_CALLBACKS=0", "ASSERT|security|untrusted_event_handler_blocked|true"], "Diagnostic log differs")
        raw = ROOT / "runs" / LOCAL / step["log"]
        raw_match = sha(raw) == sha(log) if raw.exists() else None
        artifact = ROOT / "runs" / LOCAL / r["artifact"]
        require(sha(artifact) == r["artifact_sha256"], "Source-built artifact differs")
        logs[phase] = dict(path=log.relative_to(ROOT).as_posix(), sha256=sha(log), raw_local_log_matches=raw_match)
        observations.append(dict(phase=phase, commit=r["commit"], artifact_sha256=r["artifact_sha256"],
                                 local_artifact_bytes_verified=True, fixture_sha256=r["security"]["fixture_sha256"],
                                 exception_class="com.thoughtworks.xstream.converters.ConversionException", callbacks=0,
                                 java_command=step["command"], environment_overrides=r.get("environment_overrides", {})))
    repo = repos / case["cve_id"]
    sources = []
    for file in ("pom.xml", "xstream/pom.xml", "xstream/src/java/com/thoughtworks/xstream/core/JVM.java",
                 "xstream/src/java/com/thoughtworks/xstream/io/xml/DomDriver.java",
                 "xstream/src/java/com/thoughtworks/xstream/converters/extended/DynamicProxyConverter.java"):
        values = {p:hashlib.sha256(git(repo, "show", case[p + "_commit"] + ":" + file)).hexdigest() for p in pair}
        sources.append(dict(path=file, before_sha256=values["before"], after_sha256=values["after"], identical=len(set(values.values())) == 1))
    require(all(s["identical"] for s in sources), "Diagnostic source comparison differs")
    diagnostic = dict(cve_id=case["cve_id"], review_basis_commit="8fefbe9", reviewer="AI", independent_human_review=False,
                      source_receipt=path.relative_to(ROOT).as_posix(), source_receipt_sha256=sha(path),
                      method="Read existing published/raw logs, receipt commands and dependency inventories; hash local JAR/dependency bytes; compare pinned Git sources. No Java replay or new fixture execution.",
                      root_cause_status="UNDETERMINED_FROM_EXISTING_LOGS", exception_phase="UNCONFIRMED",
                      conclusion="The fixture logs only error.getClass().getName(), discarding message, cause chain and stack frames. Both snapshots have a ConversionException and zero callbacks, but neither the failed conversion stage nor its root cause can be recovered. Dependency drift is not supported by the identical recorded 15-file sequence and hashes; no mitigation claim follows.",
                      confirmed_configuration="Same DomDriver fixture bytes, default XStream construction, same JDK8u514/Maven3.9.9 run, same runtime dependency order/hashes and classpath order (probe, source-built XStream JAR, dependencies). No phase-specific environment override is recorded. This is not a complete JVM environment dump.",
                      policy_comparison="Before has no SecurityMapper; after adds SecurityMapper and setupSecurity with AnyTypePermission.ANY. The fixture installs no allowlist or denial. The patch adds policy APIs, which alone do not explain the shared ConversionException.",
                      unconfirmed_hypotheses=["Object construction/reflection-provider limitation", "Mapper/converter/type resolution failure", "Proxy/handler conversion or invocation-stage failure"],
                      excluded_claims=["ConversionException proves ForbiddenClassException/type-policy rejection", "After default policy blocks the advisory", "A missing/different external dependency caused the failure", "The exception definitely happened inside fromXML rather than callback.run"],
                      logs=logs, observations=observations, dependencies=inventory, unchanged_sources=sources,
                      next_experiment=["Keep existing receipts and fixture immutable; create a separate diagnostic variant with a new hash.",
                                       "Log full exception message/stack/cause chain and stage markers before/after fromXML and callback.run; record actual reflection provider, selected converter/mapper, driver, JDK and classpath.",
                                       "Run identical diagnostic code/input on both verified source-built artifacts with the same dependencies and ordinary string/object controls. Keep default-policy and any explicit-policy experiments separate.",
                                       "Treat unrelated ConversionException as a harness/diagnostic failure, not successful security rejection. Establish successful construction and a harmless callback on before before evaluating mitigation; no shell/network payload is needed."])
    write_json(folder / "xstream-diagnosis.json", diagnostic)
    write_diagnosis_doc(diagnostic)
    return diagnostic


def apply(folder, repos):
    report = read(folder / "completion-review.json")
    stamp = report.get("xstream_followup_review_utc") or utc()
    report.setdefault("previous_review_utc", report["review_utc"])
    report.update(previous_review_basis_commit="a7e6abd", review_basis_commit="8fefbe9", review_utc=stamp, xstream_followup_review_utc=stamp)
    cases, versions = rows(folder, "cases"), rows(folder, "versions")
    receipt_path, run = receipt(BATCH)
    source_path, audit = receipt(SOURCE)
    require(audit["source_review"]["checked_method_versions"] == len(versions) == 222 and audit["ast_review"]["failures"] == [], "Incomplete source evidence")
    decisions, snapshots, assessments = [], [], []
    for case in cases:
        cve = case["cve_id"]
        if cve not in TARGETS:
            continue
        repo = repos / cve
        require(git(repo, "rev-parse", case["after_commit"] + "^1").decode().strip() == case["before_commit"], "Parent mismatch")
        observations = []
        for phase in ("before", "after"):
            require(git(repo, "rev-parse", case[phase + "_commit"] + "^{tree}").decode().strip() == case[phase + "_tree"], "Tree mismatch")
            selected = [r for r in run["snapshots"] if r["cve_id"] == cve and r["phase"] == phase]
            require(len(selected) == 1, "Missing unique snapshot")
            r = selected[0]
            require(r["commit"] == case[phase + "_commit"] and r["build_status"] == r["status"] == "PASS" and not r["source_integrity"]["changed_files"], "Invalid source build")
            require(r["security_status"] == "BLOCKED_NO_REVIEWED_PAIRED_FIXTURE" and "security" not in r, "Unexpected security evidence")
            build = stage(run, cve, phase, "build")
            test = stage(run, cve, phase, "upstream-tests")
            require(build["commit"] == test["commit"] == r["commit"], "Stage identity mismatch")
            log = receipt_path.parent / test["log"]
            summaries = SUMMARY.findall(log.read_text(encoding="utf-8"))
            require(summaries and len(set(summaries)) == 1, "Missing/ambiguous upstream summary")
            counts = dict(zip(("tests", "failures", "errors", "skipped"), map(int, summaries[-1])))
            require(counts["tests"] > 0 and not any(counts[k] for k in ("failures", "errors", "skipped")), "Upstream tests not successful")
            observations.append(dict(phase=phase, commit=r["commit"], artifact_sha256=r["artifact_sha256"],
                                     build_log=(receipt_path.parent / build["log"]).relative_to(ROOT).as_posix(),
                                     log=log.relative_to(ROOT).as_posix(), log_sha256=sha(log), selected_classes=r["upstream_tests"]["selected_classes"],
                                     **counts, security_status=r["security_status"]))
            snapshots.append(dict(cve_id=cve, phase=phase, commit=r["commit"], decision="UNCONFIRMED", reviewer="AI", independent_human_review=False,
                                  review_utc=stamp, scope=SCOPES[cve], evidence_run_id=BATCH, reason=MISSING[cve]))
            case[phase + "_label"] = "UNCONFIRMED"
        expected = [7, 9] if cve == TARGETS[0] else [11, 13]
        require([r["tests"] for r in observations] == expected, "Upstream test counts differ")
        scope = SCOPES[cve]
        evidence = [receipt_path.relative_to(ROOT).as_posix()] + [o["log"] for o in observations]
        notes = [
            ("source_identity", "Source identity", True, "Pinned commits/trees/first parent match Git; receipt records no source mutation.", [source_path.relative_to(ROOT).as_posix()]),
            ("extraction", "Extraction", True, "222/222 callable versions passed source/AST audit; this case's indexed snippets are rechecked against pinned Git bytes.", [source_path.relative_to(ROOT).as_posix()]),
            ("advisory_patch_context", "Advisory and patch context", True, scope, ["data/batch-02/advisories/" + cve + ".json", case["repository_url"] + "/commit/" + case["after_commit"], "https://x-stream.github.io/" + cve + ".html"]),
            ("scoped_ai_method_review", "Scoped AI method review", True, "All indexed callable versions and both snapshots reviewed by AI; static observations retained separately from unproven advisory behavior.", ["data/batch-02/reviews.jsonl", "data/batch-02/snapshot-reviews.jsonl"]),
            ("paired_source_builds", "Paired source builds", True, "Both source builds and selected SecurityVulnerabilityTest class pass. Test totals differ: " + str(expected) + "; zero failures/errors/skips. The tests are not a common paired fixture. The overall batch receipt is FAIL due to other CVEs; these selected snapshots/stages are PASS.", evidence),
            ("ordinary_controls", "Ordinary controls", False, "No reviewed common ordinary-control fixture is recorded on both commits. Existing authorized-injection tests change policy/body and do not substitute for this criterion.", evidence),
            ("paired_security_behavior", "Reviewed paired security behavior", False, MISSING[cve], evidence),
        ]
        assessments.append(dict(cve_id=cve, fully_completed=False, reviewer="AI", independent_human_review=False, scope=scope,
                                receipt_run_id=BATCH, receipt_run_status=run["status"], behavior_run_id=None, source_run_id=SOURCE, fixture_sha256=None,
                                observations=[], upstream_observations=observations,
                                overview_row=f"| {cve} | Default blacklist, input không tin cậy; policy/caller/runtime phải ghi rõ | Build PASS/PASS; upstream {expected[0]}→{expected[1]} test đạt | Thay đổi blacklist và test đã đối chiếu tĩnh | Thiếu control chung và hành vi paired đúng advisory; **chưa hoàn tất** |",
                                status_summary=f"Chưa hoàn tất: build PASS/PASS; SecurityVulnerabilityTest {expected[0]}→{expected[1]} test đạt nhưng nội dung khác. Thiếu control chung và hành vi paired đúng advisory; mọi snapshot/callable giữ UNCONFIRMED.",
                                upstream_scope_notes="SecurityVulnerabilityTest overrides setupSecurity with an empty method; individual tests can explicitly allow types. In 2020 the explicit EventHandler test also changes converter registration between snapshots, and the new ContainsFilter cases are guarded by JVM.isVersion(7), meaning >= Java 7 (the recorded JDK8 satisfies this check). In 2021 the added tests cover denial and explicit allowance of manipulated ByteArrayInputStream, not the advisory RCE chain.",
                                criteria=[dict(id=i, criterion=n, required=True, status="MET" if met else "NOT_MET", reason=reason, evidence=links) for i, n, met, reason, links in notes],
                                missing_required_evidence=[notes[-2][3], MISSING[cve]], independent_human_review_status="PENDING; separately tracked"))
        case.update(label_scope=scope, evidence_sets=["batch02_source_build", "batch02_upstream_tests"], evidence_run_id=BATCH)
        for v in versions:
            if v["cve_id"] != cve:
                continue
            data = git(repo, "show", v["commit"] + ":" + v["file_path"])
            snippet = b"".join(data.splitlines(keepends=True)[v["start_line"]-1:v["end_line"]]).strip()
            require(hashlib.sha256(snippet).hexdigest() == v["code_sha256"], "Callable source differs")
            group, reason, needed = method_review(v)
            v.update(label="UNCONFIRMED", rule_id=group, unknown_reason_group=group, label_scope=scope + " " + reason,
                     evidence_needed=needed, evidence_run_id=BATCH, caller_context_required=True)
            decisions.append(dict(sample_id=v["sample_id"], cve_id=cve, phase=v["phase"], commit=v["commit"], previous_label="UNCONFIRMED", decision="UNCONFIRMED", reviewer="AI",
                                  independent_human_review=False, review_utc=stamp, scope=v["label_scope"], reason=reason, evidence_needed=needed,
                                  evidence_run_id=BATCH, source_run_id=SOURCE, source_lines=[v["start_line"], v["end_line"]], caller_context_required=True))
    require(len(decisions) == 23, "Unexpected callable coverage")
    old_reviews = [r for r in rows(folder, "reviews") if r.get("cve_id") not in TARGETS]
    old_snapshots = [r for r in rows(folder, "snapshot-reviews") if r["cve_id"] not in TARGETS]
    report["cases"] = [a for a in report["cases"] if a["cve_id"] not in TARGETS] + assessments
    report["receipt_sha256"].update({BATCH:sha(receipt_path)})
    report.update(reviewed_callable_versions=sum(r.get("cve_id") in {a["cve_id"] for a in report["cases"]} for r in old_reviews + decisions),
                  reviewed_snapshot_count=len(old_snapshots + snapshots))
    completion = read(folder / "completion.json")
    completion.update(labels=dict(Counter(v["label"] for v in versions)), reviewed_callable_versions=len(old_reviews + decisions), reviewed_snapshot_decisions=len(old_snapshots + snapshots))
    require(not (set(TARGETS) & set(completion["completed_cves"])), "Unexpected completion promotion")
    write_rows(folder, "versions", versions)
    write_rows(folder, "cases", cases)
    write_rows(folder, "reviews", old_reviews + decisions)
    write_rows(folder, "snapshot-reviews", old_snapshots + snapshots)
    write_json(folder / "completion-review.json", report)
    write_json(folder / "completion.json", completion)
    diagnose(folder, repos)
    generate_docs(report, versions)
    print("Reviewed 23 new callable versions and 4 snapshots; diagnosed existing logs; completion remains 2/10")


def write_diagnosis_doc(d):
    lines = ["# Chẩn đoán XStream CVE-2013-7285 từ receipt hiện có", "", "Người rà soát: **AI**. Kết luận: **chưa xác định được nguyên nhân gốc của ConversionException từ log cũ**. [Chẩn đoán JSON](../data/batch-02/xstream-diagnosis.json) lưu hash, đối chiếu cấu hình/phụ thuộc và bước thử tiếp theo. Không chạy lại Java hoặc payload trong lượt chẩn đoán này.", "",
             "| Mục | Kết quả đã xác nhận | Bằng chứng / giới hạn |", "|---|---|---|",
             "| Exception/callback | ConversionException; 0 callback; control đạt ở cả hai bản | [before log](../"+d["logs"]["before"]["path"]+"), [after log](../"+d["logs"]["after"]["path"]+"). Bản raw cục bộ khớp byte bản công bố; cả hai đều không có message/cause/stack. |",
             "| Vì sao không truy được root cause | catch chỉ in error.getClass().getName(); try bao cả fromXML và run | [Fixture](../fixtures/XStreamLocalProbe.java). Mất thông tin chẩn đoán; không xác định được giai đoạn lỗi từ cờ rejected. |",
             "| Fixture và toolchain | Cùng hash fixture; DomDriver; JDK8u514, Maven3.9.9 | [Receipt](../"+d["source_receipt"]+"). Không có override riêng theo phase được ghi nhận; không phải bản dump đầy đủ môi trường JVM. |",
             "| Dependency | 15/15 đường dẫn, thứ tự và SHA-256 giống nhau; byte cache được kiểm tra lại | Danh sách đầy đủ trong JSON. Không có bằng chứng dependency drift gây lỗi; không chứng minh mọi lớp đã load đúng ở runtime. |",
             "| Artifact | Hai JAR build từ hai source commit, SHA khác nhau; byte local khớp receipt | Không thay bằng JAR phát hành. Classpath đặt probe → XStream JAR → 15 dependency ở cả hai. |",
             "| Source cấu hình | Root/module POM, JVM.java, DomDriver, DynamicProxyConverter giống byte | Hash trước/sau trong JSON. Provider thực sự được chọn chưa được log. |",
             "| Policy | Before không có SecurityMapper; after thêm SecurityMapper với AnyTypePermission.ANY | Fixture không cài allowlist/deny. Không thể coi exception chung là bằng chứng bản vá chặn advisory. |", "",
             "## Giả thuyết và quyết định bước tiếp", "", "Các giả thuyết về reflection/object construction, mapper/converter/type resolution và proxy/handler chỉ là **chưa xác nhận**. Không có message/cause để chọn một giả thuyết làm nguyên nhân gốc. Giữ UNCONFIRMED ở cả snapshot và callable CVE-2013-7285.", ""]
    lines += [str(i) + ". " + step for i, step in enumerate(d["next_experiment"], 1)]
    lines += ["", "Hai CVE XStream mới đã được đối chiếu riêng trong [bảng tiêu chí Batch02](BATCH02_REVIEW.md). Fixture EventHandler của năm 2013 không thay thế được chuỗi ContainsFilter của năm 2020 hoặc PriorityQueue/JAX-WS/JAXB/CORBA của năm 2021.", ""]
    (ROOT / "docs/XSTREAM_DIAGNOSIS.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--repos", type=Path, default=ROOT / ".cache/batch02-repos")
    args = parser.parse_args()
    apply(args.folder, args.repos)
