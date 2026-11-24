"""Generate status tables from published receipts; retain each attempt separately."""
from collections import Counter
import json
from pathlib import Path
import re
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.catalog import ROOT, rows
from tools.quality import write_json

TOTAL = re.compile(r"^(?:\[\w+\]\s+)?Tests run: (\d+), Failures: (\d+), Errors: (\d+), Skipped: (\d+)\s*$", re.MULTILINE)


def load(run_id):
    return json.loads((ROOT/"evidence/v0.2.0"/run_id/"run.json").read_text(encoding="utf-8"))


def main():
    attempts=[load(i) for i in ("2db8826fb83749229df01b3b30db9ead","ad128fead9184743b58b027a65ee6192","aab27812edb14b81912ac90b458e48e5")]
    lines=["# Thử nghiệm Jenkins/NiFi và can thiệp môi trường", "", "Các trạng thái dưới đây được sinh từ receipt đã công bố. Không sửa mã production và không thay JAR phát hành vào chỗ build lỗi. Cả bốn hồ sơ đã có source Git và kiểm tra phương thức; chưa có bằng chứng tích hợp toàn hệ thống.", "", "| CVE | Lượt 1: khai báo HTTPS/180s | Lượt 2: offline + Jenkins HTTPS/60s | Lượt 3: retry + Jenkins HTTPS/90s |", "|---|---|---|---|"]
    for c in rows("cases"):
        if c["build_module"] is not None:
            continue
        values=[]
        for attempt in attempts:
            values.append("; ".join(r["phase"]+": "+r["status"]+" / "+r.get("error_category","none") for r in attempt["snapshots"] if r["cve_id"]==c["cve_id"]))
        lines.append("| "+c["cve_id"]+" | "+" | ".join(values)+" |")
    lines += ["", "Lượt 1 chạy profile package. Lượt 2 xác định cache chưa dùng được theo repository ID hiện tại: Git Client thiếu parent plugin3.49, Perfecto plugin4.0, Docker Commons plugin4.2 khi offline. Đây không chứng minh upstream đã xóa các artifact. Lượt 3 thêm kho Jenkins HTTPS, giới hạn connect/read, giữ riêng retry_of; vẫn hết thời gian ở đồ thị parent/plugin/phụ thuộc. Kiểm tra HTTPS bằng Python truy cập được Central và Jenkins; không gọi timeout Java/Maven là mất mạng toàn máy.", "", "NiFi đã đọc reactor41 mô-đun cho shell-authorizer nhưng dừng ở phạm vi thời gian thử nghiệm. Chưa build riêng Registry framework và chưa dựng mock command/provider hai hệ thống. Những cấu hình nới enforcer/skipTests được ghi trong lệnh; chúng không tạo bằng chứng tích hợp.", "", "Phần cần tiếp tục: lưu cache Maven đầy đủ và định danh dependency/plugin, thử ngân sách build dài hơn trong runner chuyên dụng, dựng Jenkins controller/agent harness, DockerRegistryEndpoint caller-path tests và mock OS commands cho cả hai mô-đun NiFi. Không đổi nhãn UNCONFIRMED của Docker Commons vì chỉ có build hoặc thay đổi guard.", "", "## Can thiệp đã ghi", "", "- Chuyển từ Python Windows thiếu encodings sang Ubuntu WSL; không sửa Python hệ thống.", "- Dùng JDK8u514/Maven3.9.9 khóa phiên bản; thêm mirror HTTPS cho repository Jenkins lịch sử.", "- Thử package có bỏ upstream tests/checkstyle/RAT/enforcer theo profile, sau đó thử cache ngoại tuyến và retry mạng có timeout cụ thể.", "- Dùng Tree-sitter wheel có SHA256 đặt trong cache riêng vì WSL thiếu pip.", "- Chỉ định tài khoản LeTriCao khi clone private vì máy lưu nhiều tài khoản GitHub.", "", "Các can thiệp này chưa được đo thời gian lao động đầy đủ. Thời gian subprocess được lưu trong từng receipt; không tính chúng thành thời gian gán nhãn hay kết luận tiết kiệm lao động.", "", "## Nguồn bằng chứng", ""]
    for attempt in attempts:
        lines.append("- ["+attempt["run_id"]+"](../evidence/v0.2.0/"+attempt["run_id"]+"/run.json), repository policy `"+attempt.get("repository_policy","not_recorded_in_first_attempt")+"`.")
    (ROOT/"docs/EXPERIMENTS.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    batch_id = "2b54f962ab544cb789aaf746c087715e"
    plexus_id = "9c2a5b8236d34dfbbd96d36ec9df0eb1"
    folder = ROOT / "data/batch-02"
    cases = [json.loads(line) for line in (folder / "cases.jsonl").read_text(encoding="utf-8").splitlines()]
    versions = [json.loads(line) for line in (folder / "versions.jsonl").read_text(encoding="utf-8").splitlines()]
    completion = json.loads((folder / "completion.json").read_text(encoding="utf-8"))
    review = json.loads((folder / "completion-review.json").read_text(encoding="utf-8"))
    build_runs = {a["cve_id"]: a.get("behavior_run_id") or a["receipt_run_id"] for a in review["cases"]}
    build_runs.update(completion["evidence_runs"])
    build_runs["CVE-2023-37460"] = plexus_id
    runs = {run_id: load(run_id) for run_id in {batch_id, *build_runs.values()}}
    # AI review of the last recorded build stage and the next verifiable evidence for each case.
    priorities = {
        "CVE-2023-37460": (1, "Cả hai lượt cũ hết hạn. Lượt mới package thành công và chạy hai lớp test upstream ở mỗi bản.",
                           "Đối chiếu phạm vi các test upstream với advisory và từng callable. Còn thiếu đối chứng và quan sát hành vi chung."),
        "CVE-2013-7285": (1, "Hai bản build được và đạt 27 AliasTest mỗi bản. Lượt chẩn đoán dừng trong fromXML khi tìm converter ở cả hai bản.",
                          "Chưa quan sát được hành vi của caller ở cả hai snapshot. Hai snapshot và 68 phiên bản callable giữ UNCONFIRMED."),
        "CVE-2020-26217": (2, "Build đạt. Lớp test upstream có 7 test trước và 9 test sau.",
                           "Thiếu đối chứng và bằng chứng hành vi theo advisory dưới cùng điều kiện gọi."),
        "CVE-2021-21345": (2, "Build đạt. Lớp test upstream có 11 test trước và 13 test sau trong bản vá liên quan nhiều CVE.",
                           "Thiếu đối chứng chung và bằng chứng phân biệt hành vi của riêng advisory này."),
        "CVE-2018-1000850": (3, "Before hết 90 giây ở kotlin:2.5.0-RC:compile. After báo compiler từ chối JDK 8.",
                             "Đối chiếu phiên bản plugin và JDK với POM hoặc CI ở commit đã ghim."),
        "CVE-2022-25174": (3, "Hết 90 giây khi Maven xác minh lại cache theo repository ID. Mục cuối là jzlib:1.1.3-kohsuke-1 trước và maven-dependency-tree:3.0.1 sau.",
                           "Xác minh repository ID và thời gian phân giải dependency trên cả hai bản."),
        "CVE-2022-25175": (3, "Hết 90 giây khi Maven xác minh lại cache theo repository ID. Mục cuối là jsch:0.1.55.2 trước và jenkins-stapler-support:1.1 sau.",
                           "Xác minh repository ID và thời gian phân giải dependency trên cả hai bản."),
        "CVE-2022-25842": (4, "Maven báo thiếu bytekit-instrument-api và bytekit-core 0.0.8-SNAPSHOT ở cả hai bản trong các kho đã hỏi.",
                           "Cần artifact hoặc revision lịch sử có thể kiểm tra nguồn gốc cho cả hai dependency."),
        "CVE-2016-9177": (None, "Hai bản build đạt. Đã xác nhận thay đổi trên đường gọi external static files được đo.",
                          "Hoàn tất theo phạm vi external. Các đường gọi classpath và JAR còn UNCONFIRMED."),
        "CVE-2022-4244": (None, "Hai bản build đạt. Kiểm tra parent traversal chuyển từ FAIL sang PASS. Trường hợp sibling-prefix vẫn FAIL cả hai bản.",
                          "Hoàn tất trong phạm vi các trường hợp đã đo."),
    }
    statuses = []
    for case in cases:
        cve = case["cve_id"]
        run_id = build_runs.get(cve, batch_id)
        run = runs[run_id]
        base = Path("evidence/v0.2.0") / run_id
        pair = {s["phase"]: s for s in run["snapshots"] if s["cve_id"] == cve}
        priority, finding, remaining = priorities[cve]
        item = dict(cve_id=cve, source_normalized=True, cwe=case["target_cwe"], advisory_cwes=case["advisory_cwe_ids"],
                    cwe_alignment=case["cwe_alignment"], build_run_id=run_id, before=pair["before"], after=pair["after"],
                    fully_completed=cve in completion["completed_cves"], priority=priority, finding=finding,
                    remaining=remaining, build_logs={}, upstream_totals={})
        for step in run["steps"]:
            if step.get("cve_id") != cve:
                continue
            phase = step["phase"]
            log = base / step["log"]
            if step["stage"] == "build":
                item["build_logs"][phase] = log.as_posix()
            if step["stage"] == "upstream-tests" and step["status"] == "PASS":
                counts = TOTAL.findall((ROOT / log).read_text(encoding="utf-8"))
                if len(counts) != 1:
                    raise ValueError(f"Expected one Surefire total in {log}")
                tests, failures, errors, skipped = map(int, counts[0])
                item["upstream_totals"][phase] = dict(tests=tests, executed=tests-skipped, failures=failures,
                                                      errors=errors, skipped=skipped, log=log.as_posix())
        statuses.append(item)
    built = sum(all(c[p].get("build_status") == "PASS" for p in ("before", "after")) for c in statuses)
    snapshots = sum(c[p].get("build_status") == "PASS" for p in ("before", "after") for c in statuses)
    write_json(folder / "build-status.json", dict(cases=statuses, source_built_cases=built, selected_cases=len(cases),
               source_built_snapshots=snapshots, selected_snapshots=2*len(cases), reviewer="AI",
               scope="Pinned source package outcomes. Artifact-only diagnostic replays are excluded."))
    labels = Counter(v["label"] for v in versions)
    lines = ["# Batch02", "",
             f"**{built}/{len(cases)} hồ sơ build được cả hai snapshot** ({snapshots}/{2*len(cases)} snapshot). "
             f"**{completion['fully_completed']}/{len(cases)} hồ sơ hoàn tất thực nghiệm** theo tiêu chí hiện hành. "
             f"Đã chuẩn hóa {completion['source_normalized']} hồ sơ, gồm {len(versions)} phiên bản callable.",
             "", "Nhãn theo dữ liệu hiện tại gồm " + ", ".join(f"{n} {label}" for label, n in labels.items()) +
             f". Người rà soát là **{completion['reviewer']}**. Có {completion['independent_human_reviews']} người đánh giá độc lập.", "",
             "## Ưu tiên các hồ sơ còn lại", "",
             "Ưu tiên 1 dành cho hồ sơ vừa có bằng chứng mới, 2 cho hồ sơ đã build còn thiếu đối chứng, "
             "3 cho trở ngại cấu hình hoặc thời gian build, 4 cho dependency lịch sử chưa xác minh được. "
             "Nhấn vào trạng thái trước hoặc sau để đọc log package đúng commit.", "",
             "| CVE | Ưu tiên | Build trước / sau | Kết quả đọc log | Công việc còn thiếu |", "|---|---:|---|---|---|"]
    for case in sorted(statuses, key=lambda c: (c["priority"] or 5, c["cve_id"])):
        logs = []
        for phase in ("before", "after"):
            snap = case[phase]
            status = snap.get("build_status") or snap.get("error_category") or snap["status"]
            logs.append(f"[{status}](../{case['build_logs'][phase]})")
        priority = case["priority"] or "Đã hoàn tất"
        lines.append(f"| {case['cve_id']} | {priority} | {' / '.join(logs)} | {case['finding']} | {case['remaining']} |")
    lines += ["", "Mỗi bản Plexus Archiver bỏ qua một test upstream. "
              "Bảng can thiệp ghi số test thực chạy, số bỏ qua, thời gian, cấu hình Maven và SHA của hai JAR. "
              "[Lượt khôi phục Plexus](BUILD_RECOVERY.md#plexus-archiver-cve-2023-37460) · "
              "[Chẩn đoán XStream](XSTREAM_DIAGNOSIS.md)."]
    mismatch=[c for c in statuses if c["cwe_alignment"]!="MATCH"]
    lines += ["", "## Phân loại và giới hạn", "", "Giữ target_cwe từ seed; advisory hiện hành được lưu riêng. Phân loại seed không tự động là nhãn vàng. Các hồ sơ có phân loại advisory khác hoặc không chỉ rõ: "+", ".join(c["cve_id"]+" ("+", ".join(c["advisory_cwes"])+")" for c in mismatch)+". Cần người đánh giá phạm vi trước khi dùng làm tập chuẩn CWE-78.", "", "Spark chọn parent thứ nhất của merge có lý do ghi trong selection. one-java-agent giữ mọi fix reference nhưng chỉ trích cặp ở fix đầu tiên; các fix còn lại cần rà soát đa commit. Parser phân biệt anonymous class và lexical occurrence khi chữ ký cú pháp trùng; không coi đây là chữ ký JVM hay ghép ngữ nghĩa hoàn hảo.", "", "UNCONFIRMED không phải safe negative. Đợt mới chưa đủ để kết luận độ chính xác ML. Các snapshot có upstream test PASS chưa chứng minh cơ chế lỗi được tái hiện. Thời gian90/180 giây là ngân sách của lượt thử, không phải kết luận bất khả build. Cache và dependency version range có thể làm kết quả đổi theo thời điểm; cần khóa dependency để nghiên cứu dài hạn.", "", "## Chạy lại", "", "`python3 run.py expand` tạo intake mới trong run mới, không ghi đè các nhãn đã rà soát. `python3 run.py batch-build data/batch-02 --cve CVE-2022-4244` chạy fixture mới. Các hồ sơ khác dùng cùng batch-build với --cve và timeout phù hợp. Xem INSTALL.md cho export, parser và split chung409 phiên bản.", "", "Bằng chứng: [build toàn batch](../evidence/v0.2.0/2b54f962ab544cb789aaf746c087715e/run.json), [fixture Expand](../evidence/v0.2.0/20fda5362b864cac988d7560180ebb00/run.json), [build-status.json](../data/batch-02/build-status.json), [quyết định nhãn](../data/batch-02/reviews.jsonl).", ""]
    text="\n".join(lines)
    text=text.replace("Các hồ sơ có phân loại advisory khác hoặc không chỉ rõ: .", "Không có hồ sơ nào trong lượt đối chiếu này thiếu target CWE của seed trong danh sách CWE advisory.")
    for old,new in (("IRIS;5","IRIS; 5"),("và5","và 5"),("parent.10/10","parent. 10/10"),("chuẩn hóa,222","chuẩn hóa, 222"),("Hiện1/10","Hiện 1/10"),("completion.json;2","completion.json; 2"),("và220","và 220"),("soát:AI;0","soát: AI; 0"),("có1 error","có 1 error"),("plugin2.5.0","plugin 2.5.0"),("Thời gian90/180","Thời gian 90/180"),("chung409","chung 409")):
        text=text.replace(old,new)
    text += "\nBảng đối chiếu từng tiêu chí: [BATCH02_REVIEW.md](BATCH02_REVIEW.md). Quyết định từng callable: [BATCH02_CALLABLE_REVIEW.md](BATCH02_CALLABLE_REVIEW.md). `summary.json` là bản chụp intake; `completion.json` ghi trạng thái hiện tại.\n"
    if "reviewed_callable_versions" in completion:
        text += f"\nĐã có {completion['reviewed_callable_versions']} quyết định AI ở cấp callable và {completion['reviewed_snapshot_decisions']} quyết định snapshot ghi riêng. Số quyết định rà soát không phải số nhãn xác nhận. Chẩn đoán XStream: [XSTREAM_DIAGNOSIS.md](XSTREAM_DIAGNOSIS.md).\n"
    (ROOT/"docs/BATCH02.md").write_text(text,encoding="utf-8")
    print("Generated Jenkins/NiFi and batch02 status tables")


if __name__=="__main__":
    main()
