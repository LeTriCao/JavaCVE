"""Generate status tables from published receipts; retain each attempt separately."""
from collections import Counter
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.catalog import ROOT, rows
from tools.quality import write_json


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
    batch=load("2b54f962ab544cb789aaf746c087715e")
    fixture=load("20fda5362b864cac988d7560180ebb00")
    cases=[json.loads(l) for l in (ROOT/"data/batch-02/cases.jsonl").read_text(encoding="utf-8").splitlines()]
    completion=json.loads((ROOT/"data/batch-02/completion.json").read_text())
    recovery_path = ROOT/"data/batch-02/build-recovery.json"
    recovered = json.loads(recovery_path.read_text(encoding="utf-8"))["cases"] if recovery_path.exists() else []
    review_path = ROOT/"data/batch-02/completion-review.json"
    reviewed = {a["cve_id"]:a for a in json.loads(review_path.read_text(encoding="utf-8"))["cases"]} if review_path.exists() else {}
    statuses=[]
    for c in cases:
        observations=[r for r in batch["snapshots"] if r["cve_id"]==c["cve_id"]]
        latest = [r for r in recovered if r["cve_id"] == c["cve_id"]]
        if latest:
            observations = latest
        if c["cve_id"]=="CVE-2022-4244":
            observations=fixture["snapshots"]
        if c["cve_id"] in reviewed:
            observations=[r for r in load(reviewed[c["cve_id"]]["behavior_run_id"])["snapshots"] if r["cve_id"]==c["cve_id"]]
        statuses.append(dict(cve_id=c["cve_id"],source_normalized=True,cwe=c["target_cwe"],advisory_cwes=c["advisory_cwe_ids"],cwe_alignment=c["cwe_alignment"],
                             before=next(r for r in observations if r["phase"]=="before"),after=next(r for r in observations if r["phase"]=="after"),
                             fully_completed=c["cve_id"] in completion["completed_cves"]))
    write_json(ROOT/"data/batch-02/build-status.json",dict(cases=statuses,source_built_snapshots=sum(r.get("build_status")=="PASS" for c in statuses for r in (c["before"],c["after"])),
                   selected_snapshots=2*len(statuses),scope="Attempted historical snapshots; build and upstream-test outcomes separated; use fully_completed only with scoped review and paired security fixture."))
    versions=[json.loads(l) for l in (ROOT/"data/batch-02/versions.jsonl").read_text(encoding="utf-8").splitlines()]
    labels=Counter(v["label"] for v in versions)
    lines=["# Batch02: mở rộng có kiểm soát", "", f"Nguồn: cùng revision CWE-Bench-Java/IRIS; 5 hồ sơ seed CWE-22 và 5 hồ sơ seed CWE-78. Metadata/advisory đã đối chiếu và nguồn khóa theo commit/parent. {completion['source_normalized']}/{completion['selected']} chuẩn hóa, {len(versions)} phiên bản callable. Hiện {completion['fully_completed']}/{completion['selected']} hồ sơ hoàn tất theo định nghĩa trong completion.json; "+", ".join(f"{count} {label}" for label,count in labels.items())+f". Người rà soát: {completion['reviewer']}; {completion['independent_human_reviews']} đánh giá độc lập.", "", "| CVE | Build trước / sau | Kết quả khác hoặc phần thiếu |", "|---|---|---|"]
    reasons={"CVE-2016-9177":"Before timeout; after build đạt nhưng lớp test upstream có1 error; chưa có fixture bảo mật chung hai bản.",
             "CVE-2018-1000850":"Dependency Kotlin dùng version range kéo plugin2.5.0-RC không phù hợp JDK8; cần pin dependency có nguồn gốc và đo lại. Không sửa source để che lỗi.",
             "CVE-2022-25842":"Thiếu bytekit-instrument-api/core0.0.8-SNAPSHOT; cần nguồn artifact lịch sử hoặc tái build dependency có revision xác minh.",
             "CVE-2022-4244":"Hoàn tất: control đạt; parent traversal FAIL→PASS; sibling-prefix vẫn FAIL cả hai. Hai nhãn VULNERABLE theo phạm vi đã đo.",
             "CVE-2023-37460":"Timeout package; cần fixture symlink trong thư mục tạm và kiểm tra đúng các nhánh ghi đè.",
             "CVE-2013-7285":"Before timeout, after build/upstream đạt; thiếu fixture thống nhất và diễn giải callable theo advisory.",
             "CVE-2020-26217":"Hai bản build và lớp upstream được chọn đạt; chưa chứng minh FAIL→PASS bằng cùng fixture, giữ UNCONFIRMED.",
             "CVE-2021-21345":"Hai bản build và lớp upstream được chọn đạt; thiếu fixture chung/caller context, giữ UNCONFIRMED.",
             "CVE-2022-25174":"Timeout ở Jenkins parent/plugin/dependency; cần harness điều kiện credential/controller/agent.",
             "CVE-2022-25175":"Timeout ở Jenkins parent/plugin/dependency; cần fixture tích hợp tương ứng advisory."}
    for c in statuses:
        if any(r["cve_id"] == c["cve_id"] for r in recovered):
            reasons[c["cve_id"]] = "Build trước/sau đạt; xem BUILD_RECOVERY.md và build-recovery.json cho thời gian và trạng thái upstream test. Bằng chứng bảo mật và nhãn đang được rà soát."
        if c["cve_id"] in reviewed:
            assessment=reviewed[c["cve_id"]]
            reasons[c["cve_id"]] = ("Hoàn tất trong phạm vi external static files: control PASS/PASS; hai URI mã hóa đọc marker ngoài trước, trả 404 sau. Nhãn consumer/guard phụ thuộc ngữ cảnh gọi; classpath/JAR/helper còn UNCONFIRMED."
                                      if assessment["fully_completed"] else "Chưa hoàn tất: control PASS/PASS, 27 AliasTest mỗi bản đạt; fixture báo ConversionException và 0 callback cả hai. Thiếu nguyên nhân exception, callback trước và bằng chứng xử lý đúng cơ chế sau; snapshot và 68 callable giữ UNCONFIRMED.")
        lines.append("| "+c["cve_id"]+" | "+c["before"].get("build_status",c["before"]["status"])+" / "+c["after"].get("build_status",c["after"]["status"])+" | "+reasons[c["cve_id"]]+" |")
    mismatch=[c for c in statuses if c["cwe_alignment"]!="MATCH"]
    lines += ["", "## Phân loại và giới hạn", "", "Giữ target_cwe từ seed; advisory hiện hành được lưu riêng. Phân loại seed không tự động là nhãn vàng. Các hồ sơ có phân loại advisory khác hoặc không chỉ rõ: "+", ".join(c["cve_id"]+" ("+", ".join(c["advisory_cwes"])+")" for c in mismatch)+". Cần người đánh giá phạm vi trước khi dùng làm tập chuẩn CWE-78.", "", "Spark chọn parent thứ nhất của merge có lý do ghi trong selection. one-java-agent giữ mọi fix reference nhưng chỉ trích cặp ở fix đầu tiên; các fix còn lại cần rà soát đa commit. Parser phân biệt anonymous class và lexical occurrence khi chữ ký cú pháp trùng; không coi đây là chữ ký JVM hay ghép ngữ nghĩa hoàn hảo.", "", "UNCONFIRMED không phải safe negative. Đợt mới chưa đủ để kết luận độ chính xác ML. Các snapshot có upstream test PASS chưa chứng minh cơ chế lỗi được tái hiện. Thời gian90/180 giây là ngân sách của lượt thử, không phải kết luận bất khả build. Cache và dependency version range có thể làm kết quả đổi theo thời điểm; cần khóa dependency để nghiên cứu dài hạn.", "", "## Chạy lại", "", "`python3 run.py expand` tạo intake mới trong run mới, không ghi đè các nhãn đã rà soát. `python3 run.py batch-build data/batch-02 --cve CVE-2022-4244` chạy fixture mới. Các hồ sơ khác dùng cùng batch-build với --cve và timeout phù hợp. Xem INSTALL.md cho export, parser và split chung409 phiên bản.", "", "Bằng chứng: [build toàn batch](../evidence/v0.2.0/2b54f962ab544cb789aaf746c087715e/run.json), [fixture Expand](../evidence/v0.2.0/20fda5362b864cac988d7560180ebb00/run.json), [build-status.json](../data/batch-02/build-status.json), [quyết định nhãn](../data/batch-02/reviews.jsonl).", ""]
    text="\n".join(lines)
    text=text.replace("Các hồ sơ có phân loại advisory khác hoặc không chỉ rõ: .", "Không có hồ sơ nào trong lượt đối chiếu này thiếu target CWE của seed trong danh sách CWE advisory.")
    for old,new in (("IRIS;5","IRIS; 5"),("và5","và 5"),("parent.10/10","parent. 10/10"),("chuẩn hóa,222","chuẩn hóa, 222"),("Hiện1/10","Hiện 1/10"),("completion.json;2","completion.json; 2"),("và220","và 220"),("soát:AI;0","soát: AI; 0"),("có1 error","có 1 error"),("plugin2.5.0","plugin 2.5.0"),("Thời gian90/180","Thời gian 90/180"),("chung409","chung 409")):
        text=text.replace(old,new)
    text += "\nBảng đối chiếu từng tiêu chí: [BATCH02_REVIEW.md](BATCH02_REVIEW.md). Quyết định từng callable: [BATCH02_CALLABLE_REVIEW.md](BATCH02_CALLABLE_REVIEW.md). `summary.json` là bản chụp intake; `completion.json` ghi trạng thái hiện tại.\n"
    (ROOT/"docs/BATCH02.md").write_text(text,encoding="utf-8")
    print("Generated Jenkins/NiFi and batch02 status tables")


if __name__=="__main__":
    main()
