# Batch02: mở rộng có kiểm soát

Nguồn: cùng revision CWE-Bench-Java/IRIS; 5 hồ sơ seed CWE-22 và 5 hồ sơ seed CWE-78. Metadata/advisory đã đối chiếu và nguồn khóa theo commit/parent. 10/10 chuẩn hóa, 222 phiên bản callable. Hiện 1/10 hồ sơ hoàn tất theo định nghĩa trong completion.json; 2 phiên bản VULNERABLE và 220 UNCONFIRMED. Người rà soát: AI; 0 đánh giá độc lập.

| CVE | Build trước / sau | Kết quả khác hoặc phần thiếu |
|---|---|---|
| CVE-2016-9177 | PASS / PASS | Build và lớp test upstream đạt cả hai bản sau khi đặt java.io.tmpdir riêng có dấu / cuối. Chưa có fixture bảo mật chung hai bản. |
| CVE-2018-1000850 | FAIL / FAIL | Dependency Kotlin dùng version range kéo plugin 2.5.0-RC không phù hợp JDK8; cần pin dependency có nguồn gốc và đo lại. Không sửa source để che lỗi. |
| CVE-2022-25842 | FAIL / FAIL | Thiếu bytekit-instrument-api/core0.0.8-SNAPSHOT; cần nguồn artifact lịch sử hoặc tái build dependency có revision xác minh. |
| CVE-2022-4244 | PASS / PASS | Hoàn tất: control đạt; parent traversal FAIL→PASS; sibling-prefix vẫn FAIL cả hai. Hai nhãn VULNERABLE theo phạm vi đã đo. |
| CVE-2023-37460 | FAIL / FAIL | Timeout package; cần fixture symlink trong thư mục tạm và kiểm tra đúng các nhánh ghi đè. |
| CVE-2013-7285 | PASS / PASS | Đã chọn AliasTest có trong before. Cả hai bản đạt 27 test, 0 failure/error/skipped. Receipt 4063ba008c3644f5ad4d015ccd4cbcc4 lưu cả kết quả fixture cục bộ. Còn rà soát phạm vi nhãn và tiêu chí hoàn tất. |
| CVE-2020-26217 | PASS / PASS | Hai bản build và lớp upstream được chọn đạt; chưa chứng minh FAIL→PASS bằng cùng fixture, giữ UNCONFIRMED. |
| CVE-2021-21345 | PASS / PASS | Hai bản build và lớp upstream được chọn đạt; thiếu fixture chung/caller context, giữ UNCONFIRMED. |
| CVE-2022-25174 | FAIL / FAIL | Timeout ở Jenkins parent/plugin/dependency; cần harness điều kiện credential/controller/agent. |
| CVE-2022-25175 | FAIL / FAIL | Timeout ở Jenkins parent/plugin/dependency; cần fixture tích hợp tương ứng advisory. |

## Phân loại và giới hạn

Giữ target_cwe từ seed; advisory hiện hành được lưu riêng. Phân loại seed không tự động là nhãn vàng. Không có hồ sơ nào trong lượt đối chiếu này thiếu target CWE của seed trong danh sách CWE advisory. Cần người đánh giá phạm vi trước khi dùng làm tập chuẩn CWE-78.

Spark chọn parent thứ nhất của merge có lý do ghi trong selection. one-java-agent giữ mọi fix reference nhưng chỉ trích cặp ở fix đầu tiên; các fix còn lại cần rà soát đa commit. Parser phân biệt anonymous class và lexical occurrence khi chữ ký cú pháp trùng; không coi đây là chữ ký JVM hay ghép ngữ nghĩa hoàn hảo.

UNCONFIRMED không phải safe negative. Đợt mới chưa đủ để kết luận độ chính xác ML. Các snapshot có upstream test PASS chưa chứng minh cơ chế lỗi được tái hiện. Thời gian 90/180 giây là ngân sách của lượt thử, không phải kết luận bất khả build. Cache và dependency version range có thể làm kết quả đổi theo thời điểm; cần khóa dependency để nghiên cứu dài hạn.

## Chạy lại

`python3 run.py expand` tạo intake mới trong run mới, không ghi đè các nhãn đã rà soát. `python3 run.py batch-build data/batch-02 --cve CVE-2022-4244` chạy fixture mới. Các hồ sơ khác dùng cùng batch-build với --cve và timeout phù hợp. Xem INSTALL.md cho export, parser và split chung 409 phiên bản.

Bằng chứng: [build toàn batch](../evidence/v0.2.0/2b54f962ab544cb789aaf746c087715e/run.json), [fixture Expand](../evidence/v0.2.0/20fda5362b864cac988d7560180ebb00/run.json), [build-status.json](../data/batch-02/build-status.json), [quyết định nhãn](../data/batch-02/reviews.jsonl).
