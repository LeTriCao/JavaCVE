# Batch02

**8/10 hồ sơ build được cả hai snapshot** (16/20 snapshot). **2/10 hồ sơ hoàn tất thực nghiệm** theo tiêu chí hiện hành. Đã chuẩn hóa 10 hồ sơ, gồm 222 phiên bản callable.

Nhãn theo dữ liệu hiện tại gồm 213 UNCONFIRMED, 5 VULNERABLE, 4 RESOLVED_TARGET. Người rà soát là **AI**. Có 0 người đánh giá độc lập.

## Ưu tiên các hồ sơ còn lại

Ưu tiên 1 dành cho hồ sơ vừa có bằng chứng mới, 2 cho hồ sơ đã build còn thiếu đối chứng, 3 cho trở ngại cấu hình hoặc thời gian build, 4 cho dependency lịch sử chưa xác minh được. Nhấn vào trạng thái trước hoặc sau để đọc log package đúng commit.

| CVE | Ưu tiên | Build trước / sau | Kết quả đọc log | Công việc còn thiếu |
|---|---:|---|---|---|
| CVE-2013-7285 | 1 | [PASS](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/logs/12-build.log) / [PASS](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/logs/17-build.log) | Hai bản build được và đạt 27 AliasTest mỗi bản. Lượt chẩn đoán dừng trong fromXML khi tìm converter ở cả hai bản. | Chưa quan sát được hành vi của caller ở cả hai snapshot. Hai snapshot và 68 phiên bản callable giữ UNCONFIRMED. |
| CVE-2023-37460 | 1 | [PASS](../evidence/v0.2.0/9c2a5b8236d34dfbbd96d36ec9df0eb1/logs/2-build.log) / [PASS](../evidence/v0.2.0/9c2a5b8236d34dfbbd96d36ec9df0eb1/logs/4-build.log) | Cả hai lượt cũ hết hạn. Lượt mới package thành công và chạy hai lớp test upstream ở mỗi bản. | Đối chiếu phạm vi các test upstream với advisory và từng callable. Còn thiếu đối chứng và quan sát hành vi chung. |
| CVE-2020-26217 | 2 | [PASS](../evidence/v0.2.0/2b54f962ab544cb789aaf746c087715e/logs/16-build.log) / [PASS](../evidence/v0.2.0/2b54f962ab544cb789aaf746c087715e/logs/18-build.log) | Build đạt. Lớp test upstream có 7 test trước và 9 test sau. | Thiếu đối chứng và bằng chứng hành vi theo advisory dưới cùng điều kiện gọi. |
| CVE-2021-21345 | 2 | [PASS](../evidence/v0.2.0/2b54f962ab544cb789aaf746c087715e/logs/20-build.log) / [PASS](../evidence/v0.2.0/2b54f962ab544cb789aaf746c087715e/logs/22-build.log) | Build đạt. Lớp test upstream có 11 test trước và 13 test sau trong bản vá liên quan nhiều CVE. | Thiếu đối chứng chung và bằng chứng phân biệt hành vi của riêng advisory này. |
| CVE-2018-1000850 | 2 | [PASS](../evidence/v0.2.0/188f8a96a7e1421a97ca9a438faafeef/logs/2-build.log) / [PASS](../evidence/v0.2.0/188f8a96a7e1421a97ca9a438faafeef/logs/3-build.log) | Paired source package PASS with recorded temporary Kotlin plugin pin 1.2.60; JDK8u514/Maven3.9.9. | Build PASS/PASS với overlay POM tạm khóa Kotlin plugin 1.2.60 theo POM gốc; thiếu rà soát callable, đối chứng và hành vi mục tiêu. Mã Java và nhãn UNCONFIRMED giữ nguyên. |
| CVE-2022-25174 | 2 | [PASS](../evidence/v0.2.0/d6afe2302eb94c8e8ee75fe92844ec72/logs/2-build.log) / [PASS](../evidence/v0.2.0/d6afe2302eb94c8e8ee75fe92844ec72/logs/3-build.log) | Source package PASS/PASS; JDK8u514/Maven3.9.9; explicit POM overlay disables only HPI 3.22 test harness dependency staging; official repository transport recorded. | Build PASS/PASS trong profile package bỏ test harness dependency staging của HPI 3.22; overlay POM và vận chuyển dependency được ghi rõ. Thiếu rà soát callable và đối chứng/hành vi tích hợp Jenkins; giữ UNCONFIRMED. |
| CVE-2022-25175 | 3 | [TIMEOUT](../evidence/v0.2.0/2b54f962ab544cb789aaf746c087715e/logs/26-build.log) / [TIMEOUT](../evidence/v0.2.0/2b54f962ab544cb789aaf746c087715e/logs/27-build.log) | Hết 90 giây khi Maven xác minh lại cache theo repository ID. Mục cuối là jsch:0.1.55.2 trước và jenkins-stapler-support:1.1 sau. | Xác minh repository ID và thời gian phân giải dependency trên cả hai bản. |
| CVE-2022-25842 | 4 | [DEPENDENCY](../evidence/v0.2.0/2b54f962ab544cb789aaf746c087715e/logs/7-build.log) / [DEPENDENCY](../evidence/v0.2.0/2b54f962ab544cb789aaf746c087715e/logs/8-build.log) | Maven báo thiếu bytekit-instrument-api và bytekit-core 0.0.8-SNAPSHOT ở cả hai bản trong các kho đã hỏi. | Cần artifact hoặc revision lịch sử có thể kiểm tra nguồn gốc cho cả hai dependency. |
| CVE-2016-9177 | Đã hoàn tất | [PASS](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/logs/2-build.log) / [PASS](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/logs/7-build.log) | Hai bản build đạt. Đã xác nhận thay đổi trên đường gọi external static files được đo. | Hoàn tất theo phạm vi external. Các đường gọi classpath và JAR còn UNCONFIRMED. |
| CVE-2022-4244 | Đã hoàn tất | [PASS](../evidence/v0.2.0/20fda5362b864cac988d7560180ebb00/logs/2-build.log) / [PASS](../evidence/v0.2.0/20fda5362b864cac988d7560180ebb00/logs/6-build.log) | Hai bản build đạt. Kiểm tra parent traversal chuyển từ FAIL sang PASS. Trường hợp sibling-prefix vẫn FAIL cả hai bản. | Hoàn tất trong phạm vi các trường hợp đã đo. |

Mỗi bản Plexus Archiver bỏ qua một test upstream. Bảng can thiệp ghi số test thực chạy, số bỏ qua, thời gian, cấu hình Maven và SHA của hai JAR. [Lượt khôi phục Plexus](BUILD_RECOVERY.md#plexus-archiver-cve-2023-37460) · [Chẩn đoán XStream](XSTREAM_DIAGNOSIS.md).

## Phân loại và giới hạn

Giữ target_cwe từ seed; advisory hiện hành được lưu riêng. Phân loại seed không tự động là nhãn vàng. Không có hồ sơ nào trong lượt đối chiếu này thiếu target CWE của seed trong danh sách CWE advisory. Cần người đánh giá phạm vi trước khi dùng làm tập chuẩn CWE-78.

Spark chọn parent thứ nhất của merge có lý do ghi trong selection. one-java-agent giữ mọi fix reference nhưng chỉ trích cặp ở fix đầu tiên; các fix còn lại cần rà soát đa commit. Parser phân biệt anonymous class và lexical occurrence khi chữ ký cú pháp trùng; không coi đây là chữ ký JVM hay ghép ngữ nghĩa hoàn hảo.

UNCONFIRMED không phải safe negative. Đợt mới chưa đủ để kết luận độ chính xác ML. Các snapshot có upstream test PASS chưa chứng minh cơ chế lỗi được tái hiện. Thời gian 90/180 giây là ngân sách của lượt thử, không phải kết luận bất khả build. Cache và dependency version range có thể làm kết quả đổi theo thời điểm; cần khóa dependency để nghiên cứu dài hạn.

## Chạy lại

`python3 run.py expand` tạo intake mới trong run mới, không ghi đè các nhãn đã rà soát. `python3 run.py batch-build data/batch-02 --cve CVE-2022-4244` chạy fixture mới. Các hồ sơ khác dùng cùng batch-build với --cve và timeout phù hợp. Xem INSTALL.md cho export, parser và split chung 409 phiên bản.

Bằng chứng: [build toàn batch](../evidence/v0.2.0/2b54f962ab544cb789aaf746c087715e/run.json), [fixture Expand](../evidence/v0.2.0/20fda5362b864cac988d7560180ebb00/run.json), [build-status.json](../data/batch-02/build-status.json), [quyết định nhãn](../data/batch-02/reviews.jsonl).

Bảng đối chiếu từng tiêu chí: [BATCH02_REVIEW.md](BATCH02_REVIEW.md). Quyết định từng callable: [BATCH02_CALLABLE_REVIEW.md](BATCH02_CALLABLE_REVIEW.md). `summary.json` là bản chụp intake; `completion.json` ghi trạng thái hiện tại.

Đã có 153 quyết định AI ở cấp callable và 8 quyết định snapshot ghi riêng. Số quyết định rà soát không phải số nhãn xác nhận. Chẩn đoán XStream: [XSTREAM_DIAGNOSIS.md](XSTREAM_DIAGNOSIS.md).

## Lượt khôi phục build và kiểm thử thông thường (25/11/2026)

Bảng ưu tiên có thể còn mô tả lượt thử lịch sử; kết quả nghiệm thu chung mới nhất và kiểm thử chức năng cho bốn hồ sơ đã build nằm tại [RECOVERY_20261125.md](RECOVERY_20261125.md). Không sửa `summary.json` intake hoặc quyết định nhãn cũ. `UNCONFIRMED` không phải mẫu âm an toàn.
