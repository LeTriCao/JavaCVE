# Báo cáo đồ án môn Đảm bảo an toàn thông tin

**JavaCVE — Chuẩn hóa dữ liệu và kiểm chứng lỗ hổng mã nguồn Java**

Ngày chuẩn bị bộ nộp 25/11/2026.

Trường: [CẦN ĐIỀN] · Lớp: [CẦN ĐIỀN]
Sinh viên / MSSV: [CẦN ĐIỀN] · Giảng viên: [CẦN ĐIỀN]

Trên 10 CVE có cùng commit sửa, chọn parent của bản sửa làm mốc trước đã thu hẹp tập đường dẫn Java trong diff từ 62 xuống 35 (giảm 43,55%) và giữ đủ 25/25 tệp Java được IRIS chú thích. Với CVE-2019-10392, tệp GitClientSecurityTest.java rời khỏi diff nhưng vẫn tồn tại ở cả hai snapshot. Tra mã CVE trong data/context-files.jsonl để lấy đường dẫn, commit và mã băm.

Bản bàn giao cuối dùng commit nền a1ea91f12cb78d2828e97c055ff6c18481107759. Để dùng ZIP bổ sung, giải nén vào một bản sao sạch của commit nền, cho phép ghi đè. Checkout trực tiếp commit bàn giao trên GitHub có đủ cây tệp. Bốn lệnh demo nằm trong docs/DEMO_5_PHUT.md.

## 1. Mục tiêu và phạm vi

Yêu cầu đồ án là chọn bộ dữ liệu lỗ hổng Java có sẵn và cải thiện nó. JavaCVE chọn CWE-Bench-Java của IRIS làm nguồn; các đóng góp được đối chứng riêng thay vì coi tăng quy mô là tăng độ chính xác. JavaCVE liên kết CVE → advisory → repository → cặp commit trước/sau → tệp → phương thức → nhãn có phạm vi → receipt/log. Nguồn chọn mẫu là CWE-Bench-Java của IRIS, revision `d2059f299a80a68ea4a0b0315eec2f42b8743776`. Tập gồm 20 CVE, 309 phương thức/hàm khởi tạo và 409 phiên bản hiện diện, gồm cả test. Phạm vi phân phối là chỉ mục, bằng chứng và công cụ; không kèm Git cache, JAR hay toàn bộ source bên thứ ba.

## 2. Phương pháp và chuẩn C1–C7

Áp cùng bảy điều kiện cho Pilot và Batch02: C1 định danh nguồn/cặp commit; C2 blob/khoảng dòng/SHA-256/AST; C3 advisory/bản vá/caller/phạm vi; C4 rà soát callable có phạm vi; C5 build cả hai bản từ nguồn theo cấu hình ghi lại; C6 đối chứng thông thường chung; C7 hành vi mục tiêu ghép cặp đúng phạm vi. Một hồ sơ đạt khi đủ cả bảy. Bản vá một phần có thể đạt mức hồ sơ nếu ghi đầy đủ lỗi còn lại và giữ nhãn phản ánh lỗi đó; không đồng nghĩa an toàn tổng quát.

## 3. Kết quả hiện tại

| Chỉ tiêu | Pilot | Batch02 | Tổng |
|---|---:|---:|---:|
| CVE | 10 | 10 | 20 |
| Phiên bản phương thức | 187 | 222 | 409 |
| CVE có cặp build | 6 | 8 | 14/20 |
| CVE đạt C1–C7 | 6 | 2 | 8/20 |
| VULNERABLE | 44 | 5 | 49 |
| RESOLVED_TARGET | 14 | 4 | 18 |
| UNCONFIRMED | 129 | 213 | 342 |

Lượt khôi phục bổ sung hai cặp build: Retrofit CVE-2018-1000850 khóa Kotlin plugin 1.2.60 theo property của POM gốc; Jenkins CVE-2022-25174 dùng profile package bỏ riêng HPI 3.22 test harness dependency staging. Cả hai dùng Temurin 8u514/Maven 3.9.9. Overlay chỉ ở bản build tạm, có diff/băm; mã Java của commit gốc và nhãn không đổi. Đây không phải bằng chứng Jenkins integration test.

Ba XStream đạt 18 đối chứng String/chuỗi rỗng/Integer trên sáu JAR source-build đã xác minh SHA-256; Plexus Archiver đạt lại đối chứng ZIP thường ở cả hai bản. Những kiểm tra này hỗ trợ C6, không thay C7. Kết quả thực nghiệm bảo mật được đọc từ bằng chứng đã lưu; không chạy fixture CVE mới khi chuẩn bị gói nộp.

## 4. Sáu hồ sơ chưa có cặp build

| CVE | Dự án | Cổng còn thiếu | Phần cần tiếp tục |
|---|---|---|---|
| CVE-2019-10392 | Jenkins Git Client Plugin | C5, C6, C7 | Thiếu build do phụ thuộc/timeout; thiếu đối chứng và hành vi tích hợp Jenkins/caller. |
| CVE-2020-2261 | Jenkins Perfecto Plugin | C5, C6, C7 | Thiếu build do phụ thuộc/timeout; thiếu đối chứng và hành vi controller/agent Jenkins. |
| CVE-2022-20617 | Jenkins Docker Commons Plugin | C5, C6, C7 | Thiếu build, fixture/control và đường gọi DockerRegistryEndpoint; giữ nhãn sau UNCONFIRMED. |
| CVE-2022-25175 | jenkinsci/workflow-multibranch-plugin | C4, C5, C6, C7 | Maven dependency resolution TIMEOUT; thiếu build, fixture/control Jenkins và rà soát callable. |
| CVE-2022-25842 | alibaba/one-java-agent | C4, C5, C6, C7 | Thiếu phụ thuộc bytekit SNAPSHOT có provenance xác minh được; thiếu build, fixture/control và rà soát callable. |
| CVE-2022-33140 | Apache NiFi và NiFi Registry | C5, C6, C7 | Thiếu cặp build và tích hợp cả NiFi/Registry, mock OS command/provider và đối chứng. |

## 5. Sáu hồ sơ đã build nhưng chưa đạt C1–C7

| CVE | Dự án | Cổng còn thiếu | Phần cần tiếp tục |
|---|---|---|---|
| CVE-2013-7285 | x-stream/xstream | C7 | Thiếu hành vi caller: cả hai dừng ở converter lookup trước khi trả proxy; legacy assertion PASS/PASS không chứng minh sửa lỗi. |
| CVE-2018-1000850 | square/retrofit | C4, C6, C7 | Build PASS/PASS với overlay POM tạm khóa Kotlin plugin 1.2.60 theo POM gốc; thiếu rà soát callable, đối chứng và hành vi mục tiêu. Mã Java và nhãn UNCONFIRMED giữ nguyên. |
| CVE-2020-26217 | x-stream/xstream | C7 | Thiếu fixture hành vi đúng advisory/caller/policy; API round-trip thông thường và upstream 7→9 test không thay thế C7. |
| CVE-2021-21345 | x-stream/xstream | C7 | Thiếu fixture hành vi cho chuỗi advisory/caller/policy; API round-trip và upstream 11→13 test không chứng minh cơ chế CVE riêng. |
| CVE-2022-25174 | jenkinsci/workflow-cps-global-lib-plugin | C4, C6, C7 | Build PASS/PASS trong profile package bỏ test harness dependency staging của HPI 3.22; overlay POM và vận chuyển dependency được ghi rõ. Thiếu rà soát callable và đối chứng/hành vi tích hợp Jenkins; giữ UNCONFIRMED. |
| CVE-2023-37460 | codehaus-plexus/plexus-archiver | C4, C7 | Thiếu hành vi symlink theo advisory và rà soát callable; đối chứng ZIP cục bộ chưa công bố không đủ để hoàn tất. |

## 6. Phần cải thiện IRIS → JavaCVE được kiểm chứng

| Phép đo cùng commit sửa | CVE đủ bằng chứng | IRIS seed→fix | JavaCVE parent→fix | Kết quả |
|---|---:|---:|---:|---|
| Pilot giữ mẫu số cũ | 9 | 60 đường dẫn Java | 33 | Giảm 27, tức 45%; 23/23 anchor file Java IRIS fix_info vẫn giữ |
| Mở rộng thêm CVE-2022-25175 | 10 | 62 | 35 | Giảm 27, tức 43,55% làm tròn; 25/25 anchor vẫn giữ |

IRIS fix_info.csv vốn có ánh xạ file/phương thức được chú thích. 60 path là phép đo Git theo seed, không phải 60 file gán nhãn IRIS. Tập 33 path gồm 23 anchor cộng 10 ứng viên bổ sung; không thể suy ra nhãn JavaCVE chính xác hơn từ phép đo này.

Đếm đường dẫn Java khác biệt, gồm production/test/resource, mỗi path một lần trong mỗi CVE, không nhận diện rename; tổng là CVE-path. Snapshot IRIS và fix reference được đối chiếu lại với CSV gốc tại revision khóa. Mọi dòng có ba SHA và lý do loại trong [bảng 20 CVE](SO_SANH_IRIS_JAVACVE.md); JSON và CSV cho phép tính lại từ Git, không dùng số cộng sẵn trong báo cáo.

Đọc diff ca Plexus Archiver CVE-2018-1002200 xác nhận 14→2: giữ tệp guard AbstractUnArchiver và test ZipUnArchiverTest; 12 đường dẫn khác thay đổi giữa seed và parent nhưng không đổi trong fix, gồm modular JAR, đóng stream/classloader, mã hóa symlink và hỗ trợ test. Không khẳng định chúng vô ích với mọi câu hỏi bảo mật.

Ca bất lợi Git Client CVE-2019-10392 có 2→1 nhưng GitClientSecurityTest bị ra khỏi changed-set vẫn chứa regression test SECURITY-1534, cùng issue với fix. File tồn tại và có cùng blob ở parent/fix; bổ sung context-files.jsonl để giữ URL/commit/hash làm ngữ cảnh. Context không thêm vào 409 mẫu và không tự nhận nhãn. Vì vậy 45% là thu hẹp phạm vi diff, không phải “loại đúng 45% nhiễu”, tiết kiệm 45% thời gian hay tăng accuracy.

Đã xem xét đủ 20 CVE: mười đủ điều kiện; Commons IO đổi cả fix nên loại khỏi phép đo biến before; one-java-agent có nhiều fix cần đánh giá chuỗi; tám ca thiếu seed Git object trong cache đã kiểm tra. Không fetch bổ sung hoặc suy ra chúng không thể so sánh. Bốn Pilot và ca mở rộng không giảm số path; không có ca tăng trong mẫu thực đo. Hai ca đọc diff chi tiết không thay việc rà ngữ nghĩa toàn bộ 27 path bị loại.

Các phần cải thiện khác có dấu vết riêng: hiệu chỉnh ánh xạ fix Commons IO, khóa cặp commit/parent và nguồn phương thức, kiểm tra blob/dòng/SHA-256/AST, công bố trạng thái build và nhãn có phạm vi, giữ mẫu UNCONFIRMED thay vì mặc định negative, bổ sung tham chiếu ngữ cảnh bảo mật. Đối chứng build cùng sáu seed vẫn IRIS 6/6 và JavaCVE 6/6; không tuyên bố tăng tỷ lệ build so với IRIS. Batch02 3→8 cặp build là tiến trình riêng của JavaCVE. Chưa đo accuracy mô hình, thời gian người gán nhãn hay precision/recall của phép lọc path.

## 7. Rà soát nhãn độc lập

Giữ nguyên 40 sample_id đã chọn, phủ đủ 20 CVE. Bản dành cho người rà ở docs/review chỉ có định danh, tham chiếu source/advisory/log, ô quyết định và lý do trống. Nhãn AI, unknown_reason và bảng đối chiếu được tách sang docs/review_coordinator, không gửi cùng ZIP người rà. Người rà không được xem nhãn hiện tại trước khi quyết định. Mẫu chọn có chủ đích, không phải mẫu ngẫu nhiên đại diện 409 phiên bản.

Đã kiểm tra các phiếu hiện có: chưa có dòng độc lập hợp lệ đã hoàn tất. Trạng thái PENDING, 0/40 mẫu hợp lệ, không tính tỷ lệ trùng quyết định hoặc bất đồng khi chưa có dữ liệu. data/independent-review-summary.json ghi đường dẫn/băm các phiếu đã kiểm. Công cụ review_labels chỉ tổng hợp, không tự áp nhãn: yêu cầu định danh và source khớp, người rà, ngày ISO, quyết định hợp lệ, lý do, bằng chứng và trạng thái COMPLETED; loại trùng/xung đột. Khi có phiếu thật, báo cáo tỷ lệ trùng với baseline AI, không gọi đó là accuracy hoặc human gold set.

## 8. Kiểm tra bộ nộp và lựa chọn tệp

Bộ tệp được chốt trong [SUBMISSION_FILES.json](SUBMISSION_FILES.json). Workflow và công cụ GitHub dùng đúng bản HEAD, loại phần Plexus CI đang sửa dở khỏi bộ nộp; cây làm việc gốc không bị sửa. Những kết quả CI lịch sử không được dùng thay cho kiểm tra bộ nộp này.

Manifest được tạo lại chỉ trong bộ tệp cách ly. Trước khi đóng gói phải đạt toàn bộ unit test hiện tại, đối chiếu nguồn và AST 409/409 phiên bản, tái tính C1–C7 giống từng trường dữ liệu đã lưu, demo và kiểm tra phiếu chờ. Kết quả thực chạy, log và điều kiện môi trường nằm ở `verification/VERIFICATION.json` trong gói ngoài thư mục JavaCVE. Kiểm tra nguồn/AST dùng Git cache đã có và parser ngoài bộ nộp theo chế độ chỉ đọc, không cần mạng. Cache, JDK/Maven và wheel không được đóng gói.

## 9. Việc còn chờ

**Mục tiêu 12/20 đạt C1–C7 vẫn là đề xuất, chờ giảng viên xác nhận.** Cần người rà độc lập điền phiếu và đối chiếu bất đồng; hoàn thiện sáu hồ sơ thiếu build và bằng chứng của sáu hồ sơ đã build; điền thông tin trường/lớp/sinh viên/giảng viên.

Nguồn và bằng chứng: [bảng nghiệm thu 20 CVE](DOI_CHIEU_DU_LIEU.md), [phương pháp](METHODOLOGY.md), [nhãn](LABELS.md), [nguồn/giấy phép](SOURCES.md), [lượt khôi phục](RECOVERY_20261125.md), `data/acceptance-review.json` và `data/batch-02/build-status.json`.

## 10. Demo 5 phút và khả năng tái kiểm tra

Kịch bản DEMO_5_PHUT.md dùng lệnh thật: run.py demo; tools.course_demo để lần theo advisory→commit→phương thức→quan sát đã lưu của CVE-2018-1002200; tools.compare_iris để đo lại từ Git; tools.acceptance để tái tính 14 cặp build/8 C1–C7/342 UNCONFIRMED. Không build hoặc chạy payload CVE trong demo. Có phần nói về test ngữ cảnh bị loại và phiếu người rà còn PENDING.

Các lệnh được diễn tập tự động từ bản ZIP giải nén mới trên chính máy hiện tại, Ubuntu WSL/Python 3.14.4. Không tuyên bố đã chạy trên máy khác hoặc đã có buổi thuyết trình người thật đúng 5 phút. Demo đọc receipt không cần JDK/Maven; đo lại diff cần Git cache có seed/parent/fix; source/AST cần cache và parser Tree-sitter 0.25.2/Java grammar 0.23.5 bên ngoài gói. Mọi lần chạy và thời gian thực tế nằm trong verification; 5 phút là mục tiêu phân bổ lời trình bày.

Gói v2 có manifest mới trên bộ tệp đã chọn, được kiểm tra trước đóng gói và sau giải nén; gói cũ giữ nguyên để đối chiếu. Cây làm việc vẫn còn workflow/công cụ GitHub sửa dở ngoài phạm vi; bản ZIP dùng phiên bản HEAD phù hợp.
