# BÁO CÁO ĐỒ ÁN MÔN ĐẢM BẢO AN TOÀN THÔNG TIN

JavaCVE v0.2.0 — Cải thiện bộ dữ liệu lỗ hổng mã nguồn Java

Ngày cập nhật: 25/11/2026. Thông tin trường, lớp, sinh viên và giảng viên cần được người thực hiện điền trước khi nộp.

## 1. Mục tiêu và câu hỏi đánh giá

Cải thiện tập con CWE-Bench-Java bằng định danh Git, chuẩn hóa cặp bản vá, nhãn có phạm vi và bằng chứng thực thi. Đánh giá tách bạch tính toàn vẹn mẫu, khả năng build và hành vi bảo mật. Không đánh đồng callable thay đổi với một lỗ hổng độc lập.

## 2. Nguồn và phương pháp

Giữ nguyên revision IRIS và metadata seed; dùng parent đã chỉ định của commit sửa để cô lập thay đổi. Commons IO được hiệu chỉnh khỏi commit chỉ sửa test. Plexus Archiver chọn parent thứ nhất của merge; zip4j dùng lịch sử phục dựng, không coi là SHA gốc của tác giả. Phương thức thêm/xóa chỉ có bản ở phía hiện diện.

## 3. Thiết kế kiểm chứng

Tải commit cố định, xác nhận tree/blob Git, kiểm tra khoảng dòng và SHA256 phương thức. Build source bằng JDK8u514/Maven3.9.9 rồi chạy API và harness bảo mật. Fixture lịch sử giữ nguyên byte. Mỗi lệnh có run ID, thời gian UTC, môi trường, commit công cụ, lệnh, log và exit code. Assertion bảo mật FAIL là quan sát; lỗi harness hoặc đối chứng là lỗi thực nghiệm.

## 4. Kết quả tính lại

Bảng được sinh bằng `python3 run.py report`; số liệu lịch sử và lượt chạy mới được ghi riêng.

| Chỉ tiêu | Kết quả | Phạm vi |
|---|---:|---|
| CVE / phương thức / phiên bản | 10 / 126 / 187 | Pilot |
| Nhãn | {"VULNERABLE": 44, "RESOLVED_TARGET": 14, "UNCONFIRMED": 129} | Phiên bản phương thức |
| Build đối chứng IRIS / pilot | 6/6 / 6/6 | Cùng seed, JDK, Maven, mô-đun; lịch sử |
| Build mới | 12/12 | Snapshot trong các run đầu vào |
| Tái hiện hành vi mới | 6/6 | CVE có đo hành vi; yêu cầu đối chứng đạt |
| Phủ hành vi trên pilot | 6/10 | Toàn bộ pilot |
| Bản sau còn assertion bảo mật FAIL | 4/6 | Bản sau đã đo |
| Toàn vẹn phương thức mới | 187/187 | Phiên bản hiện diện |
| Người đánh giá độc lập | 0 | Lượt rà soát hiện do AI |
| Tệp Java trước → sau chuẩn hóa | 60 → 33 | 9 CVE giữ commit sửa; giảm 45.0% |
| Ánh xạ commit sửa hiệu chỉnh | 1/10 | So SHA gốc với SHA đã chọn |
| Cặp chuẩn hóa | 10/10 | Git xác nhận parent được chọn |
| Tên callable và biên AST | 409/409 | Các run AST được chỉ định; pilot và batch ghi phạm vi riêng trong JSON |

Thời gian từng bước (giây): `{"fetch": 282.364994, "build": 357.836761, "classpath": 272.334937, "api": 5.291458, "security": 9.509059}`.

Giới hạn: thời gian mạng/cache không được kiểm soát giữa hai quy trình; chưa đo lao động theo CVE hoặc độ chính xác mô hình. Không suy ra tiết kiệm thời gian hay tăng độ chính xác từ số tệp giảm. RESOLVED_TARGET chỉ áp dụng cho cơ chế và điều kiện trong hồ sơ. UNCONFIRMED cần thêm ngữ cảnh và người đánh giá độc lập.

Nguồn: CWE-Bench-Java trong [IRIS tại revision khóa](https://github.com/iris-sast/iris/tree/d2059f299a80a68ea4a0b0315eec2f42b8743776).


## 5. Đợt mở rộng

Đã chọn 10 CVE mới; 10 hồ sơ có nguồn/advisory và trích xuất chuẩn hóa, gồm 222 phiên bản phương thức. Bản chụp intake giữ 222 nhãn UNCONFIRMED. Kết quả build, fixture bổ sung và quyết định nhãn sau intake được ghi riêng trong docs/BATCH02.md và evidence/v0.2.0. Chỉ đưa vào số hoàn thành đầy đủ khi có nhãn có phạm vi, build và bằng chứng hành vi trước–sau. Không cộng vào mẫu số pilot.

| Chỉ số batch02 sau rà soát | Số lượng |
|---|---:|
| Chọn / chuẩn hóa nguồn / hoàn tất | 10 / 10 / 2 |
| Nhãn sau rà soát | {"UNCONFIRMED": 213, "VULNERABLE": 5, "RESOLVED_TARGET": 4} |
| Người đánh giá độc lập | 0 |
| Hồ sơ build được cả hai bản | 8/10 |
| Snapshot build được từ source | 16/20 |
| Quyết định AI cấp callable / snapshot ghi riêng | 153 / 8 |

Plexus Archiver đã build thành công ở cả hai commit. Mỗi bản bỏ qua một test upstream. XStream 2013 dừng ở bước tra cứu converter trong fromXML trước khi caller nhận được proxy ở cả hai bản. Đối chứng chức năng bổ sung không thay thế quan sát hành vi thuộc từng advisory của XStream 2020/2021. [Bảng ưu tiên Batch02](../BATCH02.md) · [Chẩn đoán XStream](../XSTREAM_DIAGNOSIS.md).

### Nghiệm thu chung C1–C7

Cùng tiêu chí cho cả 20 CVE: 8/20 đạt, 14/20 có cặp build. Mục tiêu 12/20 vẫn là đề xuất, chờ giảng viên xác nhận. Kiểm thử chức năng không chứng minh hành vi CVE. [Bảng nghiệm thu](../DOI_CHIEU_DU_LIEU.md) · [Biên bản máy đọc](../../data/acceptance-review.json).

### Đối chứng IRIS → JavaCVE từ Git

Giữ cùng fix: 9 Pilot đạt 60→33 đường dẫn (45.0%). Mở rộng 10 CVE đạt 62→35 (43.548387%). Giữ 25/25 anchor Java của IRIS fix_info; GitClientSecurityTest cùng SECURITY-1534 bị ra khỏi changed-set được lưu thành context reference. Không coi toàn bộ đường dẫn loại là nhiễu và không suy ra accuracy hay giảm thời gian. [Bảng 20 CVE và hai ca đọc diff](../SO_SANH_IRIS_JAVACVE.md).

## 6. Chất lượng và giới hạn

Rà soát kỹ thuật do AI thực hiện; số người đánh giá độc lập bằng 0. Các nhãn UNCONFIRMED của pilot giữ lý do ngoài phạm vi, cần caller/context hoặc phần mở rộng ngoài advisory. Toàn vẹn byte không xác nhận tính đúng ngữ nghĩa. Bốn bản sau thư viện ZIP có kiểm tra giới hạn thư mục chưa đạt trong phép đo lịch sử. Jenkins/NiFi cần kiểm thử tích hợp; tham khảo docs/EXPERIMENTS.md.

## 7. Hướng phát triển luận văn

Bổ sung người đánh giá độc lập và đo đồng thuận; hoàn thiện fixture cho batch mới; chia theo dự án hoặc CVE, gộp các nhóm trùng token trước khi chia. Cần kiểm tra clone gần giống và đo tác động của chất lượng nhãn lên một mô hình baseline. Chỉ kết luận cải thiện độ chính xác sau thí nghiệm có tập giữ lại độc lập; chỉ kết luận giảm lao động sau phép đo thời gian người thực hiện phù hợp.

## 8. Tái hiện và bàn giao

Các lệnh công khai: demo, list, fetch, build, security, all, audit, export, measure, report, split, investigate, expand và batch-build. README.md và docs/INSTALL.md hướng dẫn từ bản clone/giải nén mới. LICENSE chỉ cấp phép công cụ mới; mã bên thứ ba giữ giấy phép riêng. Không đóng gói cache, credential, JDK, Maven hoặc source Java chưa rà soát quyền tái phân phối.
