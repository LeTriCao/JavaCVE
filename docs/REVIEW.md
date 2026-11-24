# Rà soát kỹ thuật trước phát hành

## Đơn vị và phương pháp

Lượt rà soát do trợ lý AI thực hiện. Bảng `data/review.csv` có 20 quyết định ở cấp snapshot, ghi mã CVE, phía trước/sau, commit, nhãn trước đó, quyết định, lý do và phạm vi. Với 10 CVE, đã đối chiếu advisory, commit sửa, quan hệ cha, mã CWE và nhãn. Với 6 thư viện đã chạy thực nghiệm, đã kiểm tra lại 27 vị trí bằng chứng lưu từ lần rà soát trước, cùng kết quả WSL. Bốn trường hợp còn lại được đối chiếu với thay đổi mã ở các dự án Jenkins và NiFi.

Ở cấp phương thức, đã đối chiếu 187 đoạn trích với cả bản lưu bước 3 và đối tượng Git, kiểm tra khoảng dòng, SHA-256, sự liên kết với tệp, commit và cặp nhãn. Việc mã khớp tuyệt đối xác nhận danh tính mẫu. Diễn giải ngữ nghĩa vẫn mang mức tin cậy ghi trong hồ sơ. Tập xuất 150 phiên bản mã nghiệp vụ giống từng byte khi tạo từ hai nguồn.

| CVE | Dự án | Nhãn sau | Căn cứ quyết định |
|---|---|---|---|
| CVE-2017-1000487 | Plexus Utils | RESOLVED_TARGET | Đã đo hành vi đối với giá trị đường dẫn trong ngữ cảnh shell được xét |
| CVE-2018-1002200 | Plexus Archiver | VULNERABLE | Nhánh ZIP đã đo còn một kiểm tra chưa đạt. Dùng cha thứ nhất của merge |
| CVE-2018-1002201 | zt-zip | VULNERABLE | Nhánh giải nén được kiểm tra còn một tiêu chí chưa đạt |
| CVE-2018-1002202 | zip4j | VULNERABLE | Còn một tiêu chí chưa đạt. Cặp commit thuộc lịch sử phục dựng |
| CVE-2018-17297 | Hutool | VULNERABLE | Đã cải thiện hành vi chính và còn một tiêu chí chưa đạt |
| CVE-2019-10392 | Jenkins Git Client | RESOLVED_TARGET | Đối chiếu các điểm gọi trong advisory. Phạm vi mở rộng giữ chưa xác nhận |
| CVE-2020-2261 | Jenkins Perfecto | RESOLVED_TARGET | Đối chiếu thay đổi từ controller sang agent của build |
| CVE-2021-29425 | Commons IO | RESOLVED_TARGET | Hành vi trả về của hàm chuẩn hóa khớp bằng chứng |
| CVE-2022-20617 | Jenkins Docker Commons | UNCONFIRMED | Thấy thay đổi khâu kiểm tra. Chưa đủ bằng chứng kết luận toàn bộ đường sử dụng |
| CVE-2022-33140 | Apache NiFi | RESOLVED_TARGET | Đối chiếu hai mô-đun và phần bị loại bỏ ở provider tùy chọn |

10 snapshot trước đều giữ nhãn VULNERABLE theo hồ sơ CVE. 10 snapshot sau gồm 4 VULNERABLE, 5 RESOLVED_TARGET, 1 UNCONFIRMED. Tổng cộng 20/20 quyết định giữ nhãn. Nhận xét về bốn thư viện ZIP chỉ áp dụng cho snapshot lịch sử và các nhánh đã khảo sát.

## Phần chưa xác nhận

Trong 129 phiên bản phương thức có nhãn UNCONFIRMED, 117 nằm ngoài diện gán nhãn mục tiêu theo quy tắc hiện tại, 8 cần ngữ cảnh bổ sung, 4 thuộc phần mở rộng ngoài phạm vi advisory. Các mẫu này vẫn có định danh và mã băm. Với Jenkins Docker Commons, giữ nhãn chưa xác nhận ở phiên bản sau là một quyết định đã rà soát.

Tác nhân của lượt rà soát là AI. Số người đánh giá độc lập được ghi nhận bằng 0. Tỷ lệ đồng thuận liên đánh giá và hệ số kappa chưa có dữ liệu để tính. Bốn hồ sơ Jenkins/NiFi vẫn chưa được kiểm thử tích hợp toàn hệ thống.

## Bằng chứng WSL được lưu lại

Sáu CVE có 12 lượt build thành công. Trong 34 phép kiểm tra đã ghi nhận, cả 12 đối chứng bình thường đều đạt. Ở 22 phép kiểm tra hành vi bảo mật, 7 đạt và 15 chưa đạt. Cả sáu cặp đều cải thiện hành vi chính giữa hai phiên bản. Bốn thư viện ZIP vẫn còn một kiểm tra chưa đạt ở mỗi bản sau. 131 lượt test được chọn từ hai dự án gốc đều đạt. Các con số này là bằng chứng từ lần chạy WSL đã lưu.

Lần chạy v0.1.0 có phép kiểm tra API bình thường riêng cho mỗi JAR. Việc chạy lại phép kiểm tra API đánh giá khả năng dùng JAR sau build. Khả năng gán nhãn của mô hình máy học chưa được đánh giá trong thí điểm này.
