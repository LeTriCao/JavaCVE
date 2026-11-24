# Phương pháp chuẩn hóa và đo cải tiến

Giữ metadata seed của CWE-Bench-Java tại revision IRIS khóa. Với mỗi hồ sơ pilot, đối chiếu advisory → commit sửa → parent được chọn → Git tree → blob tệp → callable → khoảng dòng → SHA256. Tệp thêm/xóa giữ null ở phía vắng; phương thức thêm/xóa chỉ có phiên bản tồn tại. Chữ ký là cú pháp AST, không phải định danh JVM đã phân giải kiểu.

## Các chỉ số và mẫu số

| Chỉ số | Định nghĩa / mẫu số |
|---|---|
| Ánh xạ sửa hiệu chỉnh | Số CVE có danh sách seed fix khác SHA sửa được chọn / 10 pilot; hiện 1/10 |
| Cặp chuẩn hóa | Số cặp mà Git xác nhận before là parent được ghi của after / 10; hiện 10/10 |
| Phạm vi tệp | Đường dẫn .java duy nhất trong diff theo từng CVE, cộng qua các CVE; `--no-renames` |
| Build snapshot | Snapshot tạo được đúng primary JAR / snapshot được thử trong experiment đầu vào |
| Độ phủ build pilot | CVE có cả hai snapshot build / toàn bộ 10 pilot; giữ riêng CVE không đo |
| Tái hiện hành vi | CVE có ít nhất một assertion security FAIL→PASS và controls PASS ở cả hai phía / CVE có đo hành vi |
| Độ phủ hành vi pilot | Cùng tử số trên / toàn bộ 10 pilot |
| Toàn vẹn callable | Số phiên bản hiện diện thực sự đối chiếu từ source / 187; không tính phía vắng thành mẫu |
| Bản sau còn FAIL | Số snapshot after có ít nhất một security assertion FAIL / số after đã đo |
| Thời gian | Wall clock riêng các subprocess fetch/build/classpath/API/security; gắn môi trường/cache/network |
| Can thiệp thủ công | Ghi mô tả thay đổi môi trường/cấu hình; chưa đo đủ thời gian lao động theo CVE |

`measure` lấy cả seed và fix gốc, đếm diff seed→fix và parent→fix. Chỉ so cùng SHA sửa để cô lập ảnh hưởng chọn bản trước. Commons IO đổi SHA sửa nên bị loại khỏi phép đo 9 CVE này và báo riêng. Đã xác nhận 60→33, giảm `(60-33)/60=45%`; không diễn giải thành giảm 45% thời gian.

`report` tính lại số liệu từ bảng và các run được chỉ định, xuất JSON/CSV/Markdown/DOCX. Các snapshot trùng giữa input runs bị từ chối. Bằng chứng lịch sử matched build trên 6 seed có cùng JDK8u514, Maven3.5.0 và mô-đun; cả hai quy trình đạt6/6. Run paired hiện dùng Maven3.9.9, nên không lấy hai tỷ lệ này để suy ra cải thiện do công cụ.

## Chống trùng và rò rỉ

Giữ dự án hoặc CVE làm đơn vị chia; mọi phương thức/phiên bản cùng đơn vị đi cùng partition. Gộp các đơn vị chia sẻ hash token thành một connected component trước khi dùng hash xác định bucket train/validation/test 80/10/10 theo kỳ vọng. Mẫu nhỏ có thể lệch tỷ lệ hoặc trống partition. Với cả pilot và batch02, tính lại token theo cùng thuật toán từ source Git đã khớp SHA256, tránh so hash sinh bằng hai phiên bản extractor khác nhau.

Không có exact token duplicate băng qua các partition được công cụ sinh. Điều này không loại trừ clone gần giống, mã sao chép giữa lịch sử hoặc tương đồng ngữ nghĩa; cần detector bổ sung và đánh giá thủ công trước nghiên cứu ML. Không coi các mẫu UNCONFIRMED là negative. Chưa có mô hình baseline, phép đo tăng accuracy, kappa hay thời gian người gán nhãn.
