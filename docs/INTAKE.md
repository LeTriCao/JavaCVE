# Tiếp nhận dự án ngày 24/11/2026

Đã đọc mã v0.1.0, bảy bảng dữ liệu, công cụ trong `tools/`, bốn tài liệu phương pháp và các bằng chứng trong `evidence/`. Đã đọc báo cáo tổng hợp và nghiệm thu DOCX tại máy người dùng, gói `results.zip`, mã fixture và scripts của JavaCVE_Reproducible, metadata nguồn của Bước 1 và chú thích Bước 2. Nội dung các gói được coi là dữ liệu tham khảo; yêu cầu thực hiện là yêu cầu trực tiếp của người dùng.

Commit `55096aa` lưu nguyên đầu vào v0.1.0. Manifest cũ giữ riêng tại `evidence/v0.1.0-checksums.json`; các tệp bằng chứng lịch sử khác không sửa. `runs/` dành cho các lượt mới và không đưa log máy cá nhân vào Git mặc định.

| Hạng mục | Trạng thái lúc tiếp nhận | Bằng chứng hoặc phần thiếu |
|---|---|---|
| Liên kết chỉ mục | Hoạt động | `demo` mới xác nhận 10 CVE, 35 tệp, 126 callable, 187 phiên bản |
| Build/API | Có bằng chứng lịch sử 12/12 | `all` cũ chỉ chạy API; cần chạy lại bảo mật |
| Kiểm tra bảo mật | Có fixture trong gói B3 | Chưa tích hợp vào CLI v0.1.0 |
| WSL | `results.zip` khớp hoàn toàn | SHA256 `2d4d68211ca49af6f1c0168a7f41b0030933d511b77aec3bfe52949fbd1f124e` |
| Nguồn phương thức | Chỉ mục có hash; bằng chứng xác minh cũ | Cần tải Git và đối chiếu lại 187 đoạn |
| Chạy lại lỗi | Thiếu | Lỗi build chỉ lưu loại exception, thiếu exit code/log/timing từng bước |
| Jenkins/NiFi | Chỉ rà soát tĩnh hoặc từng phần | Thiếu build profile và fixture tích hợp |
| So sánh 60 → 33 | Chưa có công cụ trong gói v0.1.0 | Cần tính lại diff Git trên 9 CVE giữ SHA sửa |
| Mở rộng dữ liệu | Chưa thực hiện | Cần batch riêng, giữ nguyên mẫu số pilot |
| Đánh giá nhãn | 20 snapshot do AI rà soát | 0 người đánh giá độc lập; không tính kappa |
| GitHub | Chưa có Git repo trong thư mục | Đã tạo repo private LeTriCao/JavaCVE và push commit gốc |

Python Windows mặc định bị thiếu `encodings`; không dùng để suy luận lỗi mã dự án. Ubuntu WSL có Python 3.14.4, JDK/Maven đã khóa có trong cache. Việc truy cập WSL và Windows Credential Manager cần quyền chạy ngoài sandbox của phiên trợ lý; đây là điều kiện môi trường thực hiện, không phải yêu cầu quyền của ứng dụng JavaCVE.
