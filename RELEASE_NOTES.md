# JavaCVE v0.2.0

CLI tái hiện dữ liệu Java từ CWE-Bench-Java/IRIS: tải commit khóa, build, API, kiểm tra bảo mật, kiểm tra phương thức, xuất mẫu và sinh báo cáo.

- Pilot:10 CVE,126 callable,187 phiên bản; xác minh source187/187.
-12/12 snapshot thuộc6 thư viện đã build và chạy fixture bảo mật gốc.6/6 cặp cải thiện hành vi chính;4/6 bản sau vẫn có assertion bảo mật chưa đạt.
- Phép đo Git xác nhận60→33 tệp Java trên9 CVE cùng commit sửa, giảm45% phạm vi tệp. Đối chứng build lịch sử IRIS/JavaCVE đều6/6; không tuyên bố tăng tỷ lệ build hay giảm thời gian lao động.
- Batch02:10 CVE mới,222 phiên bản;1/10 hồ sơ hoàn tất theo tiêu chí build/hành vi/rà soát AI. Còn220 mẫu UNCONFIRMED và các giới hạn môi trường/fixture được ghi rõ.
- Bốn Jenkins/NiFi có profile và nhiều lượt thử thực tế nhưng chưa có kiểm thử tích hợp đầy đủ.0 người đánh giá độc lập.

Asset ZIP chứa công cụ, chỉ mục và bằng chứng đã lọc thông tin máy cá nhân; DOCX là báo cáo môn học được sinh từ kết quả. Không bao gồm cache,credential,JDK,Maven,JAR hoặc toàn bộ source bên thứ ba. Giấy phép MIT chỉ áp dụng phần công cụ mới; xem docs/SOURCES.md.

Demo Ubuntu/WSL: `python3 run.py demo`, `python3 run.py list`, `python3 run.py all --cve CVE-2021-29425`. Xem README và docs/INSTALL.md để xuất mẫu, retry, đo lại và đọc giới hạn của nhãn.
