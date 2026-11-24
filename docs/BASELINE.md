# Đối chứng trên sáu CVE

**Câu hỏi thực nghiệm.** Trên cùng sáu phiên bản gốc và cùng điều kiện build, bản thí điểm có tăng số dự án đóng gói thành công không? Cả hai bên đều đạt 6/6, chênh lệch quan sát được là 0/6.

1. Cố định IRIS ở `d2059f299a80a68ea4a0b0315eec2f42b8743776`. Đọc commit gốc từ `data/project_info.csv` và cấu hình thành công từ `data/build_info.csv`.
2. Chạy công cụ tải nguồn chính thức trên từng CVE, kiểm tra `HEAD` trùng commit bộ gốc rồi chạy `scripts/build_one.py` bằng JDK 8, Maven 3.5.0. Sáu dự án đều tạo JAR. Lượt cài ban đầu gặp lỗi kết nối proxy khi Maven lấy phụ thuộc. Sau khi sửa địa chỉ proxy ở môi trường chạy, cả sáu build thành công. `original_build_exit` ghi kết quả sau khi sửa.
3. Đo lại có đối chứng. Mỗi nhánh nhận cây nguồn sạch từ cùng commit gốc, cùng JDK 8u514, Maven 3.5.0, kho phụ thuộc ban đầu giống nhau và thư mục build riêng. Cả hai đều chạy từ thư mục gốc của dự án. Nhánh tham chiếu gọi script build nguyên bản. Nhánh thí điểm chạy lệnh đóng gói của dự án rồi kiểm tra API bình thường trên JAR. Kết quả mỗi nhánh chỉ đạt khi có đúng JAR chính ở mô-đun đích. Với Hutool, cả hai đều build toàn dự án rồi lấy JAR của `hutool-core`.
4. Ghi riêng kết quả thường ngày của `all`. Chế độ này dùng Maven 3.9.9 trên 12 snapshot trước–sau. Trong sáu CVE chỉ zip4j có commit gốc trùng commit trước vá đã chọn. Hai mẫu số 6 và 12 phục vụ hai phép đo khác nhau.

`evidence/baseline.json` lưu commit, phạm vi, mã băm JAR và kết quả từng bên. `evidence/comparison-run.json` là kết quả chạy lại qua lệnh công khai `compare`. Các lần build có thể tạo JAR khác băm do dấu thời gian. Phép đo xét khả năng build và nhận đúng JAR. Báo cáo không so sánh tốc độ hoặc độ chính xác mô hình.

## Chạy lại phép so sánh

Chuẩn bị bản sao Git của IRIS ở revision trên, JDK 8u514, Maven 3.5.0 và thư mục Maven cache ban đầu. Hai nhánh đều bắt đầu từ bản sao riêng của cache. Chương trình sử dụng bộ công cụ chính thức của IRIS, cần gói Python `docker==7.1.0` trong môi trường đang dùng. Phép đo dùng builder Maven cục bộ. Các đối số ví dụ dưới đây là đường dẫn đến những thư mục người dùng đã chuẩn bị.

```text
python3 run.py compare --upstream ../iris --jdk ../jdk8 --maven ../apache-maven-3.5.0 --m2 ../m2
```

Nếu đã có các kho dự án trong `data/project-sources` của IRIS, chương trình kiểm tra commit rồi dùng lại. Trường hợp thiếu, nó gọi trình tải của IRIS trong thư mục tạm. Máy dùng proxy doanh nghiệp cần cấu hình kho chứng chỉ tin cậy của JDK cho Maven. Archive Maven 3.5.0 trong thí nghiệm có SHA-256 `beb91419245395bd69a4a6edad5ca3ec1a8b64e41457672dc687c173a495f034`.

## Các lớp bằng chứng

| Nguồn | Nội dung được đo |
|---|---|
| `evidence/build-run.json` | Build từ nguồn và kiểm tra một API thông thường của mỗi JAR bằng v0.1.0 |
| `evidence/wsl.json` | Tóm tắt đã đối chiếu từ archive của sinh viên, gồm kiểm tra hành vi và các test của dự án đã chọn |
| `runs/` | Kết quả mới của người đang sử dụng. Mỗi lần chạy ghi tệp riêng |

Nhật ký môi trường cũ, đường dẫn máy cũ và các dòng lệnh chứa đường dẫn tuyệt đối không tham gia vào số liệu của bản phát hành. Tệp WSL chỉ cung cấp băm JAR được báo cáo. Bằng chứng build mới được tạo từ các JAR biên dịch tại lần chạy v0.1.0.

Bản ghi build phát hành được thu khi lấy 12 cây nguồn qua Git, tự tạo bộ công cụ từ archive đã khóa băm và tải phụ thuộc vào cache của bản mới. Cả 12 lần build và kiểm tra API đều đạt. Đường đọc archive đã kiểm tra SHA-256 từ gói cũ cũng đã chạy thành công cho 12 phiên bản. Khi cài trên máy dùng kho chứng chỉ riêng, có thể đặt `JAVA_CVE_TRUSTSTORE` thành đường dẫn tới kho chứng chỉ được máy tin cậy.
