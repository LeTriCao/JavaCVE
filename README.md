# JavaCVE — bộ dữ liệu lỗ hổng Java ở cấp phương thức

JavaCVE chuẩn hóa 20 hồ sơ lỗ hổng Java từ CWE-Bench-Java của IRIS. Mỗi hồ sơ liên kết mã CVE với commit trước và sau bản sửa, tệp Java, phương thức hoặc hàm khởi tạo và bằng chứng kiểm chứng. Revision nguồn IRIS là `d2059f299a80a68ea4a0b0315eec2f42b8743776`.

Trên 10 CVE giữ nguyên commit sửa, JavaCVE dùng commit cha của bản sửa làm mốc trước thay cho commit do IRIS chọn. Số đường dẫn Java xuất hiện trong diff **giảm từ 62 xuống 35 (43,55%)**, vẫn giữ đủ **25/25 tệp Java được IRIS chú thích**. Phép đo thể hiện phạm vi tệp cần rà soát, tính mỗi đường dẫn một lần cho từng CVE. Bảng so sánh trình bày riêng kết quả của 9 CVE Pilot và cách truy lại `GitClientSecurityTest.java`, tệp kiểm thử vẫn liên quan dù đã rời khỏi diff. [Bảng so sánh IRIS → JavaCVE](docs/SO_SANH_IRIS_JAVACVE.md) · [Số liệu CSV](docs/generated/iris-comparison.csv)

## Mức kiểm chứng

| Chỉ tiêu | Kết quả |
|---|---:|
| Phiên bản phương thức hoặc hàm khởi tạo khớp mã nguồn và cây cú pháp trừu tượng (AST) | 409/409 |
| CVE build thành công từ nguồn ở cả hai commit | 14/20 |
| CVE đạt đủ bảy tiêu chí nghiệm thu C1–C7 | 8/20 |
| Phiên bản còn thiếu bằng chứng để kết luận nhãn (`UNCONFIRMED`) | 342/409 |

[Bảng nghiệm thu 20 CVE](docs/DOI_CHIEU_DU_LIEU.md) · [Phương pháp và tiêu chí C1–C7](docs/METHODOLOGY.md) · [Báo cáo Markdown](docs/BAO_CAO_MON_HOC.md) · [Báo cáo Word](docs/BAO_CAO_MON_HOC.docx)

## Sử dụng

Chạy từ thư mục gốc, chọn đường dẫn đầu ra mới cho mỗi lần chạy.

```sh
python3 -m tools.compare_iris --out runs/iris-new
python3 -m tools.course_demo --out runs/course-demo-new
python3 -m tools.acceptance --out runs/common-new.json
```

Lệnh đầu cần Git cache chứa commit do IRIS chọn, commit cha và commit sửa. Hai lệnh sau đọc bằng chứng đã lưu và có thể chạy không cần JDK hay Maven. Kịch bản demo hướng dẫn cách khai báo đường dẫn cache. [Demo 5 phút](docs/DEMO_5_PHUT.md) · [Nguồn và giấy phép](docs/SOURCES.md)

Để kiểm tra bản bàn giao đã có manifest, chạy `python3 run.py demo` và `python3 -m unittest discover -s tests -v`.

## Giới hạn

Phép so sánh với IRIS đo số đường dẫn Java cần rà soát. Độ chính xác của nhãn và thời gian rà soát cần được đánh giá riêng.
