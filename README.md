# JavaCVE v0.1.0

Bộ dữ liệu thí điểm cho môn Đảm bảo an toàn thông tin. Từ 10 hồ sơ của **CWE-Bench-Java trong IRIS**, bộ dữ liệu ghép từng phương thức Java với phiên bản Git, nhãn theo CVE và mức bằng chứng. Có 5 hồ sơ CWE-22 và 5 hồ sơ CWE-78. Trong số đó, 6 thư viện có thể build theo cả hai phiên bản và chạy kiểm tra API thông thường.

## Chạy thử trên Ubuntu hoặc WSL

Giải nén gói. Mở terminal trong thư mục chứa chính tệp `run.py`. Chỉ sao chép dòng lệnh cần chạy.

| Bạn muốn làm gì? | Lệnh |
|---|---|
| Xem thống kê và kiểm tra tính toàn vẹn của bản phát hành, dùng Python 3.12+ | `python3 run.py demo` |
| Build và kiểm tra hai phiên bản của 6 thư viện, dùng Ubuntu x86_64, Git và Internet | `python3 run.py all` |
| Thử trước với một thư viện | `python3 run.py all --cve CVE-2021-29425` |
| Đối chiếu lại gói kết quả WSL cũ nếu có tệp này | `python3 run.py audit-wsl ../results.zip` |
| Kiểm tra nguồn bước 3 và xuất mã các phương thức nghiệp vụ | `python3 run.py verify-source ../JavaCVE_Buoc3/cases --export methods-local.jsonl` |

Lệnh `demo` chạy ngoại tuyến. Lệnh `all` thực sự biên dịch mã và gọi một API thông thường trên mỗi JAR. JDK 8 và Maven được chọn theo `data/toolchain.json`. Nếu thư mục `JavaCVE_Reproducible` nằm cạnh bản này, chương trình có thể dùng lại công cụ và kho lưu nguồn đã kiểm tra SHA-256. Có thể chỉ định vị trí đó bằng `--prior /duong/dan/JavaCVE_Reproducible`. Nếu thiếu, chương trình tự tải công cụ, lấy mã qua Git và đối chiếu mã cây nguồn. Lệnh có thể mất vài phút khi chạy lần đầu.

Mỗi lệnh tạo `runs/<mã-lần-chạy>/run.json`. Dòng cuối in trạng thái và vị trí kết quả. Bản tóm tắt chứa môi trường Python thực tế, thời điểm UTC và mã lần chạy mới. Một lượt bị dừng đột ngột có thể ở trạng thái `running`. Các kết quả lịch sử có nguồn riêng trong `evidence/`.

## Dữ liệu để đọc và sử dụng

| Tệp | Đơn vị quan sát |
|---|---|
| `data/cases.jsonl` | 10 CVE, dự án, nguồn công bố, commit gốc và cặp commit được chọn |
| `data/files.jsonl` | 35 tệp thay đổi, đường dẫn và mã đối tượng Git theo từng phía |
| `data/methods.jsonl` | 126 phương thức hoặc hàm khởi tạo đã thay đổi |
| `data/versions.jsonl` | 187 phiên bản phương thức thực sự tồn tại, mỗi dòng có nhãn, khoảng dòng và SHA-256 |
| `data/pairs.jsonl` | 23 cặp phương thức trọng tâm có cả hai phía |
| `data/review.csv` | 20 quyết định rà soát ở cấp phiên bản dự án, mở được bằng Excel |
| `evidence/` | Kết quả build đối chứng, lần chạy v0.1.0 và số liệu thực nghiệm WSL có trước |

**Cách lấy phần mã Java.** Bản phát hành phân phối chỉ mục và dấu vân tay nội dung. Lệnh `verify-source --export` ghép chỉ mục với mã nguồn đã lưu, kiểm tra đủ 187 bản và xuất 150 phiên bản thuộc mã ngoài thư mục kiểm thử. 37 phiên bản mã kiểm thử vẫn có nhãn và định danh trong chỉ mục. Mỗi dòng xuất có trường `code`. Tham số `--export` nhận tên tệp mới. Với nguồn lấy độc lập từ các kho Git, dùng chế độ `--git-repos` trong hướng dẫn dữ liệu.

**Ý nghĩa nhãn.** `VULNERABLE` và `RESOLVED_TARGET` mô tả cơ chế của CVE trong phạm vi đã ghi. `UNCONFIRMED` giữ nguyên sự thiếu chắc chắn. Bộ dữ liệu có 44, 14 và 129 phiên bản phương thức tương ứng. Cả 10 CVE đã được rà soát kỹ thuật với trợ lý AI. Hiện có 0 lượt đánh giá độc lập của con người.

## Kết quả chính

Đối chứng cùng phiên bản Git, cùng bộ công cụ và phạm vi build đạt **6/6 ở cả hai quy trình**. Đóng góp đo được nằm ở việc chuẩn hóa phiên bản, ghép nhãn với bằng chứng và lưu được kết quả kiểm tra theo từng lần chạy. Kết quả trên 6 thư viện chưa đại diện cho toàn bộ CWE-Bench-Java.

Đọc [từ điển dữ liệu](docs/DATA.md), [phương pháp đối chứng](docs/BASELINE.md), [kết quả rà soát](docs/REVIEW.md) và [nguồn cùng giấy phép](docs/SOURCES.md).
