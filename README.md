# JavaCVE v0.2.0

Bộ dữ liệu và công cụ thực nghiệm cho đồ án **Đảm bảo an toàn thông tin**, định hướng nghiên cứu chất lượng dữ liệu lỗ hổng Java. JavaCVE kế thừa **CWE-Bench-Java trong IRIS**, giữ revision `d2059f299a80a68ea4a0b0315eec2f42b8743776`, và bổ sung cặp commit có kiểm chứng, chỉ mục phương thức, nhãn có phạm vi và bằng chứng chạy lại.

Repository: [LeTriCao/JavaCVE](https://github.com/LeTriCao/JavaCVE) · [Phát hành v0.2.0](https://github.com/LeTriCao/JavaCVE/releases/tag/v0.2.0). Repository ban đầu để private theo yêu cầu chủ sở hữu.

## Kết quả đã đo

| Phạm vi | Kết quả | Diễn giải |
|---|---:|---|
| Pilot gốc | 10 CVE, 126 callable, 187 phiên bản | 35 tệp Java; callable gồm phương thức/hàm khởi tạo |
| Nhãn pilot | 44 VULNERABLE, 14 RESOLVED_TARGET, 129 UNCONFIRMED | Nhãn theo cơ chế và điều kiện trong hồ sơ |
| Build và hành vi pilot | 12/12 snapshot của 6 thư viện | 6/10 CVE pilot có pipeline hành vi; 4 Jenkins/NiFi còn bị chặn |
| Phép thử bảo mật pilot | 22 assertion: 7 PASS, 15 FAIL | 12 đối chứng đều PASS; 4/6 bản sau còn assertion bảo mật FAIL |
| Chuẩn hóa phạm vi tệp | 60 → 33, giảm 45% | Đúng 9 CVE giữ cùng SHA sửa; đếm đường dẫn `.java` thay đổi |
| Ánh xạ sửa hiệu chỉnh | 1/10 | Commons IO; giữ nguyên metadata seed |
| Toàn vẹn phương thức pilot | 187/187 | Kiểm tra blob Git, khoảng dòng và SHA256 từ source |
| Batch bổ sung | 10 CVE, 222 phiên bản | 10/10 đã chuẩn hóa nguồn; 2/10 hoàn tất theo tiêu chí build + hành vi + rà soát AI |
| Nhãn batch bổ sung | 5 VULNERABLE, 4 RESOLVED_TARGET, 213 UNCONFIRMED | Expand và đường gọi external của Spark có bằng chứng; XStream còn thiếu hành vi phân biệt cơ chế CVE |
| Người đánh giá độc lập | 0 | Lượt rà soát hiện do AI thực hiện |

Build đối chứng lịch sử trên cùng 6 seed, JDK, Maven và mô-đun đạt **6/6 ở cả IRIS và JavaCVE**. Không có chênh lệch tỷ lệ build trong phép đối chứng đó. Số tệp giảm không chứng minh giảm thời gian lao động hoặc tăng độ chính xác mô hình.

Xem [bảng số liệu tính lại](docs/generated/metrics.json), [báo cáo môn học](docs/generated/REPORT.md), [bản Word](docs/generated/COURSE_REPORT.docx), [thử nghiệm bị chặn](docs/EXPERIMENTS.md) và [batch bổ sung](docs/BATCH02.md).

Rà soát Spark/XStream từ `a7e6abd`: [bảng từng tiêu chí và phần thiếu](docs/BATCH02_REVIEW.md), [quyết định từng callable](docs/BATCH02_CALLABLE_REVIEW.md). Spark hoàn tất trong phạm vi external static files đã đo. XStream giữ UNCONFIRMED: 27 upstream test mỗi bản đạt, nhưng fixture chỉ ghi ConversionException và 0 callback ở cả hai bản.

Lượt tiếp từ `8fefbe9` rà soát thêm 23 callable và 4 snapshot của CVE-2020-26217/CVE-2021-21345. Cả hai giữ UNCONFIRMED: test upstream thay đổi 7→9 và 11→13, chưa có control chung và hành vi paired đúng advisory. [Chẩn đoán CVE-2013-7285](docs/XSTREAM_DIAGNOSIS.md) xác nhận 15 dependency giống thứ tự/hash; log cũ thiếu message/cause/stack nên nguyên nhân gốc vẫn chưa xác định. Tổng cộng có 153 quyết định callable và 8 quyết định snapshot ghi riêng; Batch02 vẫn 2/10 hoàn tất.

## Chạy thử trên Ubuntu/WSL x86_64

Cần Python 3.12+, Git, chứng chỉ CA và Internet ở lần đầu. JDK8u514 và Maven3.9.9 được tải theo URL đã khóa và kiểm tra SHA256. Mở terminal trong thư mục có `run.py`.

```bash
python3 run.py demo
python3 run.py list --cwe CWE-22
python3 run.py all --cve CVE-2021-29425
```

`demo` kiểm tra chỉ mục và manifest ngoại tuyến. `all` của v0.2.0 build từ nguồn, chạy API và chạy **fixture bảo mật gốc của JavaCVE_Reproducible**. Assertion bảo mật FAIL được giữ như quan sát; lỗi build, harness hoặc đối chứng làm lệnh thất bại. `PASS` của lệnh không có nghĩa mọi thuộc tính bảo mật đều đạt.

## Các thao tác chính

| Mục đích | Lệnh |
|---|---|
| Xem dự án/CWE/trạng thái bằng chứng | `python3 run.py list --json` |
| Xem riêng batch bổ sung | `python3 run.py list --batch data/batch-02` |
| Tải commit đã khóa của toàn bộ pilot | `python3 run.py fetch` |
| Build sáu CVE hỗ trợ, kèm kiểm tra API | `python3 run.py build` |
| Build và chạy kiểm tra bảo mật | `python3 run.py security --cve CVE-2021-29425` |
| Build/API/bảo mật toàn bộ tập hỗ trợ | `python3 run.py all` |
| Kiểm tra nguồn và xuất toàn bộ phương thức | `python3 run.py export --include-tests` |
| Rà soát toàn vẹn và xuất lý do UNCONFIRMED | `python3 run.py audit` |
| Tính lại phép so sánh tệp | `python3 run.py measure` |
| Sinh thống kê/báo cáo từ bằng chứng lịch sử | `python3 run.py report` |
| Thử bốn hồ sơ Jenkins/NiFi | `python3 run.py investigate --upstream-repositories --timeout 180` |
| Kiểm tra môi trường và kết nối | `python3 run.py doctor --network` |
| Tạo phân hoạch pilot theo dự án, chặn trùng token | `python3 run.py split` |
| Tái tạo bước trích xuất batch bổ sung | `python3 run.py expand` |
| Build/kiểm tra CVE mới đã có fixture | `python3 run.py batch-build data/batch-02 --cve CVE-2022-4244` |

`export`/`audit` cần chạy `fetch` trước để có đủ cả 10 kho Git. Mặc định export giữ mã nghiệp vụ; `--include-tests` thêm mã kiểm thử. Tệp xuất nằm trong thư mục run mới, kèm nguồn, nhãn và ngữ cảnh; mã nguồn bên thứ ba không được gộp vào giấy phép MIT của công cụ.

Mỗi lệnh tạo `runs/<id>/run.json`; dòng đầu và cuối chỉ vị trí. Các bước tải/build/API/bảo mật ghi thời gian, commit, lệnh, exit code và log. Kết quả lịch sử ở `evidence/`; kết quả công bố của v0.2.0 ở `evidence/v0.2.0/`.

```bash
# Thay <id> bằng ID vừa in ra; không gõ nguyên dấu < >.
python3 run.py all --retry-from runs/<id>
python3 run.py security --from-run runs/<id>
```

Retry tạo run mới và chỉ chạy các snapshot thất bại của cùng command/dataset. Replay dùng artifact đã build từ source và kiểm tra lại hash JAR/phụ thuộc. `--offline` chỉ dùng cache sẵn có; thiếu commit/phụ thuộc được báo rõ.

Để sinh báo cáo từ lượt chạy của chính bạn, thêm các `--run` trỏ đến run build, run `measure` và run `audit`. Không đưa hai quan sát trùng CVE/phase vào cùng báo cáo. Hướng dẫn cụ thể tại [INSTALL.md](docs/INSTALL.md).

## Dữ liệu và phương pháp

`data/cases.jsonl` → `files.jsonl` → `methods.jsonl` → `versions.jsonl` lưu liên kết CVE → commit → tệp → callable → nhãn. Phía phương thức không tồn tại không được tạo mẫu rỗng. `data/batch-02/` tách riêng đợt mới; không làm đổi mẫu số pilot.

Đọc [từ điển dữ liệu](docs/DATA.md), [quy tắc nhãn](docs/LABELS.md), [phương pháp đo](docs/METHODOLOGY.md), [phép đối chứng lịch sử](docs/BASELINE.md), [nguồn và giấy phép](docs/SOURCES.md), [CHANGELOG](CHANGELOG.md).

Kiểm tra tự động: `python3 -m unittest discover -s tests -v`. GitHub Actions chạy kiểm tra ngoại tuyến khi push/PR; chạy thủ công workflow để build và đo hành vi Commons IO từ source trong runner mới.
