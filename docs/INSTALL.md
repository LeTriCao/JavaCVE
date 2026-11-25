# Cài đặt, kiểm kê và xuất dữ liệu

## Mở bản bàn giao

Dùng Python 3.12 trở lên. Các lệnh kiểm kê dưới đây dùng thư viện chuẩn Python. Trên Windows có thể dùng Ubuntu trong WSL và mở terminal tại thư mục chứa `run.py`. Máy cần quyền đọc kho riêng tư để clone. Người đã có bản clone có thể thực hiện các bước kiểm kê khi ngoại tuyến.

```bash
git clone https://github.com/LeTriCao/JavaCVE.git
cd JavaCVE
git rev-parse HEAD
python3 --version
python3 run.py demo
python3 -m unittest discover -s tests -v
```

Đối chiếu SHA vừa in với commit bàn giao. Gói ZIP của tag `v0.2.0` chứa số liệu tại thời điểm phát hành. Khi dùng gói lịch sử, có thể so SHA-256 của ZIP với tệp `SHA256SUMS.txt` đi kèm release. [Trạng thái phát hành và bàn giao](DELIVERY.md)

`demo` xác minh manifest và quan hệ giữa các bảng. CLI in đường dẫn đến `runs/<id>/run.json`; xem `status` và `exit_code` trong tệp này. Nếu báo sai checksum, so sánh `git status` và chạy lại trên bản clone sạch của cùng commit. Tạo lại manifest trên một cây đang sửa dở có thể hợp thức hóa cả những thay đổi ngoài phạm vi. [Kết quả kiểm tra tại máy](KIEM_TRA_BAN_GIAO.md)

## Xuất chỉ mục và thống kê từ bằng chứng đã lưu

`data/versions.jsonl` và `data/batch-02/versions.jsonl` có thể đọc trực tiếp dưới dạng JSON Lines UTF-8. Mỗi dòng là một phiên bản phương thức hiện diện. Lệnh `list` sau đây ghi danh sách hồ sơ vào trường `cases` của receipt cho từng lô. Đầu ra terminal còn có thông báo về thư mục run.

```bash
python3 run.py list --json
python3 run.py list --batch data/batch-02 --json
```

Tạo lại thống kê trong một thư mục run mới bằng đúng bốn receipt công bố. Lệnh này đọc kết quả có sẵn và chạy được khi máy không có JDK, Maven, parser hay cache Git của các dự án Java.

```bash
python3 run.py report \
  --run evidence/v0.2.0/5cd2e8809e084ef1bb9530b2f00f8722 \
  --run evidence/v0.2.0/b6499a16a26c41729ae28ce8f19d701b \
  --run evidence/v0.2.0/ed97b42890524847a80085211e91b217 \
  --run evidence/v0.2.0/b33dd5b053464df19b1f31900f82c68f
```

Trong `runs/<id>/report/`, `metrics.json` chứa các chỉ số và SHA-256 của đầu vào, `cases.csv` liệt kê **10 hồ sơ pilot**, `REPORT.md` và `COURSE_REPORT.docx` là báo cáo do CLI sinh. Thêm `--out` với tên thư mục mới để chọn đích. Chạy `report` không truyền `--run` sẽ thiếu các quan sát mà nhóm chỉ số `current` cần. Danh mục bàn giao có đủ 20 hồ sơ tại [bảng đối chiếu hai lô](DOI_CHIEU_DU_LIEU.md).

## Xuất mã của các phương thức đã lập chỉ mục

Chuẩn bị kho Git cục bộ cho từng CVE, mỗi thư mục mang tên `cve_id`, theo `repository_url` và cặp commit trong `cases.jsonl` của lô. Với pilot, `python3 run.py fetch` chuẩn bị cache mặc định `.cache/repos` khi có mạng. Lệnh xuất Batch02 bên dưới giả định `.cache/batch02-repos` đã chứa hai commit của từng hồ sơ. `export` chỉ đọc đối tượng Git trong cache đã chọn.

```bash
python3 run.py export .cache/repos --git-repos
python3 run.py export .cache/batch02-repos --git-repos --batch data/batch-02
```

Mỗi lệnh tạo `runs/<id>/methods.jsonl`. Thêm `--include-tests` để xuất cả phương thức trong tệp kiểm thử. Dùng `--export exports/ten-moi.jsonl` để chọn tên tệp chưa tồn tại. Từ chỉ mục hiện tại, số dòng kỳ vọng mặc định là **150 pilot và 127 Batch02**. Khi gồm test, hai số lần lượt là **187 và 222**. Đọc trường `source_review.exported_versions` trong receipt để biết số thực xuất của lượt đó. Với pilot, hai bản xuất lịch sử từ Git và bản lưu nguồn có cùng SHA-256. [Receipt xuất pilot](../evidence/source-export.json) · [Chỉ mục Batch02](../data/batch-02/versions.jsonl)

Để chỉ xác minh Git blob, khoảng dòng và băm mẫu, thay `export` bằng `verify-source` trong cùng lệnh. Tùy chọn `--ast` cần parser của `requirements-annotation.txt`. Giữ `sample_id`, `record_id`, commit, nhãn và phạm vi khi ghép dữ liệu. Mã Java xuất cục bộ chịu điều kiện phân phối của từng dự án. [Từ điển dữ liệu](DATA.md) · [Nguồn và giấy phép](SOURCES.md)
