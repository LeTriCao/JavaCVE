# Cài đặt và tái hiện

## Ubuntu hoặc WSL

Môi trường đích là Linux x86_64, Python 3.12 trở lên. Đã chạy thực tế trên Ubuntu WSL với Python3.14.4. Hỗ trợ ngoại tuyến cho chỉ mục trên Python3.12+; chưa xác nhận build Windows native/ARM.

```bash
sudo apt update
sudo apt install python3 git ca-certificates unzip
git clone https://github.com/LeTriCao/JavaCVE.git
cd JavaCVE
python3 run.py demo
python3 run.py list
python3 run.py all --cve CVE-2021-29425
```

Repository private cần tài khoản được cấp quyền. Có thể tải `JavaCVE-v0.2.0.zip` từ Releases rồi giải nén và mở terminal trong thư mục chứa `run.py`; các lệnh tiếp theo giống nhau. Kiểm tra SHA256 gói bằng `sha256sum -c SHA256SUMS.txt` khi các asset ở cùng thư mục.

Không cần cài Java/Maven hệ thống. Bootstrap tải Temurin8u514 và Maven3.9.9 theo `data/toolchain.json`, kiểm tra archive SHA256 rồi giải nén với bộ lọc đường dẫn. Cache ở `.cache/`. Cần vài GB trống nếu tải NiFi và toàn bộ phụ thuộc; thời gian phụ thuộc mạng/cache. Nếu có bộ công cụ cũ, dùng `--prior /duong/dan/JavaCVE_Reproducible`; công cụ vẫn kiểm tra chuỗi phiên bản, nguồn Git vẫn phải đúng tree/commit.

## Lấy nguồn và xuất mẫu

```bash
python3 run.py fetch
python3 run.py audit
python3 run.py export --include-tests
python3 run.py measure
```

Mặc định kho bare ở `.cache/repos/<CVE>`. Có thể đặt `--repos /duong/dan/repos` cho fetch/build/measure; với audit/export truyền cùng đường dẫn ở vị trí `cases_dir` và thêm `--git-repos`. Công cụ đọc đối tượng Git, không phụ thuộc HEAD hoặc working tree của kho cache.

Export tạo `runs/<id>/methods.jsonl`. Khi chỉ định `--export duong-dan.jsonl`, đích phải là tệp mới; không ghi đè kết quả cũ. Không commit nguồn Java xuất ra trước khi kiểm tra giấy phép của dự án tương ứng.

## Build, hành vi và lỗi

`build` chạy package và API; `security`/`all` thêm harness bảo mật. Mặc định chọn sáu thư viện có fixture. `--cve` có thể lặp lại. CVE không hỗ trợ không bị bỏ qua âm thầm: lệnh báo dùng `investigate`. Hutool chỉ build `hutool-core`.

Run thành công có `status=PASS`, `exit_code=0`. Snapshot có `security.status=EXECUTED` và assertion PASS/FAIL riêng. Snapshot có lỗi được lưu với category NETWORK, TLS, DEPENDENCY, TIMEOUT, MISSING_DEPENDENCY hoặc VALIDATION; log đầy đủ ở `runs/<id>/logs/`. Exit124 dùng cho timeout của bước, 127 cho executable bị thiếu; exit tiến trình CLI giới hạn trong 1..125 khi lỗi. Nếu bị kill từ bên ngoài, run có thể còn `running`; không sử dụng làm bằng chứng hoàn thành.

```bash
python3 run.py all --retry-from runs/ID_LAN_LOI
python3 run.py security --from-run runs/ID_BUILD_CO_ARTIFACT
python3 run.py build --offline --cve CVE-2021-29425
python3 run.py doctor --network
```

Retry ghi run mới, giữ `retry_of`, các snapshot đã đạt của run trước và lý do lỗi mới. Nó đòi hỏi command và checksum dataset giống nhau. Một run bị ngắt chưa tạo snapshot hoặc hỏng trước bước setup cần chạy lại lệnh gốc. Replay kiểm tra đúng commit và hash JAR/phụ thuộc; không dùng JAR phát hành thay cho source build.

`--offline` ngăn Git lấy commit mới và yêu cầu Maven chỉ dùng cache. Bootstrap lần đầu vẫn cần Internet để có bộ công cụ; hãy chuẩn bị cache trước. Nếu báo TLS, cài CA do môi trường cung cấp và đặt `JAVA_CVE_TRUSTSTORE` đến truststore được tin cậy; không tắt kiểm tra TLS. Nếu mạng mất, sửa kết nối rồi retry. Với Jenkins, dùng `--upstream-repositories` để thêm kho HTTPS chính thức; repo lịch sử có thể cần artifact không còn sẵn.

## Sinh báo cáo từ kết quả mới

```bash
python3 run.py all
python3 run.py measure
python3 run.py audit
python3 run.py report --run runs/ID_ALL --run runs/ID_MEASURE --run runs/ID_AUDIT
```

Báo cáo tạo metrics.json, cases.csv, REPORT.md và COURSE_REPORT.docx trong run mới. `--out thu-muc-moi` chọn đích khác. Không đưa cả run toàn bộ và run replay cùng snapshot vào báo cáo; công cụ từ chối mẫu trùng. Nếu retry nhiều lượt, báo cáo từng experiment riêng; không gọi số snapshot retry là độ phủ toàn bộ dataset.

## Batch mới và phân hoạch nghiên cứu

Các lệnh pilot không cần package Python bên ngoài. Tree-sitter chỉ cần cho mở rộng hoặc tính lại token chung:

```bash
sudo apt install python3-venv
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-annotation.txt
python run.py expand
python run.py batch-build data/batch-02 --cve CVE-2022-4244
```

Nếu môi trường không có pip, `python3 tools/bootstrap_parser.py` tải wheel Linux x86_64 vào `.cache/parser`, xác nhận SHA256 với metadata PyPI của phiên bản đã khóa. Không đổi Python hệ thống.

```bash
python3 run.py export .cache/batch02-repos --batch data/batch-02 --include-tests
python3 run.py split --with-batch data/batch-02 --repos .cache/repos
```

Để xuất/chia batch từ clone mới, `expand` phải hoàn tất trước để tạo các đối tượng Git mới; sau đó export dùng chỉ mục đã rà soát trong `data/batch-02`. Bộ chia chuẩn hóa lại cùng thuật toán token trên cả hai nhóm; gộp các dự án/CVE có token trùng trước khi phân hoạch. Đây là chuẩn bị thực nghiệm, chưa phải tập chuẩn huấn luyện.

## Kiểm tra bản phân phối

```bash
python3 run.py demo
python3 -m unittest discover -s tests -v
python3 run.py list --cwe CWE-22
python3 run.py report
python3 run.py split
```

Không chạy `seal` để chữa lỗi checksum khi vừa tải gói. Hãy tải lại gói và đối chiếu SHA256. `seal` chỉ dành cho người bảo trì sau khi đã xem thay đổi dữ liệu/mã và chuẩn bị commit mới.
