# Biên bản kiểm tra ngoại tuyến

Gói v2 cập nhật đối chứng IRIS, phiếu ẩn nhãn và diễn tập từ ZIP mới. Kết quả thực chạy ở verification/ và FINAL_VERIFICATION.json của gói; các số tệp/test phía dưới là lịch sử. Xem [BAN_NOP_MON_HOC.md](BAN_NOP_MON_HOC.md).

Ngày 25/11/2026 (giờ Việt Nam), bản sao sạch của commit `a1ea91f12cb78d2828e97c055ff6c18481107759` đạt 23/23 unit test và demo. Hai lệnh đối chiếu nguồn đã đọc 20 kho Git có sẵn tại máy và xác minh đủ **409/409 phiên bản phương thức**. Môi trường thực hiện là Ubuntu trong WSL, Python 3.14.4. Đây là kết quả kiểm tra cục bộ của commit dữ liệu trước đợt cập nhật tài liệu.

| Phép kiểm tra trên bản sao sạch | Kết quả | Phạm vi đã kiểm tra |
|---|---|---|
| Băm lại từng đường dẫn trong manifest | Đạt, mã thoát 0 | SHA-256 trùng khớp ở 415/415 tệp được liệt kê trong [checksums.json](../checksums.json) của commit trên. |
| Demo ngoại tuyến | Đạt, mã thoát 0 | Kiểm tra manifest, quan hệ giữa các bảng và điều kiện bằng chứng trong danh mục. Demo đếm được 10 hồ sơ pilot và 10 hồ sơ batch-02. |
| Audit nguồn pilot | Đạt, mã thoát 0 | 66 phiên bản tệp hiện diện, 4 trạng thái tệp vắng mặt, 187/187 phiên bản phương thức khớp dải dòng và băm. Bảng lý do của audit có 129 phiên bản `UNCONFIRMED`. |
| Đối chiếu nguồn batch-02 | Đạt, mã thoát 0 | 83 phiên bản tệp hiện diện, 23 trạng thái tệp vắng mặt, 222/222 phiên bản phương thức khớp dải dòng và băm. |
| Toàn bộ unit test Python | 23 đạt, 0 lỗi, 0 thất bại, 0 bỏ qua. Mã thoát 0 | Kiểm tra quan hệ dữ liệu, băm, liên kết README, tập chia, logic trạng thái và cách đọc receipt/log. |
| Sinh lại báo cáo từ bốn receipt | Đạt, mã thoát 0 | `metrics.json`, `cases.csv` (10 hồ sơ pilot) và `REPORT.md` giống từng byte với bản đã commit. Word mở được dưới dạng gói OOXML và đọc được `word/document.xml`. Năm tệp bên trong gói đều trùng tên và nội dung. Dấu thời gian ZIP và băm toàn tệp DOCX khác nhau. |

Một trạng thái tệp vắng mặt là một tệp có trong một phiên bản và được Git xác nhận vắng ở phiên bản còn lại. Cả hai lượt kiểm tra nguồn đều ghi nhận `exported_versions = 0`. Unit test đọc bằng chứng đã lưu và phân tích chuỗi kết quả giả lập. Dòng `FAIL` bên trong `test_failure_records_exit_code_and_log` là đầu ra mong đợi của tiến trình thử nghiệm thoát với mã 7. Bản thân test này đạt. Lượt kiểm tra dữ liệu này không tạo thêm bằng chứng thực nghiệm cho nhãn CVE.

## Lặp lại trên bản sao sạch

Chạy từ thư mục gốc của bản sao cần kiểm tra. Hai biến đường dẫn dưới đây trỏ đến thư mục cha của các kho mang tên CVE. Khi các cache nằm ở checkout khác, dùng đường dẫn tuyệt đối đến cache tương ứng. Trong lượt đã ghi nhận, Git chỉ được phép truy cập đối tượng cục bộ.

```sh
PILOT_REPOS="$PWD/.cache/repos"
BATCH_REPOS="$PWD/.cache/batch02-repos"
export GIT_NO_LAZY_FETCH=1
export GIT_ALLOW_PROTOCOL=file
python3 run.py demo
python3 run.py audit "$PILOT_REPOS" --git-repos
python3 run.py verify-source "$BATCH_REPOS" --batch data/batch-02 --git-repos
python3 -m unittest discover -s tests -v
```

Demo và unit test dùng nội dung trong Git. Hai lệnh đọc mã nguồn cần đủ Git object đã khóa. Cấu hình Python mặc định của Windows trên máy bàn giao báo thiếu mô-đun chuẩn `encodings` ngay khi khởi động. Các kết quả trong bảng được đo bằng trình thông dịch của WSL.

Lượt sinh lại báo cáo dùng bốn đối số `--run` theo đúng thứ tự trong [hướng dẫn cài đặt](INSTALL.md). SHA-256 của hai bảng đầu ra là `8512ad684a97db8703cdb1dd6d8234834ae74952746d5b678e731e726e5add3c` cho JSON và `856d5694a32235f103b13fb07311e227a47df8d4b72e5ed550c2854997ad9418` cho CSV. [Thống kê đã lưu](generated/metrics.json) · [Bảng pilot](generated/cases.csv)

## Đối chiếu số hồ sơ build được cả hai bản

Tại tag `v0.2.0` (commit `5062c2b`), Batch02 có **3/10 hồ sơ** build được cả hai bản và **8/20 snapshot** build thành công. Tại `a1ea91f`, cùng 10 hồ sơ đạt **6/10** và **12/20**. Ba hồ sơ có thêm đủ cặp build là CVE-2013-7285, CVE-2016-9177 và CVE-2023-37460. Phép đếm dùng `before.build_status` và `after.build_status` trong `data/batch-02/build-status.json` ở từng commit. Mỗi snapshot được tính đều khớp commit nguồn, bản ghi snapshot và bước build đạt với mã thoát 0 trong receipt gốc, có log tương ứng. [Bảng build tại tag](https://github.com/LeTriCao/JavaCVE/blob/5062c2b1c1f0a41ba9c0264dadd51d75703ac5ea/data/batch-02/build-status.json) · [Bảng build hiện hành](../data/batch-02/build-status.json)

## Định danh receipt trên máy bàn giao

Mỗi mã dưới đây tương ứng với `runs/<mã>/run.json`. Thư mục `runs/` được Git bỏ qua. Bản clone mới sẽ sinh mã riêng khi lặp lại. Các giá trị SHA-256 dưới đây nhận diện chính xác byte của receipt tại thời điểm kiểm tra.

| Lượt chạy | Mã | SHA-256 của run.json |
|---|---|---|
| Demo, bản sao sạch | `7471e00823ea46f6b3dc4f9a4c22dd88` | `95c9e4dfb83012492b6e185adffe20d9e59bb6c5546e03fc19603bd7847c8c67` |
| Audit pilot, bản sao sạch | `b734c2e9c6d44406ad73b40ef3c77698` | `e2aa719d6c220f023ea3baf4e16b2aab2981f096252ecbc3afdbf45db4b8d7ba` |
| Đối chiếu batch-02, bản sao sạch | `dd08eaa02eb5470c9f2b8f18f412e83c` | `a6d06bcd7eefd4f43a6dedf9fd99fd3fc66bbe089abc62a6e5151b402aa284ac` |
| Sinh báo cáo từ bốn receipt, bản sao sạch | `d198080fe3474a9b9a14745fb137c7c2` | `b1a063805c963293094b576e896173868bb3678fc825598d7ee251713e2d7ffb` |
| Demo, thư mục làm việc lúc tiếp nhận | `542a5709633940fcb0d31aed62dea4d8` | `df50ee48f36fdaef2bdb19e6c355ec9e373b05352d9d8d1da997832defc7c46b` |

## Thư mục làm việc lúc tiếp nhận

Trong 415 tệp có băm ở manifest ban đầu, 413 tệp khớp. Hai tệp có sửa đổi dở là `.github/workflows/verify.yml` và `tools/github.ps1`. Tại thư mục đó, demo thoát với mã 1 ở đường dẫn đầu tiên. Unit test chạy đủ 23 bài, có 22 bài đạt và một lỗi tại `test_catalog_relations_and_counts` do cùng sai lệch SHA-256. Hai thư mục chưa được Git theo dõi là `evidence/diagnostic-logging/` và `evidence/plexus-control/`. Các con số ở phần này mô tả trạng thái ngay lúc tiếp nhận, trước khi sửa tài liệu.

## Kiểm tra nghiệm thu theo chuẩn chung ngày 25/11/2026

Phần này ghi kết quả **lượt nghiệm thu chung**, tách khỏi các lượt kiểm tra lịch sử phía trên. Môi trường: Ubuntu WSL, Python **3.14.4**. Bản ghi kiểm tra: [validation.json](../evidence/acceptance-20261125/validation.json). Toàn bộ kết luận dùng dữ liệu đang có trên máy, không chạy payload Java mới hoặc build lại các dự án Java.

| Kiểm tra | Kết quả | Bằng chứng / giới hạn |
|---|---|---|
| Đối chiếu nguồn Pilot | PASS, 187/187 phiên bản; 66 phiên bản tệp và 4 trạng thái vắng | [source-check.json](../evidence/acceptance-20261125/source-check.json) |
| Đối chiếu nguồn Batch02 | PASS, 222/222 phiên bản; 83 phiên bản tệp và 23 trạng thái vắng | Cùng bản ghi nguồn; tổng 409/409. `exported_versions=0`. |
| AST chạy lại | PASS, 409/409 khớp tên và biên dòng, 0 lỗi | [ast-check.json](../evidence/acceptance-20261125/ast-check.json) |
| Commit/tree/cha được chọn | PASS, 20/20 cặp | [topology-check.json](../evidence/acceptance-20261125/topology-check.json) |
| Rà receipt/log/fixture theo C1–C7 | 8/20 đạt; 12/20 cặp build; 342/409 phương thức U | [acceptance-review.json](../data/acceptance-review.json); kết quả thực nghiệm đã lưu, không phải lần chạy Java mới |
| Unit test trên cây làm việc | **27 đạt, 1 lỗi trên 28 bài**, exit 1 | [Log cây làm việc](../evidence/acceptance-20261125/unit-working-tree.log). Lỗi duy nhất tại `test_catalog_relations_and_counts`: SHA-256 của `.github/workflows/verify.yml` lệch manifest do sửa dở đã có từ trước. |
| Unit test trên bản sao cách ly | **28/28 đạt**, exit 0 | [Log bản sao](../evidence/acceptance-20261125/unit-isolated.log). Sao chép tệp hiện tại, chỉ tính lại 415 băm manifest trong bản sao; không reset thay đổi của người dùng, không đổi manifest gốc. Đây không phải kết quả clone sạch hoặc phát hành. |
| Word | Đọc được XML OOXML; chỉ `word/document.xml` thay đổi | Sáu thành phần còn lại trong gói, gồm styles/header/footer/relationships, giữ nguyên từng byte so với bản trước lượt này. |
| Bảo toàn sửa dở ngoài phạm vi | PASS | Workflow, `tools/github.ps1`, `docs/DATA.md`, `docs/INSTALL.md`, tài liệu CI và toàn bộ bằng chứng cục bộ đã có giữ nguyên băm. Danh sách cụ thể trong validation.json. |

Năm bài test bổ sung kiểm tra: bản vá một phần vẫn có thể hoàn tất hồ sơ; PASS/PASS không chứng minh hành vi mục tiêu; thiếu đối chứng/đổi fixture/trùng assertion bị chặn; 20 CVE dùng cùng cổng đánh giá và JSON tính lại khớp; đối chứng riêng phải đúng hai commit. Dòng `FAIL runs/...` trong bài thử tiến trình exit 7 là đầu ra mong đợi, bản thân bài test đó đạt.

Lệnh đã chạy từ thư mục gốc trong WSL:

```sh
python3 -m unittest discover -s tests -v
python3 -m tools.acceptance --out runs/acceptance-recheck.json
```

Lệnh thứ hai có thể dùng để tính lại vào một tên mới; không ghi đè assessment cũ. Đối chiếu nguồn/AST dùng trực tiếp các hàm kiểm tra để không bị chặn bởi manifest đang sửa; đặt `GIT_NO_LAZY_FETCH=1` và `GIT_ALLOW_PROTOCOL=file`:

```python
from pathlib import Path
from tools.catalog import verify_sources
from tools.batch import verify_batch
from tools.ast_audit import audit
verify_sources(Path('.cache/repos'), git_repositories=True)
verify_batch(Path('data/batch-02'), Path('.cache/batch02-repos'))
audit(Path('.cache/repos'))
audit(Path('.cache/batch02-repos'), Path('data/batch-02'))
```

Các phép kiểm tra này chỉ xác minh danh tính nguồn; không tự xác minh ý nghĩa nhãn. Các fixture Java, receipt lịch sử và nhãn phương thức giữ nguyên. Còn 12 hồ sơ chưa đạt; ưu tiên bốn hồ sơ đã build được, rồi phụ thuộc/môi trường và rà soát độc lập. Mục tiêu **12/20 vẫn là đề xuất**. Chưa commit, push, tạo tag hoặc phát hành. `checksums.json` gốc vẫn trùng HEAD; chỉ niêm phong khi các sửa dở đã được rà soát và chốt.

## Kiểm tra sau khôi phục build và kiểm thử chức năng (25/11/2026)

Lượt này dùng Ubuntu WSL/Python 3.14.4, giữ nguyên các sửa dở ngoài phạm vi. Đã chọn đúng hai CVE chưa build đủ cặp: Retrofit CVE-2018-1000850 và Jenkins CVE-2022-25174. [Kết quả và cấu hình](RECOVERY_20261125.md) · [Các lượt thử](../data/build-recovery-20261125.json).

| Kiểm tra | Kết quả | Bằng chứng / phạm vi |
|---|---|---|
| Build từ nguồn mới | **4/4 snapshot PASS; thêm 2 cặp**, tổng **14/20** | JDK 1.8.0_514-b01/Maven 3.9.9; Kotlin plugin 1.2.60 và profile Jenkins bỏ riêng HPI test staging được lưu diff/băm. Không có bằng chứng Jenkins integration test. |
| XStream chức năng | **18/18 đối chứng đạt**, 3 ca × 6 snapshot | [Receipt JVM/compile](../evidence/v0.2.0/aac8bdcef6204ac8891c54117652ef98/run.json). Dùng JAR source-build đã kiểm tra SHA-256, fixture String/chuỗi rỗng/Integer, DomDriver. Không tính thành build mới hoặc C7. |
| Plexus Archiver chức năng | **1 test mỗi bản, PASS/PASS**, 0 failure/error/skipped | [Receipt mới](../evidence/recovery-20261125/plexus-ordinary.json). Tệp ZIP thường, giới hạn 11 byte, so băm đầu ra/entry; không chạy tệp bên trong. |
| Đối chiếu nguồn và AST chạy lại | **409/409**, 0 sai lệch | [source-check.json](../evidence/recovery-20261125/source-check.json): Pilot 187, Batch02 222. Git lazy fetch tắt, chỉ protocol file. Không đổi chỉ mục nguồn, khoảng dòng hoặc nhãn phương thức. |
| Tái tính C1–C7 | **8/20 đạt**, 342/409 U | [acceptance-review.json](../data/acceptance-review.json). C6 của XStream 2020/2021 được bổ sung; C7 vẫn thiếu. Plexus 2023 vẫn thiếu C4/C7. |
| Unit test trên cây làm việc | **33/34 đạt, 1 lỗi**, exit 1 | [Log](../evidence/recovery-20261125/unit-working-tree.log). Lỗi duy nhất là SHA-256 `.github/workflows/verify.yml` không khớp manifest cũ; thay đổi này có sẵn khi tiếp nhận. |
| Unit test trong bản sao cách ly | **34/34 đạt**, exit 0 | [Log](../evidence/recovery-20261125/unit-isolated.log). Bản sao chứa các tệp dự kiến bàn giao, không phải bản clone sạch hoặc release. |
| Manifest cách ly | **501/501 tệp khớp**, đúng tập đường dẫn dự kiến tại thời điểm chụp | [validation.json](../evidence/recovery-20261125/validation.json). Chỉ `seal` ở bản sao; manifest gốc giữ nguyên từng byte. Ảnh chụp này có trước khi ghi log/biên bản kết quả cuối lượt. |
| Demo và tái tính ở bản sao | PASS, exit 0; JSON tái tính giống bản bàn giao | [Demo](../evidence/recovery-20261125/demo-isolated.log) · [Tái tính](../evidence/recovery-20261125/acceptance-isolated.log). Không cần JAR hoặc cache Git để tái tính các receipt đã lưu. |
| Báo cáo sinh lại | PASS; Batch02 **8/10 cặp**, **16/20 snapshot** | [Receipt sinh báo cáo](../evidence/recovery-20261125/report-generation.json). Bốn receipt pilot đầu vào giữ nguyên; catalog/chuẩn chung đọc ledger đã kiểm chứng. |
| Bảo toàn sửa dở | PASS theo băm đầu lượt | Workflow, `tools/github.ps1`, DATA/INSTALL và bằng chứng đã có ngoài phạm vi giữ nguyên. Tệp nhãn `versions.jsonl` hai lô giữ nguyên. Word chỉ sửa `word/document.xml`, sáu thành phần gói khác giữ nguyên từng byte. |

[Danh sách bàn giao dự kiến](DELIVERY_CANDIDATE.json) còn trạng thái **chưa chốt**. Manifest đầu lượt có 415 tệp, 408 khớp và bảy lệch đều thuộc danh sách sửa dở đã biết. Các thay đổi mới được liệt kê riêng; không niêm phong cây gốc để hợp thức hóa chúng. Kết quả `seal` ở bản sao chỉ kiểm tra toàn vẹn của ảnh chụp, không phê duyệt nội dung sửa dở.

Các lượt Jenkins bị dừng có chủ đích được ghi tại [sửa namespace](../evidence/recovery-20261125/transport-correction.json) và [dừng test staging](../evidence/recovery-20261125/test-staging-interruption.json), cùng log/thông tin thread tương ứng. Không đổi chúng thành PASS và không xóa lịch sử.

Còn **6 CVE chưa có cặp build**, **6 CVE có build nhưng chưa đạt chuẩn chung**, 0 người rà soát độc lập. Mục tiêu **12/20 đạt C1–C7** vẫn chờ giảng viên xác nhận. Chưa commit, push, tạo tag hoặc phát hành.
