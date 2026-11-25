# Đối chiếu GitHub Actions

Tại mốc bắt đầu bàn giao `a1ea91f`, GitHub Actions ghi nhận **13 lượt** của workflow `Verify JavaCVE`, gồm 12 lượt trên `main` và một lượt khi đẩy thẻ `v0.2.0`. Đối chiếu ngày 25/11/2026 (giờ Việt Nam) bằng API chỉ đọc của kho riêng tư. Cả 13 lượt đều có `status=completed`, `run_attempt=1`. Cột job ghi nguyên giá trị `conclusion` từ GitHub. Liên kết yêu cầu quyền đọc repo. [Lịch sử workflow](https://github.com/LeTriCao/JavaCVE/actions/workflows/verify.yml)

| Lượt | Commit | Sự kiện | `offline` | `source-security` | Kết luận lượt |
|---|---|---|---|---|---|
| [1 · 45344672678](https://github.com/LeTriCao/JavaCVE/actions/runs/45344672678) | `b6d7191` | push main | failure | skipped | failure |
| [2 · 45350615549](https://github.com/LeTriCao/JavaCVE/actions/runs/45350615549) | `b09707e` | push main | success | skipped | success |
| [3 · 45352424301](https://github.com/LeTriCao/JavaCVE/actions/runs/45352424301) | `5062c2b` | push main | success | skipped | success |
| [4 · 45352436195](https://github.com/LeTriCao/JavaCVE/actions/runs/45352436195) | `5062c2b` | workflow_dispatch | success | success | success |
| [5 · 45352621268](https://github.com/LeTriCao/JavaCVE/actions/runs/45352621268) | `5062c2b` | push thẻ v0.2.0 | success | skipped | success |
| [6 · 45357185290](https://github.com/LeTriCao/JavaCVE/actions/runs/45357185290) | `a8ab073` | push main | success | skipped | success |
| [7 · 45357250471](https://github.com/LeTriCao/JavaCVE/actions/runs/45357250471) | `627abe2` | push main | success | skipped | success |
| [8 · 45361863359](https://github.com/LeTriCao/JavaCVE/actions/runs/45361863359) | `1d8ae45` | push main | success | skipped | success |
| [9 · 45361871765](https://github.com/LeTriCao/JavaCVE/actions/runs/45361871765) | `1d8ae45` | workflow_dispatch | success | success | success |
| [10 · 45364875700](https://github.com/LeTriCao/JavaCVE/actions/runs/45364875700) | `a7e6abd` | push main | success | skipped | success |
| [11 · 45367863189](https://github.com/LeTriCao/JavaCVE/actions/runs/45367863189) | `8fefbe9` | push main | success | skipped | success |
| [12 · 45369797171](https://github.com/LeTriCao/JavaCVE/actions/runs/45369797171) | `0280b7d` | push main | success | skipped | success |
| [13 · 45412250213](https://github.com/LeTriCao/JavaCVE/actions/runs/45412250213) | `a1ea91f` | push main | success | skipped | success |
| **Tổng đến mốc trên** | | | **12 đạt, 1 lỗi** | **2 đạt, 11 bỏ qua** | **12 đạt, 1 lỗi** |

## Phạm vi từng kết quả

- Ở lượt 1, bước demo của job `offline` lỗi. Các bước unit test, liệt kê dữ liệu, tạo báo cáo và chia tập đều bị bỏ qua. Giá trị `failure` ở cấp job không cho biết nguyên nhân gốc của lỗi demo. [Chi tiết job offline](https://github.com/LeTriCao/JavaCVE/actions/runs/45344672678/job/138276259667)
- Ở lượt 4 của bản v0.2.0, job `source-security` ghi nhận bước xử lý Commons IO và tải artifact đều đạt. Receipt phát hành ghi riêng kết luận từng job, từng bước. Tệp `dist/verification.json` tại máy trùng SHA-256 do GitHub công bố cho tài sản `verification.json` là `af33a18ae1ad27ed6ac3d020988277f9ba596c7614620566521cb09e71042a21`. Mục `fresh_github_clone` và `fresh_archive` trong receipt là các lần kiểm tra bản giao trên máy. [Receipt phát hành](https://github.com/LeTriCao/JavaCVE/releases/download/v0.2.0/verification.json) · [Chi tiết job nguồn](https://github.com/LeTriCao/JavaCVE/actions/runs/45352436195/job/138301959935)
- Cùng commit `1d8ae45`, lượt 8 do push có `source-security=skipped`, còn lượt 9 được kích hoạt thủ công có `source-security=success`. Ở lượt 9, GitHub ghi nhận bước Commons IO, bước build cặp Spark/XStream và bước tải artifact đều đạt. Phạm vi xác nhận hành vi của từng hồ sơ phụ thuộc receipt tương ứng. Hai lượt cũng khớp ghi chép trong tài liệu khôi phục build. [Ghi chép trong repo](BUILD_RECOVERY.md) · [Chi tiết job nguồn lượt 9](https://github.com/LeTriCao/JavaCVE/actions/runs/45361871765/job/138333691090)
- Tại commit `a1ea91f12cb78d2828e97c055ff6c18481107759`, năm bước dữ liệu của `offline` đều đạt gồm demo, unit test, liệt kê, tạo báo cáo và chia tập. Điều kiện của `source-security` chỉ cho phép sự kiện `workflow_dispatch`, nên mọi lượt push trong bảng có kết luận `skipped` cho job này. [Job offline](https://github.com/LeTriCao/JavaCVE/actions/runs/45412250213/job/138508874758) · [Job bị bỏ qua](https://github.com/LeTriCao/JavaCVE/actions/runs/45412250213/job/138508877562) · [Workflow tại mốc kiểm kê](https://github.com/LeTriCao/JavaCVE/blob/a1ea91f12cb78d2828e97c055ff6c18481107759/.github/workflows/verify.yml)

Khi bắt đầu kiểm kê, bản làm việc có sửa dở `.github/workflows/verify.yml` và `tools/github.ps1` để thêm tùy chọn kiểm tra Plexus khi kích hoạt thủ công. Cả 13 lượt trong bảng đều dùng cấu hình đã commit tại SHA của chúng. Chưa có kết quả CI cho phần sửa dở đó trong phạm vi đối chiếu.
