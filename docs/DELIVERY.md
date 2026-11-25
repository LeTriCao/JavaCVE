# Biên bản bàn giao JavaCVE ngày 25/11/2026

Gói v2 cập nhật đối chứng IRIS, phiếu ẩn nhãn và diễn tập từ ZIP mới. Kết quả thực chạy ở verification/ và FINAL_VERIFICATION.json của gói; các số tệp/test phía dưới là lịch sử. Xem [BAN_NOP_MON_HOC.md](BAN_NOP_MON_HOC.md).

| Sản phẩm | Nội dung |
|---|---|
| [Báo cáo môn học](BAO_CAO_MON_HOC.md) · [Bản Word](BAO_CAO_MON_HOC.docx) | Kết quả hai lô, bảng so sánh cải tiến, giới hạn và nguồn của từng phép đo |
| [Bảng đối chiếu dữ liệu](DOI_CHIEU_DU_LIEU.md) | Đủ 20 tên hồ sơ IRIS, dự án, advisory, số phiên bản, nhãn, phạm vi và receipt tương ứng |
| [Biên bản kiểm tra](KIEM_TRA_BAN_GIAO.md) · [Bảng GitHub Actions](DOI_CHIEU_CI.md) | Môi trường và phép kiểm tra cục bộ, sự kiện và kết luận từng job CI |
| [Cài đặt và xuất dữ liệu](INSTALL.md) · [Từ điển dữ liệu](DATA.md) · [Phương pháp và giới hạn](METHODOLOGY.md) | Cách đọc lại các bảng, xác minh nguồn và tạo bản xuất |
| [Thống kê JSON](generated/metrics.json) · [CSV pilot](generated/cases.csv) | Đầu ra máy đọc của pipeline. CSV chứa 10 hồ sơ pilot. |

## Trạng thái Git khi tiếp nhận

`git status` và `git log --oneline --decorate -n 50` cho thấy nhánh `main` và `origin/main` cùng ở `a1ea91f12cb78d2828e97c055ff6c18481107759`. Lịch sử khi đó có 11 commit. Tag `v0.2.0` trỏ tới commit `5062c2b1c1f0a41ba9c0264dadd51d75703ac5ea`. Sau tag có các lượt khôi phục build và rà soát bổ sung ở Batch02. Bảng bàn giao sử dụng dữ liệu tại `a1ea91f`. [Cây dữ liệu tại thời điểm kiểm kê](https://github.com/LeTriCao/JavaCVE/tree/a1ea91f12cb78d2828e97c055ff6c18481107759) · [Release tại tag](https://github.com/LeTriCao/JavaCVE/releases/tag/v0.2.0)

Hai tệp đã sửa là `.github/workflows/verify.yml` và `tools/github.ps1`. Hai thư mục chưa được theo dõi là `evidence/diagnostic-logging/` và `evidence/plexus-control/`. Đây là phần việc cục bộ có trước đợt bàn giao. Manifest của bản giao được tính trên cây sạch chỉ chứa tài liệu mới và các tệp thuộc commit. Chạy demo ngay trên cây đang sửa vẫn có thể báo sai băm ở tệp CI. [Chi tiết kiểm tra hai trạng thái](KIEM_TRA_BAN_GIAO.md)

## Công việc còn thiếu tại mốc bàn giao ban đầu

| Phần việc | Tình trạng và điều kiện khép lại |
|---|---|
| Bốn CVE pilot chưa có cặp build đạt | Jenkins Git Client, Jenkins Perfecto, Jenkins Docker Commons và Apache NiFi/NiFi Registry có phân tích tĩnh. Còn thiếu cặp build của mô-đun đã chọn và bằng chứng tích hợp. Các lần thử đã lưu ghi lỗi phụ thuộc hoặc hết thời gian. [Lịch sử pilot](EXPERIMENTS.md) |
| Bốn CVE Batch02 đã build cả hai bản | XStream CVE-2013-7285, CVE-2020-26217, CVE-2021-21345 và Plexus Archiver CVE-2023-37460 còn thiếu kết luận hành vi đủ phạm vi. Giữ nhãn đang chờ đến khi bằng chứng được thẩm định. [Rà soát theo tiêu chí](BATCH02_REVIEW.md) · [Build theo hồ sơ](../data/batch-02/build-status.json) |
| Bốn CVE Batch02 chưa build đủ cặp | Retrofit CVE-2018-1000850, one-java-agent CVE-2022-25842 và hai plugin Jenkins CVE-2022-25174, CVE-2022-25175 còn vướng cấu hình, thời gian hoặc phụ thuộc. Còn thiếu nguồn xác minh cho một số phụ thuộc lịch sử. [Nhật ký Batch02](BATCH02.md) |
| Rà soát nhãn và giới hạn nghiên cứu | 342/409 phiên bản phương thức chưa xác nhận. Cần người rà soát độc lập và ghi nhận mức đồng thuận. Chưa có số đo thời gian lao động, chất lượng mô hình hoặc kiểm tra clone gần giống. [Quy tắc nhãn](LABELS.md) · [Phương pháp](METHODOLOGY.md) |
| Bản nộp môn học | Còn thiếu trường, lớp, sinh viên và giảng viên đã xác nhận. Bản đề xuất hoặc mục tiêu nghiệm thu trong tài liệu làm việc cần được đánh giá riêng khi có tiêu chí chính thức. |
| Thay đổi dở trước bàn giao | Hai tệp cấu hình/công cụ và hai thư mục bằng chứng cục bộ nêu trên còn cần được chủ sở hữu rà soát riêng. |

## Dấu vết phát hành

Bản báo cáo do CLI sinh tại `docs/generated/` dùng bốn receipt ghi trong `metrics.json`. Báo cáo môn học ở đầu trang bổ sung đối chiếu với tag và danh mục đầy đủ. Receipt phát hành còn ghi các phép kiểm tra trước đây trên clone và ZIP. Chọn đúng sự kiện và commit khi trích dẫn kết quả CI. [Cách tính lại thống kê](INSTALL.md) · [Kiểm tra clone lịch sử](../evidence/v0.2.0/fresh-clone-b09707e.json) · [Các lượt CI](DOI_CHIEU_CI.md)

## Cập nhật nghiệm thu chung ngày 25/11/2026

Đã rà toàn bộ 20 CVE theo C1–C7 giống nhau cho Pilot và Batch02: **8/20 đạt** (6 Pilot, 2 Batch02), **12/20 cặp build**, giữ nguyên 342/409 nhãn `UNCONFIRMED`. Đây là lượt đọc lại receipt/log và kiểm tra nguồn, không có thực nghiệm Java mới. Mục tiêu **12/20 đạt chuẩn** vẫn là đề xuất chờ giảng viên xác nhận. [Bảng nghiệm thu](DOI_CHIEU_DU_LIEU.md) · [Chuẩn chung](METHODOLOGY.md#tiêu-chí-nghiệm-thu-chung-common-scoped-v1) · [JSON](../data/acceptance-review.json)

Các sửa dở của người dùng được giữ nguyên; tài liệu được cập nhật tiếp trên nội dung hiện có. Không thay manifest của cây làm việc, không commit/push/tag/release. Các nhận xét về manifest và kiểm tra cây sạch ở phía trên là lịch sử; kết quả lượt này ở [biên bản mới](KIEM_TRA_BAN_GIAO.md#kiểm-tra-nghiệm-thu-theo-chuẩn-chung-ngày-25112026).

## Lượt khôi phục build và kiểm thử thông thường (25/11/2026)

Kết quả hiện tại: **14/20 cặp build**, tăng **2**; **8/20 đạt chuẩn chung**, không nâng nhãn phương thức. [Build và kiểm thử chức năng mới](RECOVERY_20261125.md) · [Bảng nghiệm thu](DOI_CHIEU_DU_LIEU.md). Manifest gốc được giữ nguyên, danh sách bàn giao vẫn là dự kiến. Chưa commit/push/tag/release. Các kết quả và tiêu chí theo lô phía trên là lịch sử; C1–C7 cập nhật ở `data/acceptance-review.json`.
