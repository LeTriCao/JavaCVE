# JavaCVE — cải thiện CWE-Bench-Java của IRIS

Trên 10 CVE có cùng commit sửa, chọn parent của bản sửa làm mốc trước đã thu hẹp tập đường dẫn Java trong diff từ 62 xuống 35 (giảm 43,55%) và giữ đủ 25/25 tệp Java được IRIS chú thích. Với CVE-2019-10392, tệp GitClientSecurityTest.java rời khỏi diff nhưng vẫn tồn tại ở cả hai snapshot. Tra mã CVE trong data/context-files.jsonl để lấy đường dẫn, commit và mã băm.

Đồ án chọn một bộ dữ liệu lỗ hổng Java có sẵn và cải thiện cách định danh, ghép phiên bản, trích xuất phương thức và lưu bằng chứng. Nguồn là CWE-Bench-Java/IRIS tại revision `d2059f299a80a68ea4a0b0315eec2f42b8743776`.

**Hiện trạng: 20 CVE, 409 phiên bản phương thức; 14/20 có cặp build; 8/20 đạt C1–C7; 342/409 UNCONFIRMED.** Mục tiêu 12/20 là đề xuất chờ giảng viên xác nhận. Không có rà soát nhãn độc lập hoàn tất.

| Đối chứng cùng fix | IRIS seed→fix | JavaCVE parent→fix | Giới hạn |
|---|---:|---:|---|
| 9 CVE Pilot, mẫu số cũ | 60 path Java | 33 | Giảm 45%; giữ 23/23 anchor IRIS |
| 10 CVE có đủ Git object | 62 | 35 | Giảm 43,55%; giữ 25/25 anchor IRIS |

Đây là phạm vi changed-path tính từ Git, không phải số file gán nhãn của IRIS fix_info; 33 path gồm 23 anchor và 10 ứng viên bổ sung. Không suy ra giảm thời gian hoặc tăng accuracy/precision nhãn. GitClientSecurityTest cùng SECURITY-1534 bị ra khỏi changed-set vẫn được lưu như ngữ cảnh. Bảng đủ 20 CVE ghi lý do loại từng ca; không gọi mọi path bị loại là nhiễu.

- [Bảng so sánh và hai ca đọc diff](docs/SO_SANH_IRIS_JAVACVE.md) · [CSV](docs/generated/iris-comparison.csv).
- [Báo cáo môn học](docs/BAO_CAO_MON_HOC.md) · [Word](docs/BAO_CAO_MON_HOC.docx).
- [Bảng nghiệm thu 20 CVE](docs/DOI_CHIEU_DU_LIEU.md) · [Phương pháp](docs/METHODOLOGY.md).
- [Phiếu người rà ẩn baseline](docs/review/HUONG_DAN.md) · [CSV](docs/review/PHIEU_RA_SOAT_NHAN.csv). Chỉ gửi ZIP người rà, không gửi thư mục review_coordinator hoặc nhãn gốc trước khi họ quyết định.
- [Kịch bản demo 5 phút](docs/DEMO_5_PHUT.md) · [Nguồn/giấy phép](docs/SOURCES.md).

Tại workspace đang sửa, ba lệnh độc lập sau dùng đích mới:

```sh
python3 -m tools.compare_iris --out runs/iris-new
python3 -m tools.course_demo --out runs/course-demo-new
python3 -m tools.acceptance --out runs/common-new.json
```

Lệnh so sánh cần Git cache có seed/parent/fix; trên bản giải nén truyền ba tùy chọn đường dẫn cache theo kịch bản. Demo và tái tính receipt không cần JDK/Maven. Bộ nộp v2 có manifest riêng được tạo lại và kiểm tra từ bản giải nén; workspace giữ manifest gốc và workflow/GitHub helper đang sửa dở ngoài phạm vi. Trong ZIP đã niêm phong, chạy `python3 run.py demo` và `python3 -m unittest discover -s tests -v`. Không ghi đã chạy trên máy khác: diễn tập hiện tại ở cùng máy Ubuntu WSL.

Giữ 6 hồ sơ thiếu cặp build và 6 hồ sơ đã build nhưng chưa đạt chuẩn, liệt kê trong báo cáo. UNCONFIRMED không phải nhãn an toàn. Phiếu trống vẫn PENDING, không tính tỷ lệ đồng thuận khi chưa có người rà. Chưa commit, push, tạo tag hoặc phát hành; gói nộp cũ được giữ nguyên.
