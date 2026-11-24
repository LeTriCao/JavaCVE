# Changelog

## Sau 8fefbe9 — 24/11/2026

- Đối chiếu tiêu chí và receipt cho CVE-2020-26217/CVE-2021-21345: upstream 7→9 và 11→13 test đạt nhưng thiếu control chung/hành vi paired; thêm 23 quyết định callable và 4 snapshot do AI rà soát, giữ UNCONFIRMED.
- Lưu chẩn đoán CVE-2013-7285: fixture/toolchain và 15 dependency giống nhau; log chỉ in tên ConversionException nên không thể xác định nguyên nhân gốc. Ghi kế hoạch thu thập message/cause/stack và giai đoạn trong thử nghiệm tiếp theo.
- Tính thống kê quyết định từ dữ liệu: 153 callable, 8 snapshot ghi riêng. Batch02 vẫn 2/10 hoàn tất; nhãn không đổi. Receipt/intake lịch sử giữ nguyên.

## Sau a7e6abd — 24/11/2026

- Rà soát AI từng tiêu chí hoàn tất, 4 snapshot và 128 callable Spark/XStream dựa trên receipt đã có; kiểm tra lại nguồn/AST Batch02 đạt 222/222.
- Spark hoàn tất trong phạm vi external static files đã đo; XStream giữ UNCONFIRMED vì ConversionException/0 callback cả hai bản chưa chứng minh cơ chế advisory. Batch02 hiện 2/10, nhãn 5 VULNERABLE, 4 RESOLVED_TARGET, 213 UNCONFIRMED.
- Gắn receipt theo từng CVE và kiểm tra nhất quán tiêu chí, quyết định nhãn, số lượng và tài liệu; giữ nguyên receipt/intake lịch sử.

## v0.2.0 — 24/11/2026

- Tích hợp nguyên fixture bảo mật từ JavaCVE_Reproducible vào `security` và `all`; giữ riêng API và assertion.
- Thêm list/fetch/build/export/audit/measure/report/split/doctor, run bất biến, log từng bước, thời gian/commit/exit code, replay artifact và retry snapshot lỗi.
- Xác minh lại 10 CVE,126 callable,187 phiên bản; đối chiếu Git/source187/187; tái hiện12 snapshot thuộc6 CVE.
- Tính lại1 ánh xạ sửa hiệu chỉnh,10 cặp chuẩn hóa,60→33 tệp trên9 CVE cùng SHA sửa.
- Thử các cấu hình build cho bốn Jenkins/NiFi và lưu trạng thái bị chặn.
- Chuẩn hóa10 CVE bổ sung/222 phiên bản;1 CVE có build, fixture trước–sau và nhãn có phạm vi; phần chưa xác nhận giữ riêng.
- Thêm báo cáo môn học sinh từ số liệu, hướng dẫn Ubuntu/WSL, từ điển nhãn, nguồn/giấy phép, kiểm thử và GitHub Actions.
- Tạo GitHub repository private, giữ commit gốc và bằng chứng lịch sử.

## v0.1.0

Pilot10, chỉ mục nhãn, kiểm tra API thông thường, bằng chứng WSL và build đối chứng lịch sử. Commit tiếp nhận `55096aa` giữ bản phân phối ban đầu.
