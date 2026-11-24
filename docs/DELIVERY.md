# Bàn giao v0.2.0

Repository private: https://github.com/LeTriCao/JavaCVE. Tag/release: v0.2.0. Dùng `git rev-parse 'v0.2.0^{}'` để lấy SHA phát hành; bản release ghi cùng commit và có ZIP, SHA256SUMS, báo cáo DOCX.

## Sản phẩm

- Chỉ mục pilot: data/cases.jsonl, files.jsonl, methods.jsonl, versions.jsonl, pairs.jsonl và reviews.jsonl.
- Batch mở rộng tách riêng tại data/batch-02; completion.json và build-status.json ghi phần hoàn tất/bị chặn.
- Công cụ tải/build/API/bảo mật/export/audit/report cùng ví dụ tại README.md và INSTALL.md.
- [Bảng cải tiến tính lại](generated/metrics.json), [CSV hồ sơ](generated/cases.csv), [báo cáo môn học](generated/REPORT.md), [bản Word](generated/COURSE_REPORT.docx).
- [Bốn Jenkins/NiFi và các lượt đã thử](EXPERIMENTS.md), [chín hồ sơ batch02 chưa đủ bằng chứng](BATCH02.md), [quy tắc nhãn](LABELS.md).
- [Phân hoạch dự án](generated/split-project/summary.json):409 phiên bản,376 hash token chung phân biệt;0 trùng token chính xác băng qua tập. Train376/validation8/test25 là số phiên bản, không phải số CVE; tỷ lệ lệch do gộp dự án/trùng mã và mẫu nhỏ.

Tập pilot có6/10 CVE hoàn tất build và phép thử hành vi;4 hệ thống còn thiếu tích hợp. Batch02 có1/10 CVE hoàn tất theo định nghĩa đã công bố.10/10 hồ sơ mới đều có nguồn và trích xuất nhưng không gọi toàn bộ là đã kiểm chứng bảo mật. Các quyết định rà soát mới do AI thực hiện, chưa có đánh giá độc lập của con người.

## Tính lại bảng báo cáo đã công bố

Chạy từ thư mục gốc của bản clone hoặc gói giải nén, không cần source/cache để tính lại các bảng từ receipt:

```bash
python3 run.py report --run evidence/v0.2.0/5cd2e8809e084ef1bb9530b2f00f8722 --run evidence/v0.2.0/b6499a16a26c41729ae28ce8f19d701b --run evidence/v0.2.0/ed97b42890524847a80085211e91b217 --run evidence/v0.2.0/b33dd5b053464df19b1f31900f82c68f
```

Để tạo bằng chứng mới từ Git, xem lệnh fetch/measure/audit/all trong INSTALL.md. Receipt công bố đã che đường dẫn máy cá nhân; JAR/dependency không phân phối cùng gói, nên replay artifact dùng run được tạo trên máy đang sử dụng.

## Demo ngắn trước giảng viên

```bash
python3 run.py demo
python3 run.py list --cwe CWE-22
python3 run.py all --cve CVE-2021-29425
python3 run.py list --batch data/batch-02
```

Hai lệnh đầu chạy ngoại tuyến; lệnh build cần mạng lần đầu. Chuẩn bị một lượt all trước buổi trình bày, rồi `python3 run.py security --from-run runs/ID_ALL --cve CVE-2021-29425` để chạy lại fixture từ artifact tự build đã xác minh hash.

## Đã kiểm tra cách cài đặt

Bản clone GitHub ở commit b09707e đã chạy đủ demo/tests/list/report/split và build+security Commons IO trong thư mục tạm/cache mới; receipt tại evidence/v0.2.0/fresh-clone-b09707e.json. Các commit sau bổ sung kiểm tra phát hành, AST, tài liệu và trường trạng thái; workflow GitHub kiểm tra lại trên commit được push. Gói ZIP và commit tag được kiểm tra riêng trong bước phát hành, kết quả kèm asset verification.json nếu được tạo.

Không đo thời gian lao động gán nhãn, độ chính xác mô hình hay độ đồng thuận giữa hai người. Đường hướng luận văn ở METHODOLOGY.md và báo cáo môn học.
