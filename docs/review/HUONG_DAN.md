# Phiếu dành riêng cho người rà — không kèm nhãn hiện tại

Trạng thái PENDING. Người rà: ____________________ · Ngày: ____________________.

Chỉ chuyển thư mục/ZIP người rà này cho người rà độc lập; không chuyển thư mục review_coordinator, data/versions.jsonl hoặc báo cáo kết luận AI trước khi họ ghi quyết định. Phiếu giữ nguyên 40 sample_id đã chọn, phủ đủ 20 CVE; quyết định, tên, ngày, lý do và bằng chứng kiểm tra đang để trống. Không coi phiếu trống là một lượt rà hoàn tất.

1. Mở PHIEU_RA_SOAT_NHAN.csv hoặc bản Word. EVIDENCE_REFERENCES.json cung cấp advisory, ba SHA, chữ ký cú pháp, tệp/khoảng dòng/hash và các log đo thực tế. Log là quan sát để đọc, không phải câu trả lời về nhãn. Không có cột nhãn hiện tại hoặc lý do quyết định AI trong bản này.
2. Đọc source từ URL công khai hoặc Git cache đã có. Ví dụ: git -C <cache>/<CVE> show <commit>:<file>. Xem cả bản trước/sau, caller, điều kiện đầu vào/quyền và phạm vi advisory. SHA-256 trong phiếu là đoạn mã theo quy tắc cắt khoảng dòng rồi strip; không phải băm toàn tệp. Phương thức thêm/xóa chỉ có phía hiện diện.
3. Quyết định cho đúng phiên bản phương thức: VULNERABLE khi bằng chứng hỗ trợ cơ chế mục tiêu theo điều kiện ghi rõ; RESOLVED_TARGET khi xử lý cơ chế đó trong phạm vi đã kiểm chứng, không có nghĩa SAFE tổng quát; UNCONFIRMED khi thiếu ngữ cảnh/bằng chứng hoặc ngoài diện gán nhãn. Không tự lấy nhãn của cả CVE cho mọi helper/test. Build, băm hoặc test bình thường đạt chưa đủ kết luận nhãn bảo mật.
4. Điền reviewer_name, review_date dạng YYYY-MM-DD, reviewer_decision, reason, evidence_checked. Chỉ đổi review_status thành COMPLETED cho dòng đã rà xong. Khi chưa truy cập được nguồn, để dòng PENDING; không đoán nhãn. UNCONFIRMED là quyết định hợp lệ sau khi rà và nêu lý do.
5. Trả một bản CSV mới có tên riêng; không sửa trực tiếp dữ liệu gốc. Điều phối viên sẽ kiểm tra định danh, đếm mẫu hợp lệ và đối chiếu bảng baseline lưu riêng. Mẫu được chọn có chủ đích, không dùng tỷ lệ đồng thuận của mẫu này làm độ chính xác cho toàn bộ 409 mẫu.

Bản này chỉ gồm tham chiếu và log; không đóng gói toàn bộ source bên thứ ba. Cần mạng để đọc URL hoặc người chuẩn bị cung cấp đúng Git cache theo giấy phép. Phiếu không yêu cầu chạy fixture CVE. Chưa có lượt chạy trên máy khác hay chữ ký người rà được xác nhận.
