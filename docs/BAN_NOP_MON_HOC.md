# Chốt gói nộp v2 — chứng minh cải thiện IRIS

Bản bàn giao cuối dùng commit nền a1ea91f12cb78d2828e97c055ff6c18481107759. Để dùng ZIP bổ sung, giải nén vào một bản sao sạch của commit nền, cho phép ghi đè. Checkout trực tiếp commit bàn giao trên GitHub có đủ cây tệp. Bốn lệnh demo nằm trong docs/DEMO_5_PHUT.md.

Gói v2 dùng snapshot công việc hiện tại và hai tệp HEAD: .github/workflows/verify.yml, tools/github.ps1; phần Plexus CI sửa dở được giữ ở workspace, không đưa vào gói. Không tạo commit/tag/release mới. Manifest của gói được tạo lại trên đúng bộ tệp; manifest gốc giữ nguyên để không hợp thức hóa sửa dở ngoài phạm vi.

Kết quả: 20 CVE, 409 phiên bản phương thức, 14 cặp build, 8 C1–C7, 342 UNCONFIRMED. Primary 9 CVE 60→33; mở rộng 10 CVE 62→35. Đây là Git changed-path từ seed, không phải số mẫu IRIS đã gán nhãn; giữ 25/25 anchor file Java IRIS và một test SECURITY-1534 làm context riêng.

Đọc docs/SO_SANH_IRIS_JAVACVE.md, docs/BAO_CAO_MON_HOC.docx và docs/DEMO_5_PHUT.md. Phiếu người rà ở docs/review; baseline riêng ở docs/review_coordinator. Chỉ gửi ZIP người rà, không gửi toàn bộ gói dataset/baseline trước quyết định độc lập. Chưa có phiếu hoàn tất hợp lệ; PENDING, không có tỷ lệ đồng thuận.

Quy trình yêu cầu unit test, nguồn/AST, tái tính so sánh từ Git, C1–C7 và demo đều đạt trước đóng gói; diễn tập bốn lệnh demo từ ZIP giải nén mới và kiểm tra lại ZIP cuối. Kết quả, môi trường, thời gian thực tế và hạn chế trong verification/VERIFICATION.json và FINAL_VERIFICATION.json đi kèm. Source/AST cần Git cache/parser ngoài gói, không được đóng gói; Git lazy fetch tắt. Không có thử trên máy khác hoặc buổi trình bày người thật đủ 300 giây.

Các bản ghi 34 test/415/501/508 tệp là lịch sử. Danh sách gói mới là SUBMISSION_FILES.json; các tệp candidate trước là lịch sử. Gói cũ giữ nguyên. Mục tiêu 12/20 chờ giảng viên; người rà thật, thông tin bài nộp và thử trên máy chấm còn cần thực hiện.
