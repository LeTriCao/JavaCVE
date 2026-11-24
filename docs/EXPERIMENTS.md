# Thử nghiệm Jenkins/NiFi và can thiệp môi trường

Các trạng thái dưới đây được sinh từ receipt đã công bố. Không sửa mã production và không thay JAR phát hành vào chỗ build lỗi. Cả bốn hồ sơ đã có source Git và kiểm tra phương thức; chưa có bằng chứng tích hợp toàn hệ thống.

| CVE | Lượt 1: khai báo HTTPS/180s | Lượt 2: offline + Jenkins HTTPS/60s | Lượt 3: retry + Jenkins HTTPS/90s |
|---|---|---|---|
| CVE-2019-10392 | before: FAIL / TIMEOUT; after: FAIL / TIMEOUT | before: FAIL / DEPENDENCY; after: FAIL / DEPENDENCY | before: FAIL / TIMEOUT; after: FAIL / TIMEOUT |
| CVE-2020-2261 | before: FAIL / TIMEOUT; after: FAIL / TIMEOUT | before: FAIL / DEPENDENCY; after: FAIL / DEPENDENCY | before: FAIL / TIMEOUT; after: FAIL / TIMEOUT |
| CVE-2022-20617 | before: FAIL / TIMEOUT; after: FAIL / TIMEOUT | before: FAIL / DEPENDENCY; after: FAIL / DEPENDENCY | before: FAIL / TIMEOUT; after: FAIL / TIMEOUT |
| CVE-2022-33140 | before: FAIL / TIMEOUT; after: FAIL / TIMEOUT | before: FAIL / TIMEOUT; after: FAIL / TIMEOUT | before: FAIL / TIMEOUT; after: FAIL / TIMEOUT |

Lượt 1 chạy profile package. Lượt 2 xác định cache chưa dùng được theo repository ID hiện tại: Git Client thiếu parent plugin3.49, Perfecto plugin4.0, Docker Commons plugin4.2 khi offline. Đây không chứng minh upstream đã xóa các artifact. Lượt 3 thêm kho Jenkins HTTPS, giới hạn connect/read, giữ riêng retry_of; vẫn hết thời gian ở đồ thị parent/plugin/phụ thuộc. Kiểm tra HTTPS bằng Python truy cập được Central và Jenkins; không gọi timeout Java/Maven là mất mạng toàn máy.

NiFi đã đọc reactor41 mô-đun cho shell-authorizer nhưng dừng ở phạm vi thời gian thử nghiệm. Chưa build riêng Registry framework và chưa dựng mock command/provider hai hệ thống. Những cấu hình nới enforcer/skipTests được ghi trong lệnh; chúng không tạo bằng chứng tích hợp.

Phần cần tiếp tục: lưu cache Maven đầy đủ và định danh dependency/plugin, thử ngân sách build dài hơn trong runner chuyên dụng, dựng Jenkins controller/agent harness, DockerRegistryEndpoint caller-path tests và mock OS commands cho cả hai mô-đun NiFi. Không đổi nhãn UNCONFIRMED của Docker Commons vì chỉ có build hoặc thay đổi guard.

## Can thiệp đã ghi

- Chuyển từ Python Windows thiếu encodings sang Ubuntu WSL; không sửa Python hệ thống.
- Dùng JDK8u514/Maven3.9.9 khóa phiên bản; thêm mirror HTTPS cho repository Jenkins lịch sử.
- Thử package có bỏ upstream tests/checkstyle/RAT/enforcer theo profile, sau đó thử cache ngoại tuyến và retry mạng có timeout cụ thể.
- Dùng Tree-sitter wheel có SHA256 đặt trong cache riêng vì WSL thiếu pip.
- Chỉ định tài khoản LeTriCao khi clone private vì máy lưu nhiều tài khoản GitHub.

Các can thiệp này chưa được đo thời gian lao động đầy đủ. Thời gian subprocess được lưu trong từng receipt; không tính chúng thành thời gian gán nhãn hay kết luận tiết kiệm lao động.

## Nguồn bằng chứng

- [2db8826fb83749229df01b3b30db9ead](../evidence/v0.2.0/2db8826fb83749229df01b3b30db9ead/run.json), repository policy `not_recorded_in_first_attempt`.
- [ad128fead9184743b58b027a65ee6192](../evidence/v0.2.0/ad128fead9184743b58b027a65ee6192/run.json), repository policy `central_and_jenkins_https`.
- [aab27812edb14b81912ac90b458e48e5](../evidence/v0.2.0/aab27812edb14b81912ac90b458e48e5/run.json), repository policy `central_and_jenkins_https`.
