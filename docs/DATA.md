# Từ điển dữ liệu

Khóa chính đi từ `cve_id` đến `file_id`, `record_id` và `sample_id`. `record_id` định danh phương thức trong cặp phiên bản. `sample_id` có thêm phía `before` hoặc `after`. Phương thức mới thêm hoặc đã xóa chỉ có bản ghi ở phía tồn tại. Trong 252 vị trí theo cặp có 65 vị trí vắng mặt. Phạm vi dòng bắt đầu từ 1, bao gồm dòng kết thúc. Chữ ký là kết quả phân tích cú pháp Java, chưa phân giải kiểu theo JVM.

| Trường | Diễn giải |
|---|---|
| `seed_commit`, `seed_fix_commits` | Mốc do bộ nguồn công bố |
| `before_commit`, `after_commit` | Cha được chọn và commit sửa dùng để so sánh |
| `before_tree`, `after_tree` | Git tree dùng kiểm tra nội dung cả phiên bản |
| `provenance`, `selected_parent_index` | Nguồn lịch sử và chỉ số cha, cha thứ nhất ứng với 0 |
| `before_blob`, `after_blob` | Mã Git của nội dung tệp. `null` cho phía vắng mặt |
| `code_sha256` | SHA-256 của đoạn mã gốc được trích, bỏ khoảng trắng ngoài hai đầu đoạn theo quy tắc của bộ thí điểm |
| `token_hash` | Dấu vân tay token từ bước chuẩn hóa, dùng phát hiện nội dung trùng |
| `rule_id`, `unknown_reason_group` | Quy tắc gán nhãn và lý do giữ chưa xác nhận |
| `requires_context`, `is_test`, `split` | Cần xét ngữ cảnh, thuộc mã kiểm thử, và thuộc tập thí điểm |

## Ghép với mã nguồn

Nếu đã có dữ liệu bước 3, đường dẫn cho `verify-source` là thư mục `cases` có các thư mục con mang mã CVE và hai thư mục `before`, `after`.

Một người dùng mới có thể dùng kho Git cục bộ. Đặt mỗi kho vào một thư mục con mang tên `cve_id` dưới một thư mục chung, với hai commit trong `data/cases.jsonl` có sẵn trong kho. Trường `repository_url` chỉ đúng kho cho từng trường hợp, kể cả lịch sử tái dựng của zip4j. Chạy `python3 run.py verify-source ../repos --git-repos --export methods-local.jsonl`. Công cụ đọc đối tượng Git và chỉ tạo tệp xuất khi các phiên bản hiện diện đều khớp băm. Nếu chỉ cần đối chiếu, bỏ đối số `--export`.

## Dùng cho nghiên cứu

Thống kê theo CVE, phương thức và phiên bản trả lời ba câu hỏi khác nhau. Hai phiên bản của một phương thức có liên hệ với nhau. Khi mở rộng thành tập huấn luyện, cần chia theo dự án hoặc CVE và kiểm tra trùng token giữa các tập. Bản thí điểm giữ `pilot_only`. Trong 187 mẫu có 165 dấu vân tay token phân biệt. Con số này chưa cho biết có bao nhiêu cơ chế lỗi độc lập.

`RESOLVED_TARGET` chỉ nói đến cơ chế đang xét. Các mẫu `UNCONFIRMED` được giữ khi mã là thay đổi hỗ trợ, nằm ngoài phạm vi đã xét hoặc cần thêm ngữ cảnh. Thời gian lao động của người gán nhãn chưa được đo đủ cho từng CVE.

## Nhóm quy tắc phương thức

| Mã | Phạm vi quyết định |
|---|---|
| M00 | Thay đổi không đủ bằng chứng để gán nhãn ở cấp phương thức |
| M01 | Nhánh xử lý đường dẫn của bốn thư viện lưu trữ đã khảo sát |
| M02 | Hành vi chuẩn hóa đường dẫn trong Commons IO |
| M03 | Xử lý thành phần lệnh trong Plexus Utils, theo ngữ cảnh đã ghi |
| M04 / M04X | Các điểm gọi Git Client trong advisory / phần mở rộng ngoài phạm vi |
| M05 | Vị trí thực thi trên controller hoặc agent trong Perfecto |
| M06 | Bằng chứng ở lớp kiểm tra dữ liệu của Docker Commons |
| M07 / M07X | Phần tra cứu của provider NiFi / các nhánh cần ngữ cảnh bổ sung |

Trường `evidence_sets` xác định đích danh CVE nào xuất hiện trong từng tập bằng chứng lịch sử, đối chứng hoặc bản phát hành. Một hồ sơ mới có thể có chỉ mục nguồn và nhãn trước khi có bằng chứng build. Bổ sung hồ sơ mới không làm thay đổi mẫu số lịch sử.
