# Điều kiện áp dụng nhãn

| Nhãn | Điều kiện | Phần không được suy ra |
|---|---|---|
| VULNERABLE | Mã tham gia cơ chế CVE, dưới điều kiện nguồn vào/caller/quyền đã ghi, có bằng chứng tĩnh hoặc hành vi phù hợp | Mọi caller đều khai thác được |
| RESOLVED_TARGET | Thay đổi và bằng chứng hỗ trợ xử lý cơ chế mục tiêu trong phạm vi hồ sơ | SAFE tổng quát hoặc không còn lỗ hổng khác |
| UNCONFIRMED | Ngoài phạm vi gán nhãn, thiếu ngữ cảnh/caller, hoặc thiếu bằng chứng hành vi/ngữ nghĩa | Mẫu âm an toàn |

Pilot giữ các rule M00..M07X trong DATA.md, quyết định snapshot ở reviews.jsonl và điều kiện đầu vào cụ thể ở `evidence/inputs/case_annotations-step2.json`. Export nối cả scope của snapshot, repository, advisory, revision và nguồn bằng chứng. Snapshot label và callable label có thể khác: một hàm hỗ trợ không tự động nhận nhãn của cả CVE.

Các thư viện ZIP đòi hỏi ứng dụng giải nén dữ liệu không tin cậy vào đích có quyền ghi. Commons IO xét đường chuẩn hóa prefix cụ thể, chưa chứng minh mọi caller có thể bị tác động. Plexus Utils xét thành phần executable/path trong ngữ cảnh shell đã thử. Jenkins đòi hỏi xét controller/agent, cách truyền đối số, quyền và điểm gọi. NiFi đòi hỏi xét provider, cấu hình, hệ điều hành và mô-đun tương ứng.

129 phiên bản UNCONFIRMED của pilot giữ lý do gốc: 117 ngoài diện gán nhãn mục tiêu, 8 cần thêm ngữ cảnh, 4 là mở rộng ngoài phạm vi công bố. `audit` xuất unconfirmed.json với từng sample_id, nhóm lý do, scope và bằng chứng cần bổ sung. Chưa có người đánh giá độc lập; mọi kết quả rà soát mới ghi reviewer=AI.

Batch02 dùng `B02_PENDING` cho mẫu chưa đủ điều kiện. Riêng `B02_EXPAND_BOUNDARY` áp dụng đúng `Expand.extractFile` của CVE-2022-4244: trước ghi được parent traversal, sau chặn ca chính nhưng vẫn ghi ngoài khi thư mục ngoài có cùng tiền tố tên đích. Cả hai phiên bản giữ VULNERABLE dưới điều kiện đó. Quyết định và hash fixture nằm ở `data/batch-02/reviews.jsonl`; không tự lan nhãn sang phương thức khác.

`B02_SPARK_EXTERNAL_CONTEXT` chỉ áp dụng đường gọi external static files trong fixture CVE-2016-9177: ba callable trước VULNERABLE, ba callable tương ứng sau và guard external mới RESOLVED_TARGET. Hai consumer chỉ được xác nhận khi dùng ExternalResourceHandler và cấu hình trong fixture; guard đòi hỏi StaticFilesFolder.external khớp thư mục public. `consumeWithFileResourceHandlers` chỉ đổi khoảng trắng trong patch, nên khác biệt hành vi thuộc ngữ cảnh handler. Không suy nhãn an toàn độc lập cho consumer/guard, không lan sang classpath/JAR hay helper.

68 phiên bản callable CVE-2013-7285 giữ UNCONFIRMED với lý do `XSTREAM_CALLER_BEHAVIOR_MISSING` hoặc `TEST_OUTSIDE_TARGET`. Fixture bắt mọi XStreamException; ConversionException và 0 callback ở cả hai bản chưa chứng minh cơ chế advisory. Các API permission mới cần policy và caller cụ thể; setupSecurity của commit được ghim vẫn thêm AnyTypePermission.ANY. Xem [bảng rà soát](BATCH02_REVIEW.md) và [từng callable](BATCH02_CALLABLE_REVIEW.md).

CVE-2020-26217 có 14 phiên bản callable và CVE-2021-21345 có 9 phiên bản; tất cả giữ UNCONFIRMED. `XSTREAM_DEFAULT_POLICY_CONTEXT_MISSING` ghi nhận thiếu hành vi paired/caller/policy cho callable production; `TEST_OUTSIDE_TARGET` giữ test ngoài nhãn mục tiêu. Thay đổi blacklist trong setupSecurity được xác minh tĩnh, nhưng thiếu control chung và bằng chứng đúng chuỗi advisory. Hai callable setupMappers/unmarshal của bản vá 2021 chỉ đổi định dạng/thông báo tại vị trí được trích; không lan nhãn từ setupSecurity. Các test ByteArrayInputStream không đủ chứng minh chuỗi RCE của CVE-2021-21345.
