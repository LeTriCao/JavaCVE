# Rà soát Spark và XStream từ a7e6abd

Người rà soát: **AI**; 0 người đánh giá độc lập. Đối chiếu định nghĩa hiện hành trong [completion.json](../data/batch-02/completion.json); quyết định có cấu trúc ở [completion-review.json](../data/batch-02/completion-review.json). Lượt này dùng receipt có sẵn và chạy lại kiểm tra toàn vẹn nguồn; không chạy fixture bảo mật mới.

| CVE | Điều kiện áp dụng | Before / after | Phạm vi đã chứng minh | Còn thiếu |
|---|---|---|---|---|
| CVE-2016-9177 | HTTP vào externalStaticFileLocation; process đọc được marker ngoài public, trong cây tạm do fixture quản lý | Control PASS/PASS; hai URI mã hóa: 200 + marker → 404; literal /../: 400/400 | Đọc file ngoài external root trước, chặn hai đầu vào đó sau; **hoàn tất theo phạm vi** | Classpath/JAR, symlink, tên sibling cùng prefix chưa đo; đánh giá độc lập còn chờ |
| CVE-2013-7285 | XML không tin cậy → dynamic proxy/EventHandler; cần unmarshal thành công rồi caller gọi method; policy phải ghi rõ | Control PASS/PASS; ConversionException, 0 callback cả hai; assertion PASS/PASS | JAR build được; 27 AliasTest mỗi bản đạt; phép thử hiện tại không chạy được callback | Nguyên nhân exception và giai đoạn lỗi; callback vô hại trên before; cùng input/oracle sau với policy rõ ràng; ánh xạ callable. **Chưa hoàn tất** |

Fixture Spark chỉ tạo/đọc marker trong cây tạm và bind 127.0.0.1. XStream dùng Marker.touch, không chạy shell. Cùng hash fixture trong hai snapshot xác nhận cùng mã tạo đầu vào và cùng oracle; địa chỉ port và thư mục tạm được tạo riêng mỗi lần.

## CVE-2016-9177

| Tiêu chí hiện hành | Bằng chứng | Đạt/chưa đạt | Lý do |
|---|---|---|---|
| Source identity | [run.json](../evidence/v0.2.0/2dc3374df54a4ed5b04e2894f1cb59f6/run.json) | Đạt | Pinned commits/trees and selected first parent match Git; source files unchanged in the build receipt. |
| Extraction | [run.json](../evidence/v0.2.0/2dc3374df54a4ed5b04e2894f1cb59f6/run.json) | Đạt | Source audit verifies Git blobs, line ranges, SHA256 and AST names/boundaries for all 222 batch callable versions. |
| Advisory and patch context | [CVE-2016-9177.json](../data/batch-02/advisories/CVE-2016-9177.json), [bản vá](https://github.com/perwendel/spark/commit/efcb46c710e3f56805b9257a63d1306882f4faf9) | Đạt | External-resource traversal matches the advisory and added guard. |
| Scoped AI method review | [reviews.jsonl](../data/batch-02/reviews.jsonl), [snapshot-reviews.jsonl](../data/batch-02/snapshot-reviews.jsonl) | Đạt | Every indexed callable version in this CVE has an AI decision, caller scope and missing-evidence reason; UNCONFIRMED is retained where needed. |
| Paired source builds | [run.json](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/run.json), [6-security.log](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/logs/6-security.log), [11-security.log](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/logs/11-security.log) | Đạt | Both pinned source builds PASS; JAR hashes, commands, exit codes and original-source integrity are in the receipt. |
| Ordinary controls | [run.json](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/run.json), [6-security.log](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/logs/6-security.log), [11-security.log](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/logs/11-security.log) | Đạt | Same fixture bytes and oracle in both snapshots; ordinary_static_file PASS/PASS. |
| Reviewed paired security behavior | [run.json](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/run.json), [6-security.log](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/logs/6-security.log), [11-security.log](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/logs/11-security.log) | Đạt | Two encoded traversal cases return the outside marker before and 404 after; literal /../ returns 400 on both and does not demonstrate a regression. |

Phạm vi nhãn: Pinned Spark snapshots on Linux/JDK8, externalStaticFileLocation(public), an HTTP caller supplying /..%5coutside.txt or /%2e%2e%5coutside.txt, and a process-readable sibling marker outside public. Before returns 200 with the marker; after returns 404. Only this external-file caller path is established. Classpath/JAR resources, symlinks and sibling names sharing the public prefix are unmeasured.

## CVE-2013-7285

| Tiêu chí hiện hành | Bằng chứng | Đạt/chưa đạt | Lý do |
|---|---|---|---|
| Source identity | [run.json](../evidence/v0.2.0/2dc3374df54a4ed5b04e2894f1cb59f6/run.json) | Đạt | Pinned commits/trees and selected first parent match Git; source files unchanged in the build receipt. |
| Extraction | [run.json](../evidence/v0.2.0/2dc3374df54a4ed5b04e2894f1cb59f6/run.json) | Đạt | Source audit verifies Git blobs, line ranges, SHA256 and AST names/boundaries for all 222 batch callable versions. |
| Advisory and patch context | [CVE-2013-7285.json](../data/batch-02/advisories/CVE-2013-7285.json), [bản vá](https://github.com/x-stream/xstream/commit/6344867dce6767af7d0fe34fb393271a6456672d) | Đạt | Advisory requires successful unmarshal plus a later proxy method call; the patch adds permission APIs with an allow-all default. No default mitigation is inferred. |
| Scoped AI method review | [reviews.jsonl](../data/batch-02/reviews.jsonl), [snapshot-reviews.jsonl](../data/batch-02/snapshot-reviews.jsonl) | Đạt | Every indexed callable version in this CVE has an AI decision, caller scope and missing-evidence reason; UNCONFIRMED is retained where needed. |
| Paired source builds | [run.json](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/run.json), [16-security.log](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/logs/16-security.log), [21-security.log](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/logs/21-security.log) | Đạt | Both pinned source builds PASS; JAR hashes, commands, exit codes and original-source integrity are in the receipt. |
| Ordinary controls | [run.json](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/run.json), [16-security.log](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/logs/16-security.log), [21-security.log](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/logs/21-security.log) | Đạt | Same fixture bytes and oracle in both snapshots; string_roundtrip PASS/PASS. AliasTest: 27 tests per snapshot, zero failures/errors/skips; functional evidence only. |
| Reviewed paired security behavior | [run.json](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/run.json), [16-security.log](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/logs/16-security.log), [21-security.log](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/logs/21-security.log) | Chưa đạt | Assertion PASS/PASS means only that an XStreamException occurred and callbacks stayed zero. ConversionException cause is absent; this is not evidence of advisory mitigation. A bounded fixture must first demonstrate successful proxy construction and a harmless callback on before, record the exception cause and conversion stage, then evaluate the same input/oracle on after with any security configuration stated explicitly and ordinary controls passing. The pinned patch's setupSecurity adds AnyTypePermission.ANY; new permission APIs alone do not prove default rejection. Map the result to the actual caller and affected callable. No shell execution is needed. Version 1.4.10, JSON and other gadget chains are outside this pair. |

Phạm vi nhãn: Pinned XStream snapshots, DomDriver, default XStream configuration, untrusted XML requesting a Runnable dynamic proxy with java.beans.EventHandler and a harmless Marker.touch target; the caller would invoke run() only after successful unmarshalling. Both logs show ConversionException and zero callbacks. No root cause or successful proxy construction is recorded. This does not establish advisory callback execution or its prevention by the patch.

## Diễn giải và giới hạn

Bản vá Spark thêm guard ở ExternalResourceHandler.getResource và bắt DirectoryTraversalDetection ở StaticFilesConfiguration.consume. consumeWithFileResourceHandlers chỉ đổi khoảng trắng; nhãn của callable này phụ thuộc handler và caller, không phải thuộc tính an toàn độc lập. Guard external mới cũng chỉ được xác nhận cùng cấu hình StaticFilesFolder.external. Các callable classpath/JAR, cấu hình và helper không đủ bằng chứng riêng vẫn UNCONFIRMED.

XStreamLocalProbe coi mọi XStreamException kèm 0 callback là assertion đạt. Log chỉ ghi tên ConversionException, không ghi message/cause hay giai đoạn; do đó không thể xác định lỗi do type policy, dựng object hay mapper. Bản vá được ghim thêm SecurityMapper và setupSecurity với AnyTypePermission.ANY. Không suy ra cấu hình mặc định đã từ chối EventHandler. 68 phiên bản callable XStream và hai snapshot giữ UNCONFIRMED; việc rà soát xong một tiêu chí không làm cả hồ sơ hoàn tất.

Advisory chính thức mô tả cần caller gọi method trên proxy sau unmarshalling: [XStream CVE-2013-7285](https://x-stream.github.io/CVE-2013-7285.html). Nguồn Spark: [issue #700](https://github.com/perwendel/spark/issues/700). Bản vá, advisory JSON lưu trong repo và hành vi được đối chiếu cho đúng cặp commit; không mở rộng sang XStream 1.4.10 hay mọi đầu vào/formats.

Upstream tests là bằng chứng chức năng hỗ trợ, không phải điều kiện thay thế paired security behavior. Đánh giá độc lập còn chờ được theo dõi riêng theo định nghĩa hiện hành. Receipt CI success ghi trong BUILD_RECOVERY.md chỉ xác nhận lệnh/job chạy đạt, không tự chứng minh fixture phân biệt được lỗi. Trạng thái Batch02 hiện là **2/10**, không phải 3/10.

Danh sách đầy đủ từng callable: [BATCH02_CALLABLE_REVIEW.md](BATCH02_CALLABLE_REVIEW.md); [quyết định snapshot](../data/batch-02/snapshot-reviews.jsonl); [quyết định callable](../data/batch-02/reviews.jsonl). Intake summary.json giữ nguyên trạng thái lúc nhập; completion.json là trạng thái sau rà soát.
