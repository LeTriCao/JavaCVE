# Chẩn đoán XStream CVE-2013-7285 từ receipt hiện có

Người rà soát: **AI**. Kết luận: **chưa xác định được nguyên nhân gốc của ConversionException từ log cũ**. [Chẩn đoán JSON](../data/batch-02/xstream-diagnosis.json) lưu hash, đối chiếu cấu hình/phụ thuộc và bước thử tiếp theo. Không chạy lại Java hoặc payload trong lượt chẩn đoán này.

| Mục | Kết quả đã xác nhận | Bằng chứng / giới hạn |
|---|---|---|
| Exception/callback | ConversionException; 0 callback; control đạt ở cả hai bản | [before log](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/logs/16-security.log), [after log](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/logs/21-security.log). Bản raw cục bộ khớp byte bản công bố; cả hai đều không có message/cause/stack. |
| Vì sao không truy được root cause | catch chỉ in error.getClass().getName(); try bao cả fromXML và run | [Fixture](../fixtures/XStreamLocalProbe.java). Mất thông tin chẩn đoán; không xác định được giai đoạn lỗi từ cờ rejected. |
| Fixture và toolchain | Cùng hash fixture; DomDriver; JDK8u514, Maven3.9.9 | [Receipt](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/run.json). Không có override riêng theo phase được ghi nhận; không phải bản dump đầy đủ môi trường JVM. |
| Dependency | 15/15 đường dẫn, thứ tự và SHA-256 giống nhau; byte cache được kiểm tra lại | Danh sách đầy đủ trong JSON. Không có bằng chứng dependency drift gây lỗi; không chứng minh mọi lớp đã load đúng ở runtime. |
| Artifact | Hai JAR build từ hai source commit, SHA khác nhau; byte local khớp receipt | Không thay bằng JAR phát hành. Classpath đặt probe → XStream JAR → 15 dependency ở cả hai. |
| Source cấu hình | Root/module POM, JVM.java, DomDriver, DynamicProxyConverter giống byte | Hash trước/sau trong JSON. Provider thực sự được chọn chưa được log. |
| Policy | Before không có SecurityMapper; after thêm SecurityMapper với AnyTypePermission.ANY | Fixture không cài allowlist/deny. Không thể coi exception chung là bằng chứng bản vá chặn advisory. |

## Giả thuyết và quyết định bước tiếp

Các giả thuyết về reflection/object construction, mapper/converter/type resolution và proxy/handler chỉ là **chưa xác nhận**. Không có message/cause để chọn một giả thuyết làm nguyên nhân gốc. Giữ UNCONFIRMED ở cả snapshot và callable CVE-2013-7285.

1. Keep existing receipts and fixture immutable; create a separate diagnostic variant with a new hash.
2. Log full exception message/stack/cause chain and stage markers before/after fromXML and callback.run; record actual reflection provider, selected converter/mapper, driver, JDK and classpath.
3. Run identical diagnostic code/input on both verified source-built artifacts with the same dependencies and ordinary string/object controls. Keep default-policy and any explicit-policy experiments separate.
4. Treat unrelated ConversionException as a harness/diagnostic failure, not successful security rejection. Establish successful construction and a harmless callback on before before evaluating mitigation; no shell/network payload is needed.

Hai CVE XStream mới đã được đối chiếu riêng trong [bảng tiêu chí Batch02](BATCH02_REVIEW.md). Fixture EventHandler của năm 2013 không thay thế được chuỗi ContainsFilter của năm 2020 hoặc PriorityQueue/JAX-WS/JAXB/CORBA của năm 2021.
