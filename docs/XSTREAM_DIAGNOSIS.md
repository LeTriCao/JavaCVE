# Chẩn đoán XStream CVE-2013-7285

**Cả hai snapshot dừng trong `XStream.fromXML` khi tra cứu converter.** JVM ghi `ConversionException` với thông điệp `No converter specified for class java.beans.EventHandler`. Frame đầu tiên của exception là `DefaultConverterLookup.lookupConverterForType`. Chuỗi cause chỉ chứa chính exception đó. Đối chứng chuỗi đã đạt trước khi lỗi xuất hiện. Người rà soát là **AI**. [Receipt chẩn đoán](../evidence/v0.2.0/a4e197b267ca44baa4896be94b9f65b5/run.json) · [Kết luận có cấu trúc](../data/batch-02/xstream-diagnosis.json).

| Phép đo | Before · `64533f1` | After · `6344867` |
|---|---|---|
| Đối chứng `string_roundtrip` | PASS | PASS |
| Giai đoạn phát sinh exception | `PROXY_FROM_XML` | `PROXY_FROM_XML` |
| Cause lồng bên trong | 0 | 0 |
| Fixture nhận được proxy | Không | Không |
| Đã thử gọi callback / số callback quan sát | Không / 0 | Không / 0 |
| Kết luận về hành vi advisory | UNCONFIRMED | UNCONFIRMED |
| Message đầy đủ, cause, stack trace và classpath từ JVM | [Log before](../evidence/v0.2.0/a4e197b267ca44baa4896be94b9f65b5/logs/2-diagnostic.log) | [Log after](../evidence/v0.2.0/a4e197b267ca44baa4896be94b9f65b5/logs/4-diagnostic.log) |

### So sánh với lần trước

Receipt ban đầu ghi loại exception và số callback. Lượt chẩn đoán dùng bản fixture bổ sung ghi log, cùng nội dung XML và hai assertion ban đầu. Receipt liên kết bằng `diagnostic_of` và SHA-256 của **receipt gốc trước khi ẩn đường dẫn**. Giá trị này khớp `original_run_sha256` trong receipt công bố lần trước. Hai hash fixture và hash đầu vào được lưu riêng. [Receipt lần trước](../evidence/v0.2.0/4063ba008c3644f5ad4d015ccd4cbcc4/run.json) · [Receipt chẩn đoán](../evidence/v0.2.0/a4e197b267ca44baa4896be94b9f65b5/run.json).

Cả hai JVM báo Temurin `1.8.0_514-b01`, cùng `DomDriver`, `SunUnsafeReflectionProvider` và `CachingMapper`. Classpath có 17 mục theo thứ tự gồm thư mục lớp fixture theo phase, JAR của commit tương ứng và 15 dependency. Tên, thứ tự và SHA-256 của 15 dependency trùng với lần trước. Hai JAR có SHA-256 riêng khớp với JAR đã build từ từng commit. Lượt chẩn đoán tái sử dụng cả hai JAR. [Phiên bản Java](../evidence/v0.2.0/a4e197b267ca44baa4896be94b9f65b5/logs/0-java-version.log) · [Đối chiếu cấu hình, POM và dependency](../data/batch-02/xstream-diagnosis.json).

Fixture dùng cấu hình mặc định của từng snapshot. Hai phiên bản có cấu hình quyền khác nhau trong source. Stack trace xác định lỗi trực tiếp khi chuyển đổi dữ liệu. Lỗi xuất hiện trước khi caller nhận được đối tượng, nên phép đo này chưa cho biết bản vá ảnh hưởng ra sao đến hành vi của caller.

<details>
<summary>Phần ghi log exception của fixture trong receipt</summary>

Biến `stage` lưu giai đoạn hiện tại. JVM ghi `java.version`, `java.runtime.version`, `java.vendor`, `java.vm.name`, `java.home` và `java.class.path` bằng `System.getProperty` trước khi bắt đầu đối chứng. Đây là hàm ghi exception của bản fixture có SHA-256 trong receipt.

```java
private static void exception(Throwable error) {
    System.out.println("EXCEPTION_STAGE=" + stage);
    System.out.println("EXCEPTION_CLASS=" + error.getClass().getName());
    System.out.println("EXCEPTION_MESSAGE_BEGIN");
    System.out.println(error.getMessage());
    System.out.println("EXCEPTION_MESSAGE_END");
    IdentityHashMap<Throwable, Boolean> seen = new IdentityHashMap<Throwable, Boolean>();
    Throwable cause = error;
    int index = 0;
    while (cause != null && !seen.containsKey(cause)) {
        seen.put(cause, Boolean.TRUE);
        System.out.println("CAUSE_" + index + "_CLASS=" + cause.getClass().getName());
        System.out.println("CAUSE_" + index + "_MESSAGE=" + cause.getMessage());
        cause = cause.getCause();
        index++;
    }
    if (cause != null) System.out.println("CAUSE_CYCLE=true");
    System.out.println("STACK_TRACE_BEGIN");
    error.printStackTrace(System.out);
    System.out.println("STACK_TRACE_END");
}
```

</details>

Bản nguồn đầy đủ của biến thể đã chạy được lưu cùng run cục bộ. Bản công bố gồm phần ghi log ở trên, SHA-256, receipt và hai log JVM để kiểm tra ngoại tuyến.

### Quyết định hoàn tất

Sáu trong bảy tiêu chí đạt. Tiêu chí `paired_security_behavior` còn thiếu quan sát hành vi thuộc advisory trên cùng điều kiện gọi và căn cứ quy hành vi đó cho callable. Assertion cũ trả về `true` ở cả hai bản chỉ vì có exception và số callback bằng 0. Hai snapshot cùng 68 phiên bản callable giữ **UNCONFIRMED**. Bước tiếp theo là đối chiếu bằng chứng hồi quy có sẵn của upstream với hai commit và ngữ cảnh gọi đã ghi. [Bảng từng tiêu chí](BATCH02_REVIEW.md) · [Quyết định từng callable](BATCH02_CALLABLE_REVIEW.md).
