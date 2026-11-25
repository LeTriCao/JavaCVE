# Phương pháp chuẩn hóa và đo cải tiến

## Cách đọc kết quả bàn giao

Sổ kiểm kê có 20 CVE phân biệt. Đếm một cặp build khi cả hai phía của **cùng một CVE** khớp commit trong chỉ mục và bước build từ nguồn đạt. Một lần thử lỗi, một lượt retry hoặc hai JAR của cùng một phía không làm tăng số cặp. Với Batch02, tra `build_run_id` trong sổ build để lấy receipt của từng phát biểu. Với pilot, đối chiếu mười hai snapshot trong receipt đã chọn. [Receipt pilot](../evidence/v0.2.0/5cd2e8809e084ef1bb9530b2f00f8722/run.json) · [Sổ build Batch02](../data/batch-02/build-status.json)

Các chỉ số hành vi Pilot và quyết định `fully_completed` của Batch02 được giữ làm lịch sử theo lô. Lượt nghiệm thu hiện tại rà lại toàn bộ 20 CVE theo cùng C1–C7 bên dưới, ghi nhận **8/20 đạt chuẩn chung**. Hồ sơ có thể đạt chuẩn trong phạm vi công bố và vẫn còn assertion FAIL ở bản sau. [Mã tính chỉ số pilot](../tools/quality.py) · [Tiêu chí và quyết định Batch02](../data/batch-02/completion-review.json)

Để tính số còn chưa xác nhận, nhóm `versions.jsonl` theo nhãn cho cấp phiên bản và dùng `cases.after_label` cho nhãn bản sau của mỗi CVE. Kết quả tương ứng là **342/409 phiên bản** và **9/20 hồ sơ**. Một câu hỏi khác là có bao nhiêu hồ sơ chứa ít nhất một phiên bản chưa xác nhận. Phép nhóm theo CVE cho kết quả **18/20**. [Đếm theo từng hồ sơ](DOI_CHIEU_DU_LIEU.md)

## Tiêu chí nghiệm thu chung `common-scoped-v1`

Rà soát ngày 25/11/2026 bởi **AI**, dùng bằng chứng đã lưu cho cả Pilot và Batch02. Đây là chuẩn kỹ thuật nội bộ để chuẩn bị nghiệm thu; yêu cầu chính thức của giảng viên chưa được xác nhận. Mục tiêu **12/20 hồ sơ đạt** vẫn là **đề xuất**. Đánh giá độc lập bởi con người được theo dõi riêng, hiện bằng 0, chưa là điều kiện của chuẩn này.

| Mã | Điều kiện bắt buộc áp dụng giống nhau cho cả 20 CVE |
|---|---|
| C1 | Có advisory, repository, cặp commit/tree và cha được chọn; ghi rõ lịch sử phục dựng nếu có. |
| C2 | Toàn bộ phiên bản phương thức đã đối chiếu Git blob, khoảng dòng, SHA-256 và tên/biên AST. |
| C3 | Ghi ngữ cảnh advisory/bản vá, caller, điều kiện sử dụng và phạm vi kết luận. |
| C4 | Có rà soát có phạm vi cho callable mục tiêu; các helper, test và phương thức chưa đủ căn cứ giữ `UNCONFIRMED` kèm lý do. Rà soát snapshot của Pilot được đọc cùng quy tắc phương thức và annotations, không tự lan nhãn snapshot. |
| C5 | Build từ nguồn cả hai commit đúng mô-đun; mỗi phía có bước build PASS, exit 0, log và mã băm artifact đã lưu. |
| C6 | Cùng fixture/test và đầu vào đối chứng có cùng mã băm/tên; đối chứng thông thường đạt ở cả hai phía. Cho phép receipt đối chứng riêng nếu đúng hai commit/tree, mã kiểm tra và kết quả đã lưu; không thay thế C7. |
| C7 | Cùng đầu vào/oracle, có ít nhất một assertion mục tiêu FAIL trước → PASS sau, được diễn giải đúng cơ chế/phạm vi CVE; ghi rõ các assertion còn FAIL. |

Một hồ sơ **đạt chuẩn chung khi cả C1–C7 đều đạt**. Bản vá một phần vẫn có thể đạt chuẩn hồ sơ nếu hành vi và giới hạn được ghi đầy đủ; nhãn bản sau vẫn phản ánh lỗi còn lại. Process exit 0, upstream tests PASS hoặc assertion PASS/PASS do exception trước hành vi mục tiêu không thay thế C7. Đạt chuẩn hồ sơ không yêu cầu mọi callable đều được xác nhận và không đồng nghĩa an toàn tổng quát.

Từng cặp build và security log đã được ghép theo CVE, phase và commit. Assertion bảo mật được parse lại từ log đã lưu, đối chiếu receipt; mã băm fixture được kiểm tra với tệp hiện có. Đối chứng ZIP riêng của Plexus Archiver 2023 dùng receipt cục bộ có băm verifier/test/input/output và Surefire, không có log Maven gốc; chỉ ghi nhận C6. Băm các đầu vào được ghi trong [biên bản máy đọc](../data/acceptance-review.json). Thứ tự rà: sáu Pilot có hành vi, Spark và Plexus Utils Batch02, sau đó 12 hồ sơ còn lại. Lượt khôi phục tiếp theo có build nguồn và chạy kiểm thử chức năng thông thường. Không chạy payload CVE mới hoặc sửa bằng chứng lịch sử.

Kết quả: **8/20 hồ sơ đạt chuẩn chung** (Pilot 6/10, Batch02 2/10), **14/20** có cặp build, **12/20** chưa đạt chuẩn. Giữ nguyên **342/409** nhãn phương thức `UNCONFIRMED`. Tám hồ sơ đạt trùng nhóm ứng viên ban đầu, nhưng kết luận này được đánh giá lại theo cùng C1–C7, không cộng cơ học hai định nghĩa theo lô.

## Mốc so sánh

Ba mốc của Batch02 gồm bản tiếp nhận sau trích xuất, tag `v0.2.0` và cây dữ liệu tại `a1ea91f`. Chúng ghi lần lượt 222, 220 và 213 phiên bản `UNCONFIRMED` trên cùng 222 mẫu. Dùng số trong commit tương ứng khi trích dẫn. Tệp `catalog` nhúng trong một receipt cũng phản ánh thời điểm lập receipt. [Tiếp nhận](../data/batch-02/summary.json) · [Tại tag](https://github.com/LeTriCao/JavaCVE/blob/5062c2b1c1f0a41ba9c0264dadd51d75703ac5ea/data/batch-02/completion.json) · [Tại bàn giao](../data/batch-02/completion.json)

## Phạm vi chưa xác minh

Định danh và băm mẫu có thể đối chiếu độc lập với Git. Kết luận ngữ nghĩa vẫn giới hạn ở mã, caller, mô-đun và môi trường được ghi trong từng hồ sơ. Tất cả sổ rà soát hiện ghi AI và 0 người đánh giá độc lập. Độ đồng thuận, mức tiết kiệm công sức và thay đổi độ chính xác mô hình đều **chưa đo**. Độ phủ có thể thay đổi khi có biên bản mới. [Sổ rà soát và phần còn thiếu](DOI_CHIEU_DU_LIEU.md) · [Bảng so sánh trong báo cáo môn học](BAO_CAO_MON_HOC.md)

## Chọn cặp commit và đoạn mã

Giữ metadata seed của CWE-Bench-Java tại revision IRIS khóa. Với mỗi hồ sơ pilot, đối chiếu advisory → commit sửa → parent được chọn → Git tree → blob tệp → callable → khoảng dòng → SHA256. Tệp thêm/xóa giữ null ở phía vắng; phương thức thêm/xóa chỉ có phiên bản tồn tại. Chữ ký là cú pháp AST, không phải định danh JVM đã phân giải kiểu.

## Các chỉ số và mẫu số

| Chỉ số | Định nghĩa / mẫu số |
|---|---|
| Ánh xạ sửa hiệu chỉnh | Số CVE có danh sách seed fix khác SHA sửa được chọn / 10 pilot; hiện 1/10 |
| Cặp chuẩn hóa | Số cặp mà Git xác nhận before là parent được ghi của after / 10; hiện 10/10 |
| Phạm vi tệp | Đường dẫn .java duy nhất trong diff theo từng CVE, cộng qua các CVE; `--no-renames` |
| Build snapshot | Snapshot tạo được đúng primary JAR / snapshot được thử trong experiment đầu vào |
| Độ phủ build pilot | CVE có cả hai snapshot build / toàn bộ 10 pilot; giữ riêng CVE không đo |
| Tái hiện hành vi | CVE có ít nhất một assertion security FAIL→PASS và controls PASS ở cả hai phía / CVE có đo hành vi |
| Độ phủ hành vi pilot | Cùng tử số trên / toàn bộ 10 pilot |
| Toàn vẹn callable | Số phiên bản hiện diện thực sự đối chiếu từ source / 187; không tính phía vắng thành mẫu |
| Bản sau còn FAIL | Số snapshot after có ít nhất một security assertion FAIL / số after đã đo |
| Thời gian | Wall clock riêng các subprocess fetch/build/classpath/API/security; gắn môi trường/cache/network |
| Can thiệp thủ công | Ghi mô tả thay đổi môi trường/cấu hình; chưa đo đủ thời gian lao động theo CVE |

`measure` lấy cả seed và fix gốc, đếm diff seed→fix và parent→fix. Chỉ so cùng SHA sửa để cô lập ảnh hưởng chọn bản trước. Commons IO đổi SHA sửa nên bị loại khỏi phép đo 9 CVE này và báo riêng. Đã xác nhận 60→33, giảm `(60-33)/60=45%`; không diễn giải thành giảm 45% thời gian.

`report` tính lại số liệu từ bảng và các run được chỉ định, xuất JSON/CSV/Markdown/DOCX. Các snapshot trùng giữa input runs bị từ chối. Bằng chứng lịch sử matched build trên 6 seed có cùng JDK8u514, Maven3.5.0 và mô-đun; cả hai quy trình đạt6/6. Run paired hiện dùng Maven3.9.9, nên không lấy hai tỷ lệ này để suy ra cải thiện do công cụ.

## Chống trùng và rò rỉ

Giữ dự án hoặc CVE làm đơn vị chia; mọi phương thức/phiên bản cùng đơn vị đi cùng partition. Gộp các đơn vị chia sẻ hash token thành một connected component trước khi dùng hash xác định bucket train/validation/test 80/10/10 theo kỳ vọng. Mẫu nhỏ có thể lệch tỷ lệ hoặc trống partition. Với cả pilot và batch02, tính lại token theo cùng thuật toán từ source Git đã khớp SHA256, tránh so hash sinh bằng hai phiên bản extractor khác nhau.

Không có exact token duplicate băng qua các partition được công cụ sinh. Điều này không loại trừ clone gần giống, mã sao chép giữa lịch sử hoặc tương đồng ngữ nghĩa; cần detector bổ sung và đánh giá thủ công trước nghiên cứu ML. Không coi các mẫu UNCONFIRMED là negative. Chưa có mô hình baseline, phép đo tăng accuracy, kappa hay thời gian người gán nhãn.

## Tương thích bản ghi trong giai đoạn phát triển

`security.status`, process_exit_code, fixture_sha256, tests và controls_pass là các trường kết quả hành vi có thẩm quyền. Run Expand20fda536 được tạo trước khi sửa trường trạng thái tóm tắt `security_status`; trường tóm tắt cũ có thể còn BLOCKED dù security.status=EXECUTED. Errata ở evidence/v0.2.0/ERRATA.json ghi rõ sai lệch metadata này; kết quả từng assertion, hash, log và run thô được giữ nguyên. CLI hiện tại cập nhật cả hai trường thành EXECUTED sau khi fixture chạy.

## Lượt khôi phục build và kiểm thử thông thường (25/11/2026)

Hiện **14/20 cặp build**, **8/20 đạt C1–C7**, giữ **342/409 UNCONFIRMED**. C5 của Retrofit dùng POM tạm khóa Kotlin plugin bằng property 1.2.60 trong POM gốc. Jenkins dùng POM tạm bỏ riêng execution chuẩn bị dependency test harness của HPI 3.22. Diff, băm và phạm vi từng overlay được ghi trong receipt; mã Java không đổi. C1/C2 và nhãn vẫn trỏ nguồn commit gốc. Không suy ra C7 từ package hoặc API round-trip. Đối chứng XStream mới dùng cùng fixture, String/Integer cố định, JAR source-build đúng commit/băm và log thực thi được parse lại. Đối chứng Plexus kiểm tra Surefire 1 test/0 lỗi cùng băm đầu ra. [Chi tiết](RECOVERY_20261125.md). Mục tiêu 12/20 vẫn là đề xuất.

## Đối chứng IRIS bổ sung và context

data/iris-comparison.json được tính lại từ CSV nguồn và Git, đủ 20 dòng: primary 9 CVE 60→33, expanded 10 CVE 62→35; quy tắc no-renames/path Java bao gồm test/resource, sum CVE-path. Giữ 23/23 và 25/25 anchor Java của IRIS fix_info. Không tăng accuracy hay giảm thời gian được suy ra từ số path. Tệp GitClientSecurityTest cùng SECURITY-1534 bị loại khỏi changed-set được giữ ở context-files.jsonl, không thêm vào 409 mẫu. Chỉ hai ca được đọc diff chi tiết; không chứng minh tất cả 27 path bị loại là không liên quan. Phiếu người rà không có baseline; điều phối viên giữ riêng và trạng thái còn PENDING. [Bảng và giới hạn](SO_SANH_IRIS_JAVACVE.md).
