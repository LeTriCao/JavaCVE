# Nguồn và phạm vi phân phối

Nguồn chọn mẫu là CWE-Bench-Java trong kho IRIS, revision `d2059f299a80a68ea4a0b0315eec2f42b8743776`. Các tác giả của IRIS đã cung cấp hồ sơ dự án, thông tin commit, tập phương thức và công cụ tải, build. Bản thí điểm giữ lại định danh gốc và ghi riêng cặp phiên bản được chọn. [Kho IRIS tại revision sử dụng](https://github.com/iris-sast/iris/tree/d2059f299a80a68ea4a0b0315eec2f42b8743776)

Bộ dữ liệu chuẩn hóa tham chiếu hai nhóm yếu điểm theo MITRE. Các advisory và kho dự án tương ứng được liệt kê ở mỗi dòng của `data/cases.jsonl`. [CWE-22](https://cwe.mitre.org/data/definitions/22.html) · [CWE-78](https://cwe.mitre.org/data/definitions/78.html)

Bản phân phối chứa chỉ mục dữ liệu, nhãn, mô tả phương pháp, kết quả rút gọn và mã kiểm tra do đồ án bổ sung. Tệp `LICENSE` kế thừa phạm vi giấy phép của phần công cụ và tài liệu đồ án. Văn bản MIT của kho IRIS nằm ở `licenses/IRIS-LICENSE`. Danh mục `licenses/inventory.json` ghi từng tệp LICENSE hoặc NOTICE thực tế đã thu được, mã băm, kho nguồn và commit liên quan đến từng dự án. Riêng Plexus Utils, tài liệu lưu trong gói chỉ có NOTICE. Với zip4j, tệp MIT trong lịch sử phục dựng ghi tác giả iris-sast năm 2025. Phạm vi giấy phép của mã zip4j lịch sử cần đối chiếu với nguồn ban đầu nếu tái phân phối mã.

Người sử dụng lấy mã Java và phụ thuộc từ nguồn dự án tương ứng. Tệp mã xuất cục bộ, các archive nguồn, JAR, JDK, Maven, cache và bản ghi chỉ dành cho máy cá nhân được bỏ qua theo `.gitignore`. Phạm vi gói đã kiểm tra là cây tệp phát hành này. Khi trích dẫn trong báo cáo, ghi tên bộ, phiên bản v0.1.0, revision IRIS và mã CVE dùng trong phép đo.

## Bổ sung trong v0.2.0

Các CSV nguồn tại `evidence/inputs/` được lấy từ gói lịch sử, sau đó `expand` đối chiếu byte độc lập với các tệp tại đúng revision IRIS trên raw.githubusercontent.com. SHA256 từng tệp nằm trong `data/batch-02/summary.json`. Bản gốc project_info.csv dùng CRLF; `.gitattributes` giữ nguyên byte để hash không đổi sau clone.

Metadata advisory của batch02 được lấy từ GitHub Global Security Advisories API ngày 24/11/2026. Mỗi JSON giữ `html_url`, `ghsa_id`, `cve_id`, tham chiếu và phân loại CWE từ nguồn; xem `data/batch-02/advisories/`. Nội dung GitHub Advisory Database được cấp phép [CC BY 4.0](https://github.com/github/advisory-database/blob/main/LICENSE.md); attribution thuộc GitHub và các tác giả/advisory được nêu trong bản ghi, bản sao JSON không sửa phần nội dung nguồn. Lượt trích xuất/chú thích JavaCVE được ghi riêng. Bản đầy đủ giấy phép được giữ ở `licenses/GITHUB-ADVISORY-CC-BY-4.0.txt`.

Thêm mười hồ sơ không mở rộng giấy phép MIT sang source Java của Spark, Retrofit, one-java-agent, Plexus, XStream hoặc Jenkins. Chỉ phân phối chỉ mục, nhận xét và bằng chứng chạy; export source được tạo cục bộ từ repository tương ứng. Tree-sitter và grammar Java là công cụ tùy chọn được tải riêng theo requirements-annotation.txt; không đóng gói wheel trong phát hành. Bộ công cụ JDK/Maven cũng được tải riêng và giữ giấy phép của nhà cung cấp.

Khi trích dẫn bản mới, ghi JavaCVE v0.2.0, SHA/tag phát hành, revision IRIS, batch ID và CVE. Các nhãn và phép đo pilot/batch02 có phạm vi khác nhau; xem METHODOLOGY.md và BATCH02.md.
