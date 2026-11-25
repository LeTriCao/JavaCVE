# Khôi phục build Batch02

Các mục trước phần “Lượt khôi phục build và kiểm thử thông thường” là lịch sử đến a1ea91f. Hiện Batch02 có **8/10 cặp build**; C6 của ba XStream được bổ sung bằng API round-trip, C7 vẫn thiếu. [Kết quả cập nhật](RECOVERY_20261125.md).

## Plexus Archiver CVE-2023-37460

**Cả hai commit đã package thành công và có JAR build từ source.** AI chọn hồ sơ này vì log trước cho thấy Maven còn xác minh repository ID của artifact đã có trong cache. Log sau đã ghi tạo JAR rồi mới hết thời gian ở `site:attach-descriptor`. Cả hai lần cũ đều hết hạn 90 giây với exit code 124. [Log cũ trước](../evidence/v0.2.0/2b54f962ab544cb789aaf746c087715e/logs/11-build.log) · [Log cũ sau](../evidence/v0.2.0/2b54f962ab544cb789aaf746c087715e/logs/12-build.log).

Lượt mới chỉ chọn Plexus, tăng ngân sách mỗi bước lên 600 giây và dùng cấu hình Maven mặc định của runner cho Central cùng các kho HTTPS khai báo trong dự án. Lượt cũ bật thêm kho Jenkins. Cả hai dùng cache Maven trên máy. Package bỏ qua test, Checkstyle và RAT. Bước test riêng chọn `SymlinkTest` và `ZipArchiverTest` với `failIfNoTests=true`, dùng Maven 3.9.9 và Temurin 8u514. Không có dependency thay thế hay chỉnh sửa source. Các điều kiện cache, kho và ngân sách thay đổi cùng nhau nên chưa thể quy thành công cho riêng một thay đổi. [Lệnh và môi trường lượt cũ](../evidence/v0.2.0/2b54f962ab544cb789aaf746c087715e/run.json) · [Lệnh, thời gian và SHA-256 JAR lượt mới](../evidence/v0.2.0/9c2a5b8236d34dfbbd96d36ec9df0eb1/run.json).

| Snapshot | Package / test (giây) | Tệp nguồn đã kiểm tra / thay đổi | Test ghi nhận / thực chạy / bỏ qua | Failure / error | Bằng chứng |
|---|---:|---:|---:|---:|---|
| Before · `18a6485` | 59,61 / 57,47 | 552 / 0 | 28 / 27 / 1 | 0 / 0 | [Build](../evidence/v0.2.0/9c2a5b8236d34dfbbd96d36ec9df0eb1/logs/2-build.log) · [Test](../evidence/v0.2.0/9c2a5b8236d34dfbbd96d36ec9df0eb1/logs/3-upstream-tests.log) |
| After · `5475983` | 40,59 / 43,15 | 553 / 0 | 29 / 28 / 1 | 0 / 0 | [Build](../evidence/v0.2.0/9c2a5b8236d34dfbbd96d36ec9df0eb1/logs/4-build.log) · [Test](../evidence/v0.2.0/9c2a5b8236d34dfbbd96d36ec9df0eb1/logs/5-upstream-tests.log) |

Surefire ghi nhận 6 test của SymlinkTest ở mỗi bản. ZipArchiverTest có 22 test trước và 23 test sau, trong đó mỗi bản bỏ qua một test. Mỗi log test có bốn byte NUL nên Git nhận dạng là tệp nhị phân. Trường `upstream_totals` cung cấp các tổng Surefire dưới dạng văn bản. [Số liệu theo snapshot](../data/batch-02/build-status.json).

Receipt ghi `BLOCKED_NO_REVIEWED_PAIRED_FIXTURE` cho cả hai snapshot. Hồ sơ còn thiếu phép đo có đối chứng chung và căn cứ quy hành vi cho callable. Batch02 hiện có 6/10 cặp build thành công và 2/10 hồ sơ hoàn tất. [Bảng ưu tiên từng hồ sơ](BATCH02.md).

## Spark và XStream từ v0.2.0

Git lúc tiếp nhận sạch, main và tag v0.2.0 cùng SHA 5062c2b1c1f0a41ba9c0264dadd51d75703ac5ea. Các lượt dưới đây do AI thực hiện, dùng JDK8u514, Maven3.9.9 và cache Maven hiện có. Ngân sách mỗi bước là 600 giây.

Lệnh chẩn đoán ban đầu chạy hai CVE cùng nhau bằng `python3 run.py batch-build data/batch-02 --cve CVE-2016-9177 --cve CVE-2013-7285 --timeout 600`. Receipt 2ad70474dd2f4a9a8d2313dd8ce41dd0 giữ bốn lần package đạt. Trạng thái toàn lệnh FAIL do hai bước upstream test. Log cũ Spark dừng ở chọn plugin trong 90 giây, XStream dừng ở dependency:copy sau compilation. Lượt mới cho thấy cả hai source build được trong điều kiện cache và ngân sách đã ghi.

Spark StaticFilesTestExternal.setup nối `System.getProperty("java.io.tmpdir") + "sparkish"`, dẫn đến /tmpsparkish với cấu hình cũ và lỗi FileNotFound. Profile mới tạo thư mục tạm riêng cho snapshot, truyền JAVA_TOOL_OPTIONS với java.io.tmpdir có dấu / cuối tới Maven và JVM test. Source production và test giữ nguyên byte, được kiểm tra sau khi chạy. Lệnh xác minh `python3 run.py batch-build data/batch-02 --cve CVE-2016-9177 --timeout 600` đạt cả hai snapshot và các lớp upstream, receipt 9dc0292fc028480080aa9bad378f9b90.

XStream before package đạt, bước upstream test thoát 1 vì Surefire báo zero tests với danh sách lớp lấy từ after. XStream after package và upstream test đạt. Kết quả build PASS/PASS được ghi trong build-status.json. Cần chọn bộ test áp dụng cho before và dựng fixture chung để kiểm chứng hành vi CVE.

## Kết quả chọn lại upstream test XStream

Receipt 4063ba008c3644f5ad4d015ccd4cbcc4 bổ sung lượt chọn lại test. Parent POM khóa Surefire 2.4.3, include **/*Test.java và **/*TestSuite.java. Cây nguồn before có com.thoughtworks.acceptance.AliasTest và com.thoughtworks.acceptance.annotations.AliasTest. Selector `-Dtest=AliasTest -DfailIfNoTests=true` chạy cả hai lớp, gồm 21 và 6 test. Các lớp này kiểm tra alias, serialize và unmarshal thông thường.

Cả before và after đều đạt 27 test, 0 failure, 0 error, 0 skipped. Trạng thái build và test được ghi riêng trong data/batch-02/upstream-selection.json, kèm commit, SHA256 JAR, exit code và thời gian. Build before mất 51.51 giây, test mất 37.06 giây. Build after mất 55.21 giây, test mất 36.31 giây. Thời gian lấy từ subprocess, có cache và JDK8u514/Maven3.9.9.

Quan sát zero tests của lượt cũ được diễn giải là NO_TESTS_FOUND trong upstream-selection.json và dẫn về receipt gốc. CLI hiện ghi NO_TESTS_FOUND khi Surefire báo không có test hoặc danh sách chọn rỗng. Completion và nhãn giữ trạng thái đang rà soát. Receipt mới cũng lưu các assertion fixture đã chạy trong lượt đang thực hiện trước yêu cầu thu hẹp sang upstream test.

Thời gian, exit code, commit, công cụ, override, mã băm JAR và kiểm tra source nằm trong các receipt ở evidence/v0.2.0. build-recovery.json liên kết kết quả và giả thuyết của giai đoạn khôi phục build. Tại thời điểm đó số snapshot Batch02 build đạt tăng từ 8/20 lên 10/20; hoàn tất thực nghiệm giữ 1/10 và nhãn hai hồ sơ giữ UNCONFIRMED.

Ở lượt rà soát từ a7e6abd, Spark hoàn tất theo đường gọi external đã đo. Với XStream, log bổ sung sau đó đã xác định exception phát sinh trước callback ở cả hai bản. [Bảng từng tiêu chí](BATCH02_REVIEW.md) · [Chẩn đoán XStream](XSTREAM_DIAGNOSIS.md).

## Ghi chính xác bằng chứng CI

Workflow chạy khi push commit 627abe2 có job offline đạt và source-security bị skipped. Điều kiện `github.event_name == 'workflow_dispatch'` chỉ bật source-security cho lượt kích hoạt thủ công. Trạng thái Success của lượt push xác nhận các job đã chạy đạt. Bằng chứng bảo mật cần đọc kết quả job source-security của một lượt workflow_dispatch cụ thể.

Người dùng có thể mở Actions → Verify JavaCVE → Run workflow trên main. Công cụ bảo trì `powershell -NoProfile -File tools/github.ps1 -Action Dispatch` thực hiện cùng thao tác. Source-security hiện chạy Commons IO và hai cặp Spark/XStream. Lệnh Status in cả kết luận từng job để ghi nhận chính xác trạng thái skipped.

Đã xác minh lượt workflow_dispatch 45361871765 tại commit 1d8ae45 có offline=success và source-security=success. Job source-security thực sự chạy các lệnh source đã cấu hình. Lượt push 45361863359 tại cùng commit có offline=success, source-security=skipped. Hai kết quả được ghi theo từng job và sự kiện kích hoạt. URL kiểm tra là https://github.com/LeTriCao/JavaCVE/actions/runs/45361871765.

## Lượt khôi phục build và kiểm thử thông thường (25/11/2026)

Kết quả hiện tại: **14/20 cặp build**, tăng **2**; **8/20 đạt chuẩn chung**, không nâng nhãn phương thức. [Build và kiểm thử chức năng mới](RECOVERY_20261125.md) · [Bảng nghiệm thu](DOI_CHIEU_DU_LIEU.md). Manifest gốc được giữ nguyên, danh sách bàn giao vẫn là dự kiến. Chưa commit/push/tag/release. Các kết quả và tiêu chí theo lô phía trên là lịch sử; C1–C7 cập nhật ở `data/acceptance-review.json`.
