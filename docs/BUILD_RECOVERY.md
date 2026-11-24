# Khôi phục build Spark và XStream từ v0.2.0

Git lúc tiếp nhận sạch, main và tag v0.2.0 cùng SHA 5062c2b1c1f0a41ba9c0264dadd51d75703ac5ea. Các lượt dưới đây do AI thực hiện, dùng JDK8u514, Maven3.9.9 và cache Maven hiện có. Ngân sách mỗi bước là 600 giây.

Lệnh chẩn đoán ban đầu chạy hai CVE cùng nhau bằng `python3 run.py batch-build data/batch-02 --cve CVE-2016-9177 --cve CVE-2013-7285 --timeout 600`. Receipt 2ad70474dd2f4a9a8d2313dd8ce41dd0 giữ bốn lần package đạt. Trạng thái toàn lệnh FAIL do hai bước upstream test. Log cũ Spark dừng ở chọn plugin trong 90 giây, XStream dừng ở dependency:copy sau compilation. Lượt mới cho thấy cả hai source build được trong điều kiện cache và ngân sách đã ghi.

Spark StaticFilesTestExternal.setup nối `System.getProperty("java.io.tmpdir") + "sparkish"`, dẫn đến /tmpsparkish với cấu hình cũ và lỗi FileNotFound. Profile mới tạo thư mục tạm riêng cho snapshot, truyền JAVA_TOOL_OPTIONS với java.io.tmpdir có dấu / cuối tới Maven và JVM test. Source production và test giữ nguyên byte, được kiểm tra sau khi chạy. Lệnh xác minh `python3 run.py batch-build data/batch-02 --cve CVE-2016-9177 --timeout 600` đạt cả hai snapshot và các lớp upstream, receipt 9dc0292fc028480080aa9bad378f9b90.

XStream before package đạt, bước upstream test thoát 1 vì Surefire báo zero tests với danh sách lớp lấy từ after. XStream after package và upstream test đạt. Kết quả build PASS/PASS được ghi trong build-status.json. Cần chọn bộ test áp dụng cho before và dựng fixture chung để kiểm chứng hành vi CVE.

Thời gian, exit code, commit, công cụ, override, mã băm JAR và kiểm tra source nằm trong hai receipt ở evidence/v0.2.0. build-recovery.json liên kết kết quả mới và giả thuyết. Số snapshot Batch02 build đạt tăng từ 8/20 lên 10/20. Số hồ sơ hoàn tất thực nghiệm giữ 1/10, nhãn của hai hồ sơ đang xử lý giữ UNCONFIRMED.

Lượt này hoàn tất phạm vi build. Công việc còn thiếu gồm fixture trước–sau có đối chứng, kiểm tra ngữ cảnh advisory, rà soát nhãn và xác minh lệnh fixture từ clone mới.

## Ghi chính xác bằng chứng CI

Workflow chạy khi push commit 627abe2 có job offline đạt và source-security bị skipped. Điều kiện `github.event_name == 'workflow_dispatch'` chỉ bật source-security cho lượt kích hoạt thủ công. Trạng thái Success của lượt push xác nhận các job đã chạy đạt. Bằng chứng bảo mật cần đọc kết quả job source-security của một lượt workflow_dispatch cụ thể.

Người dùng có thể mở Actions → Verify JavaCVE → Run workflow trên main. Công cụ bảo trì `powershell -NoProfile -File tools/github.ps1 -Action Dispatch` thực hiện cùng thao tác. Source-security hiện chạy Commons IO và hai cặp Spark/XStream. Lệnh Status in cả kết luận từng job để ghi nhận chính xác trạng thái skipped.
