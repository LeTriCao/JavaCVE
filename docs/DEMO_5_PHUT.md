# Kịch bản demo JavaCVE — mục tiêu 5 phút

Bản bàn giao cuối dùng commit nền a1ea91f12cb78d2828e97c055ff6c18481107759. Để dùng ZIP bổ sung, giải nén vào một bản sao sạch của commit nền, cho phép ghi đè. Checkout trực tiếp commit bàn giao trên GitHub có đủ cây tệp. Bốn lệnh demo nằm trong docs/DEMO_5_PHUT.md.

## Chuẩn bị

Mở terminal trong thư mục JavaCVE của ZIP v2 vừa giải nén. Python ≥3.12. Lệnh thứ ba cần Git và cache ngoài gói có đúng các object được bảng so sánh chỉ định. Source/AST cần parser ở requirements-annotation.txt; riêng walkthrough và tái tính receipt không cần parser/JDK/Maven. Không chạy build hoặc fixture CVE trong demo.

Đặt ba đường dẫn thật trên máy. Không coi ví dụ placeholder là đường dẫn có sẵn:

```sh
export IRIS_PILOT_REPOS="/duong-dan-cache/measurement-repos"
export JAVACVE_BATCH_REPOS="/duong-dan-cache/batch02-repos"
export JAVACVE_PILOT_REPOS="/duong-dan-cache/repos"
export GIT_NO_LAZY_FETCH=1
export GIT_ALLOW_PROTOCOL=file
```

## Lời trình bày và thao tác

| Mốc | Nội dung | Thao tác |
|---|---|---|
| 0:00–0:35 | Yêu cầu là cải thiện dataset có sẵn. Chọn IRIS/CWE-Bench-Java, giữ source revision và mẫu số. | Mở README và bảng SO_SANH_IRIS_JAVACVE.md. |
| 0:35–1:20 | 9 Pilot: 60→33; thêm một CVE 2→2 nên tổng 62→35. Cùng fix, quy tắc path rõ. | Chỉ ba SHA của Plexus Archiver và các hàng không giảm; không gọi 45% là accuracy. |
| 1:20–2:25 | Chuỗi advisory→fix/parent→method/hash→receipt. Sau patch chính parent traversal được chặn nhưng sibling-prefix còn FAIL, nhãn chưa phải SAFE. | Chạy lệnh 1 và 2 bên dưới. |
| 2:25–3:20 | Trường hợp bất lợi GitClientSecurityTest cùng SECURITY-1534 ra khỏi changed-set. Giữ context reference và 25/25 anchor của IRIS. | Mở phần ca 2 của bảng so sánh; chạy lệnh 3. |
| 3:20–4:15 | Tái tính 14/20 cặp build, 8/20 đạt C1–C7, 342/409 U. Source identity và build khác với semantic label. | Chạy lệnh 4, mở JSON mới trong runs/. |
| 4:15–5:00 | Phiếu 40 mẫu ẩn baseline, quyết định trống; 6 thiếu build/6 thiếu tiêu chí; mục tiêu 12/20 đề xuất. | Mở docs/review/PHIEU_RA_SOAT_NHAN.csv và báo cáo mục 4/5. Nêu rõ chưa có người rà hoặc máy khác. |

## Bốn lệnh thật đã được đưa vào quy trình diễn tập

```sh
# 1 — manifest và quan hệ dữ liệu
python3 run.py demo
# 2 — chỉ đọc bằng chứng đã lưu; không thực thi CVE
python3 -m tools.course_demo --out runs/demo-walkthrough --verify-manifest
# 3 — tính lại từ Git object cục bộ, cần cache ngoài gói
python3 -m tools.compare_iris --out runs/demo-iris \
  --pilot-repos "$IRIS_PILOT_REPOS" \
  --batch-repos "$JAVACVE_BATCH_REPOS" \
  --fallback-repos "$JAVACVE_PILOT_REPOS"
# 4 — tái tính chuẩn nghiệm thu từ receipt/log
python3 -m tools.acceptance --out runs/demo-acceptance.json
```

Mỗi đích output phải chưa tồn tại. Khi chạy lại, dùng tên mới. So comparison.json vừa sinh với data/iris-comparison.json, so JSON nghiệm thu với data/acceptance-review.json. Nếu thiếu cache, không nói đã tái tính Git: chỉ trình bày bản chứng cứ lưu và ghi phần chưa chạy.

## Môi trường và điều đã/chưa thực hiện

Quy trình kiểm tra v2 ghi phiên bản Python, Git, parser, đường dẫn cache được ẩn thông tin máy và số giây từng lệnh. Các lệnh được chạy từ ZIP giải nén mới trên cùng máy Windows/Ubuntu WSL hiện tại, không phải lần thử trên máy khác. Chưa có buổi thuyết trình người thật đo đủ 300 giây; bảng thời gian là kịch bản dự kiến. Cần người trình bày tập lại trên máy chấm và người rà điền phiếu thật. verification/ và FINAL_VERIFICATION.json của gói ghi kết quả thực tế.
