# Chỉ dành cho điều phối viên

BASELINE_AI.json chứa nhãn hiện tại và lý do tham khảo, không gửi cho người rà trước khi họ quyết định. Dùng:

```sh
python3 -m tools.review_labels --reference docs/review_coordinator/BASELINE_AI.json --forms <phieu_da_dien.csv> --out runs/review-result-new.json
```

Dòng hợp lệ cần review_id/sample_id khớp, quyết định thuộc ba nhãn, người rà không phải AI, ngày ISO, lý do và evidence_checked đầy đủ, review_status COMPLETED. File trùng nội dung không tăng số mẫu. Dòng xung đột bị loại khỏi tỷ lệ cho đến khi giải quyết. Báo cáo trùng quyết định là so với baseline AI trên mẫu có chủ đích, không phải accuracy/gold set. Không tự áp nhãn vào data/.
