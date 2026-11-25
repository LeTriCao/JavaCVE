# Đối chứng giải nén ZIP thông thường cho CVE-2023-37460

Người rà soát là **AI**. Phương thức upstream `ZipUnArchiverTest.testZipMaxOutputSizeEqualToExtractedFileSize` đặt giới hạn giải nén bằng 11 byte, giải nén một tệp thường vào thư mục đích của test rồi kiểm tra kích thước tệp. Trình xác minh còn so sánh từng byte của tệp đầu ra với nội dung entry trong ZIP. Tệp `test.sh` chỉ được đọc để so sánh. [Mã test ở before](https://github.com/codehaus-plexus/plexus-archiver/blob/18a64852036bd6f0ebc880eb16563d8f08b0bc37/src/test/java/org/codehaus/plexus/archiver/zip/ZipUnArchiverTest.java#L236-L251) · [Mã test ở after](https://github.com/codehaus-plexus/plexus-archiver/blob/54759839fbdf85caf8442076f001d5fd64e0dcb2/src/test/java/org/codehaus/plexus/archiver/zip/ZipUnArchiverTest.java#L236-L251).

Cả hai lượt biên dịch lại lớp từ source trong checkout tạm của commit và tree ghi tại [cases.jsonl](../../data/batch-02/cases.jsonl). Mỗi lượt dùng cùng selector, mã nguồn test và đầu vào. Trình xác minh kiểm tra báo cáo Surefire chỉ gồm đúng phương thức trên, một test chạy, 0 lỗi và 0 bỏ qua. Receipt lưu SHA-256 của mã xác minh, tệp nguồn upstream, archive, dữ liệu entry và đầu ra. Receipt cũng ghi kết quả kiểm tra thay đổi đối với các tệp Git theo dõi. [Mã xác minh](verify.py) · [Receipt cục bộ](run.json).

### Chạy từ thư mục gốc JavaCVE

Trên Linux hoặc Ubuntu WSL, dùng Git, Python 3.11 trở lên, JDK 8 với `JAVA_HOME` và Maven trên `PATH`. Lệnh sau lấy đúng hai commit upstream, dùng Maven để biên dịch và ghi kết quả của lần chạy vào `runs/`.

```sh
python3 evidence/plexus-control/verify.py --output runs/plexus-control.json
```

Lượt trong receipt dùng bản sao Git và cache Maven có sẵn của JavaCVE, cùng JDK và Maven đã khai báo trong [toolchain.json](../../data/toolchain.json). Với cùng cache, có thể chạy lại như sau.

```sh
python3 evidence/plexus-control/verify.py \
  --repo .cache/batch02-repos/CVE-2023-37460 --dataset-toolchain --offline \
  --output runs/plexus-control.json
```

Phạm vi phép đo là giải nén thành công một tệp thường trong thư mục đích ở giới hạn kích thước nêu trên. Hành vi xử lý liên kết tượng trưng thuộc advisory cần bằng chứng riêng.
