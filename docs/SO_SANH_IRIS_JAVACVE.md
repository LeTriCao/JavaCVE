# Đối chứng IRIS → JavaCVE từ nguồn Git

Trên 10 CVE có cùng commit sửa, chọn parent của bản sửa làm mốc trước đã thu hẹp tập đường dẫn Java trong diff từ 62 xuống 35 (giảm 43,55%) và giữ đủ 25/25 tệp Java được IRIS chú thích. Với CVE-2019-10392, tệp GitClientSecurityTest.java rời khỏi diff nhưng vẫn tồn tại ở cả hai snapshot. Tra mã CVE trong data/context-files.jsonl để lấy đường dẫn, commit và mã băm.

Ngày 25/11/2026; AI đối chiếu, chưa có rà soát nhãn độc lập hoàn tất. Không chạy fixture CVE mới.

## Câu hỏi và quy tắc đếm

Giữ **cùng commit sửa F** và so hai mốc trước: seed S do IRIS khai báo với parent P JavaCVE chọn. Đếm tập đường dẫn Java trong diff S→F và P→F bằng `git diff --name-only --no-renames -z START F -- "*.java"`; phân biệt hoa/thường, mỗi đường dẫn một lần trong mỗi CVE, gồm production, test và Java resources. Cộng theo CVE-path, không phải số tệp duy nhất trên toàn bộ dự án. Không đếm LOC/phương thức hay suy ra chính xác nhãn, thời gian hoặc độ chính xác mô hình.

Metadata seed/fix lấy lại từ project_info.csv; đối chiếu JavaCVE cases.jsonl. Các băm CSV và cây Git nằm trong [JSON tính lại](../data/iris-comparison.json), [bảng CSV](generated/iris-comparison.csv), [từng đường dẫn](generated/iris-paths.csv). Không tải thêm Git object: thiếu snapshot được loại với lý do.

## Mẫu số baseline cần đọc đúng

IRIS đã có bảng fix_info.csv trỏ tới file/phương thức được chú thích. **60 path không phải số tệp IRIS đã gán nhãn**: đó là số tính lại bằng Git từ buggy_commit_id đến cùng fix. Parent-diff 33 path gồm 23 anchor IRIS và 10 path bổ sung; tổng mở rộng 35 gồm 25 anchor và 10 path bổ sung. Không đối chiếu trực tiếp “60 nhãn IRIS” với “33 nhãn JavaCVE”, không kết luận precision/recall hoặc số false positive được cải thiện. Tác dụng đã chứng minh là đơn vị phiên bản trước gần fix hơn và phạm vi diff gắn với fix rõ hơn, cùng provenance/băm/receipt; chất lượng nhãn tương đối còn cần người rà và đánh giá riêng.

## Kết quả đã xác minh

| Phạm vi | CVE đủ điều kiện | IRIS S→F | JavaCVE P→F | Chênh lệch | Tỷ lệ | Anchor file Java trong IRIS fix_info còn giữ |
|---|---:|---:|---:|---:|---:|---:|
| Pilot, giữ mẫu số cũ | 9 | 60 | 33 | −27 | 45% | 23/23 |
| Mở rộng với CVE-2022-25175 | 10 | 62 | 35 | −27 | 43,548387% | 25/25 |

Không có đường dẫn mới trong tập P→F ở mười ca đủ điều kiện. Bốn trong chín ca Pilot không giảm số đường dẫn; ca bổ sung cũng 2→2. Giảm phạm vi diff không chứng minh mọi tệp bị loại là không liên quan: một test bảo mật cùng issue bị ra khỏi tập changed-path và được giữ thành context reference.

## Bảng đủ 20 CVE

S = snapshot trước theo IRIS; P = snapshot trước theo JavaCVE; F = commit sửa JavaCVE. Với dòng bị loại, F không luôn là fix chung hợp lệ; xem cột cuối và danh sách fix IRIS trong JSON.

| CVE / lô | IRIS S | JavaCVE P | F | S→F Java | P→F Java | Kết luận / lý do loại |
|---|---|---|---|---:|---:|---|
| CVE-2017-1000487 / pilot | `3b271b43f9e5021b4232fc2ffdfb4e469c7f8685` | `86c37983bb2bd92b1df43fe73f321ffbfa155070` | `b38a1b3a4352303e4312b2bb601a0d7ec6e28f41` | 6 | 5 | Đủ điều kiện; giảm 1 |
| CVE-2018-1002200 / pilot | `b9f9a425865eb47fb3665b3144ee4ca11f402704` | `97c0d97504632a2a80b7d847bccdd9b37d27aea1` | `f8f4233508193b70df33759ae9dc6154d69c2ea8` | 14 | 2 | Đủ điều kiện; giảm 12 |
| CVE-2018-1002201 / pilot | `bd3f3d77f3709f901fd5180a493ef32e4dfebfa6` | `d1c40776d2ff18550d95db2609d3d154692dea93` | `759b72f33bc8f4d69f84f09fcb7f010ad45d6fff` | 3 | 2 | Đủ điều kiện; giảm 1 |
| CVE-2018-1002202 / pilot | `d87ffa2d64ffb3a0a1cf0c7a69c7b19d7015bfde` | `d87ffa2d64ffb3a0a1cf0c7a69c7b19d7015bfde` | `59aeea594ff885e06c25751dc6334dfea1bed8c6` | 2 | 2 | Đủ điều kiện; không giảm |
| CVE-2018-17297 / pilot | `7687720c5125b29386d3bb9c7c2931da79664b73` | `fd77bb8718648f69a587046b735488a80123cc26` | `8d7d0b7fb5ea4f7447b40131bffc1ec506a6528e` | 2 | 2 | Đủ điều kiện; không giảm |
| CVE-2019-10392 / pilot | `72add81da4cbeabc95504ebdb9007d47ac1c2b0b` | `04d2c155d19a37ae28ffe2345e0e2ccd96556b07` | `899123fa2eb9dd2c37137aae630c47c6be6b4b02` | 2 | 1 | Đủ điều kiện; giảm 1 |
| CVE-2020-2261 / pilot | `adabcd9da98628e063bb91198e30ff39a34dc921` | `60f9da8c6cdf06ef7824c5b35a63e3a21dda3110` | `52c09ad2e26416211e4009b095c4f16508b27b8a` | 2 | 2 | Đủ điều kiện; không giảm |
| CVE-2021-29425 / pilot | `2ae025fe5c4a7d2046c53072b0898e37a079fe62` | `7791a851c4a303f47743b156007fb19c6ed8ed81` | `2736b6fe0b3fa22ec8e2b4184897ecadb021fc78` | — | — | Loại: fix IRIS khác F; đổi cả biến fix nên không dùng để đo riêng hiệu quả chọn P. |
| CVE-2022-20617 / pilot | `2f0fda49452a7653c33de24220c908786f1aa405` | `7078a70448719715ae2c91b6a7fd718de76cf5a2` | `c069b79c31c5aa80a01b0c462f0dc6b41751f059` | 4 | 4 | Đủ điều kiện; không giảm |
| CVE-2022-33140 / pilot | `06f04958272dafc30ce357c4c4edcaf470050b52` | `fe0ed03d4d5aa5399216c4cf8cede84236fbb4f7` | `a1306a19f78e11c2d809e9aef24336669461403a` | 25 | 13 | Đủ điều kiện; giảm 12 |
| CVE-2016-9177 / batch02 | `ce57dfb949ed183405f75dee8cf3262b45c9b3b5` | `c57e572f95de5752c5bf8e1e5de764aa50e4a0f6` | `efcb46c710e3f56805b9257a63d1306882f4faf9` | — | — | Loại ở lượt này: chưa có đủ object seed S trong các cache đã kiểm tra; không fetch mạng. |
| CVE-2018-1000850 / batch02 | `7158698314daa138e993fac6a590ed19d78a8599` | `5088b0df6f2c52fcead426dafbb04214225e0cc7` | `b9a7f6ad72073ddd40254c0058710e87a073047d` | — | — | Loại ở lượt này: chưa có đủ object seed S trong các cache đã kiểm tra; không fetch mạng. |
| CVE-2022-25842 / batch02 | `b911af2bb779917c84a016350700745dc31c642a` | `29dc527a5d76c14de833ac3f2eae282a27190505` | `359603b63fc6c59d8b57e061c171954bab3433bf` | — | — | Loại khỏi phép đo single-fix: IRIS có nhiều fix reference, chưa so trọn chuỗi đa commit. |
| CVE-2022-4244 / batch02 | `6176f91bb843eecddac857591ed20bda38e01470` | `f933e5e78dc2637e485447ed821fe14904f110de` | `33a2853df8185b4519b1b8bfae284f03392618ef` | — | — | Loại ở lượt này: chưa có đủ object seed S trong các cache đã kiểm tra; không fetch mạng. |
| CVE-2023-37460 / batch02 | `e7cbadba1b5c78192677da95b355dd790f3a4535` | `18a64852036bd6f0ebc880eb16563d8f08b0bc37` | `54759839fbdf85caf8442076f001d5fd64e0dcb2` | — | — | Loại ở lượt này: chưa có đủ object seed S trong các cache đã kiểm tra; không fetch mạng. |
| CVE-2013-7285 / batch02 | `768c6e417a75e7732fc591bee844e5e81af56a7d` | `64533f1fe2ece82398a1478edc2d30478fb7cd11` | `6344867dce6767af7d0fe34fb393271a6456672d` | — | — | Loại ở lượt này: chưa có đủ object seed S trong các cache đã kiểm tra; không fetch mạng. |
| CVE-2020-26217 / batch02 | `d03f6987b793fac71ab89a31d7aa633c366c5289` | `573fbafb06859ecb3a836bd6fe2afacfc5cdabcc` | `0fec095d534126931c99fd38e9c6d41f5c685c1a` | — | — | Loại ở lượt này: chưa có đủ object seed S trong các cache đã kiểm tra; không fetch mạng. |
| CVE-2021-21345 / batch02 | `f04bbec461f2c2a6f1e2cf41770f42c64aae24a4` | `d3c679a2cca689a0113c3bf011a74ad79b85c4f3` | `d5e51177634afea7213b9dc2d21f101d2e258db9` | — | — | Loại ở lượt này: chưa có đủ object seed S trong các cache đã kiểm tra; không fetch mạng. |
| CVE-2022-25174 / batch02 | `ff04fa68714d2cc277e8a87512461bdf3a39e186` | `d1912e98fa56b77ef495beee79e3f27f0c8f4026` | `ace0de3c2d691662021ea10306eeb407da6b6365` | — | — | Loại ở lượt này: chưa có đủ object seed S trong các cache đã kiểm tra; không fetch mạng. |
| CVE-2022-25175 / batch02 | `d43c65dec013812b084fecbb4a310d856eb6b89a` | `d43c65dec013812b084fecbb4a310d856eb6b89a` | `71c3f0a6ccdb2ba43f43686826b0d62160df85e8` | 2 | 2 | Đủ điều kiện; không giảm |

## Ca 1: Plexus Archiver CVE-2018-1002200 — 14 → 2

F là merge commit, P là parent thứ nhất đã xác minh. Hai tệp còn trong P→F là `AbstractUnArchiver.java` và `ZipUnArchiverTest.java`. Diff thêm guard canonical-path trong extractFile và một regression test cho đích giải nén. Anchor Java trong fix_info của IRIS là AbstractUnArchiver; vẫn giữ. Đây là kiểm tra định danh độc lập với phép so equality tập indexed-path, vốn đúng theo cách chọn parent.

Mười hai đường dẫn được loại khỏi changed-set có blob P bằng blob F. Đã đọc diff S→P để phân loại nội dung; chúng không đổi tại fix F đang đo. Không suy rộng thành “không liên quan đến bảo mật” cho mọi phiên bản/lỗ hổng khác.

| Đường dẫn bị loại | Nội dung S→P đã đọc | Vì sao không nằm trong P→F |
|---|---|---|
| `src/main/java/org/codehaus/plexus/archiver/AbstractArchiver.java` | Thêm hook postCreateArchive sau khi tạo archive. | Blob P = F, không sửa ở fix chung. |
| `src/main/java/org/codehaus/plexus/archiver/jar/JarArchiver.java` | Đổi đọc manifest sang try-with-resources để đóng stream. | Blob P = F, không sửa ở fix chung. |
| `src/main/java/org/codehaus/plexus/archiver/jar/JarToolModularJarArchiver.java` | Thêm triển khai tạo modular JAR bằng jar tool. | Blob P = F, không sửa ở fix chung. |
| `src/main/java/org/codehaus/plexus/archiver/jar/ModularJarArchiver.java` | Thêm lớp cấu hình moduleMainClass/moduleVersion. | Blob P = F, không sửa ở fix chung. |
| `src/main/java/org/codehaus/plexus/archiver/zip/AbstractZipArchiver.java` | Đổi mã hóa symlink qua ByteBuffer.limit; không đổi trong fix đang đo. | Blob P = F, không sửa ở fix chung. |
| `src/main/java/org/codehaus/plexus/archiver/zip/PlexusIoZipFileResourceCollection.java` | Bổ sung đóng URLClassLoader trong finally trước khi đóng ZIP. | Blob P = F, không sửa ở fix chung. |
| `src/test/java/org/codehaus/plexus/archiver/BasePlexusArchiverTest.java` | Đổi cơ chế chờ/cập nhật timestamp của test. | Blob P = F, không sửa ở fix chung. |
| `src/test/java/org/codehaus/plexus/archiver/jar/BaseJarArchiverTest.java` | Thêm lớp test nền cho các triển khai JAR. | Blob P = F, không sửa ở fix chung. |
| `src/test/java/org/codehaus/plexus/archiver/jar/JarArchiverTest.java` | Chuyển sang JUnit annotation và lớp nền BaseJarArchiverTest. | Blob P = F, không sửa ở fix chung. |
| `src/test/java/org/codehaus/plexus/archiver/jar/JarToolModularJarArchiverTest.java` | Thêm test modular JAR. | Blob P = F, không sửa ở fix chung. |
| `src/test/resources/java-src/com/example/app/Main.java` | Thêm ứng dụng Java mẫu cho resource test module. | Blob P = F, không sửa ở fix chung. |
| `src/test/resources/java-src/module-info.java` | Thêm module descriptor cho resource test. | Blob P = F, không sửa ở fix chung. |

Cả tệp guard và test của bản sửa đều được giữ. Guard chỉ so tiền tố đường dẫn; bằng chứng cũ vẫn ghi sibling-prefix FAIL ở bản sau, vì vậy không gán SAFE tổng quát. C1–C7 hoàn tất trong phạm vi đã đo không có nghĩa bản vá xử lý mọi ca.

## Ca 2: Git Client CVE-2019-10392 — 2 → 1 và mất ngữ cảnh hữu ích

Tệp còn lại `CliGitAPIImpl.java` chứa thay đổi kiểm tra remote URL/các điểm gọi Git; đây cũng là anchor Java của IRIS fix_info. Tệp bị loại `GitClientSecurityTest.java` đã được thêm trong S→P và có blob P = F, nên không còn là changed-path. Đọc source cho thấy test và fix message đều ghi **SECURITY-1534**, với các kiểm tra remote URL; do đó không được coi tệp này là nhiễu không liên quan. Không thực thi các test bảo mật đó trong lượt này.

Blob test P/F: `35b541d007bf979c82c7e391b8f28c8f92c26022`; SHA-256 cả file `c260188a742445132802cbd119b898c249d204080020cd46a46a7ee033ed2446`. Tệp vẫn có trong cả hai snapshot, chỉ bị bỏ khỏi chỉ mục phương thức thay đổi. Đã bổ sung [context-files.jsonl](../data/context-files.jsonl) với URL/commit/blob/hash. Context không thêm vào 409 mẫu và không tự mang nhãn binary.

Đây là trường hợp bất lợi về ngữ cảnh: lấy parent gần fix làm diff hẹp hơn nhưng có thể che một regression test cần đọc. Giải pháp là giữ tách biệt tập changed-callable và các tham chiếu ngữ cảnh, không tuyên bố cả 27 tệp bị loại là false positive của IRIS.

## Giới hạn và kết luận đúng mức

Đã xem xét đủ 20 CVE; mười đủ điều kiện, mười loại. Commons IO đổi fix `fe7543eee5cd4b2f9e78aa44c31031b68eba204d` sang `2736b6fe0b3fa22ec8e2b4184897ecadb021fc78`; công bố như hiệu chỉnh ánh xạ riêng. one-java-agent có hai fix tham chiếu nên không đại diện bằng một cặp để so full CVE. Tám hồ sơ còn lại thiếu seed object cục bộ; không phải kết luận chúng không thể so hoặc build được. Zip4j giữ chú thích benchmark_reconstruction.

Phép đo xác nhận **thu hẹp phạm vi changed-path ở cùng fix**, bổ sung kiểm tra 25/25 anchor IRIS còn giữ và một tham chiếu ngữ cảnh bất lợi. Chưa có phép đo precision/recall nhãn, công sức con người hay hiệu quả mô hình. Hai ca được đọc diff chi tiết không đại diện cho việc đã rà ngữ nghĩa mọi tệp bị loại.

## Tính lại bằng lệnh thật

```sh
python3 -m tools.compare_iris --out runs/iris-compare-new
# Trên bản giải nén: truyền --pilot-repos, --batch-repos, --fallback-repos tới cache ngoài gói.
```

Các patch đầy đủ chỉ lưu trong runs/improvement_20261125/raw-diffs trên máy thực hiện; không đóng gói source bên thứ ba. JSON chứa băm diff, danh sách path, blob và cây; lệnh Git với ba SHA trong bảng cho phép đọc lại diff từ cache hoặc upstream.
