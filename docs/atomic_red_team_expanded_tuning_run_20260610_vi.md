# Tổng hợp chạy Atomic Red Team mở rộng để phục vụ tuning

Thời điểm chạy: 10/06/2026

Mục tiêu của đợt chạy này là mở rộng số lượng test Atomic Red Team ngoài 12 test ban đầu, nhằm đánh giá thêm độ chính xác của telemetry và verdict trước khi tiếp tục tuning logic kết hợp ML + rule. Các test được ưu tiên là PowerShell execution, discovery, ingress/download, registry/persistence, scheduled task và LOLBins.

## 1. Các report đã sinh ra

| Nhóm chạy | Report JSON | Kết quả chính |
|---|---|---|
| Gap 4688 sau khi bổ sung Security 4688 sensor | `tests/atomic_red_team/atomic_gap_4688_report_20260610_193658.json` | 2/2 pass |
| Holdout non-admin sau chỉnh kỳ vọng source | `tests/atomic_red_team/atomic_accuracy_holdout_non_admin_report_20260610_194851.json` | 3/4 pass, 1 skipped prereq |
| Expanded all non-admin | `tests/atomic_red_team/atomic_accuracy_all_non_admin_report_20260610_195040.json` | 23 executed, 19 pass, 4 fail, 3 skipped prereq |
| Broad non-admin batch | `tests/atomic_red_team/atomic_accuracy_all_non_admin_report_20260610_200237.json` | 12 executed, 10 pass, 2 fail |
| Full `Set=all` elevated sau tuning PowerShell logging | `tests/atomic_red_team/atomic_accuracy_all_include_admin_after_logging_tune_report_20260610_215420.json` | 29 executed, 29 pass, 0 fail, 3 skipped prereq |

Lưu ý: các tỷ lệ trên không nên cộng trực tiếp thành một accuracy cuối cùng vì có một số case trùng nhau và một số lần chạy không có quyền đọc Security Event Log 4688.

## 2. Kết quả đáng chú ý

### 2.1. Các case đã được chứng minh pass khi có 4688

Hai case từng bị gap do process quá ngắn đã pass khi bật Security 4688 process creation telemetry:

| Case | Technique | Mô tả | Kết quả |
|---|---|---|---|
| `ART-ACC-021` | T1547.001-1 | Reg Key Run | Pass qua `eventlog_4688_sensor`, verdict `ALERT` |
| `ART-ACC-027` | T1053.005-2 | Scheduled task Local | Pass qua `eventlog_4688_sensor`, verdict `ALERT` |

Điều này cho thấy việc bổ sung 4688 là đúng hướng đối với `reg.exe`, `schtasks.exe` và các LOLBins/process ngắn.

### 2.2. Fail do chạy agent không elevated, không phải do detection logic

Các case dưới đây fail chủ yếu vì PythonAgent trong lần chạy non-admin không đọc được Security Event Log 4688:

| Case | Mô tả | Nhận xét |
|---|---|---|
| `ART-ACC-021` | Reg Key Run | Đã pass ở report gap 4688 khi chạy elevated |
| `ART-ACC-027` | Scheduled task Local | Đã pass ở report gap 4688 khi chạy elevated |
| `ART-ACC-029` | Scheduled task + Base64 + Registry | Non-admin không thấy telemetry; cần chạy lại elevated |
| `ART-BROAD-011` | Discover OS Product Name via Registry | Lệnh `reg query` rất ngắn, cần 4688 để ghi nhận ổn định |
| `ART-BROAD-012` | Discover OS Build Number via Registry | Tương tự, cần 4688 để ghi nhận ổn định |

Kết luận: nhóm này không nên dùng để tuning rule khi agent không chạy elevated. Cần chạy lại từ checkpoint lab với PythonAgent elevated và process creation auditing đã bật.

### 2.3. Case cần xem xét tuning thật sự

| Case | Mô tả | Kết quả hiện tại | Kỳ vọng |
|---|---|---|---|
| `ART-ACC-006` | NTFS Alternate Data Stream Access | Có telemetry, max verdict `TERMINATE` | Nên cân nhắc chỉ `ALERT` |

Lý do cần xem xét: case ADS có `Invoke-Expression` từ alternate data stream nên đáng nghi, nhưng payload Atomic chỉ in chuỗi demo `"Stream Data Executed"`. Nếu mục tiêu response là conservative opt-in, `TERMINATE` nên dành cho chain mạnh hơn như credential theft, defense evasion rõ ràng, persistence + encoded execution, hoặc malicious cmdlet/high-confidence payload.

Không nên tuning ngay chỉ dựa vào một case. Nên chạy riêng `ART-ACC-006` và lưu các event gây `TERMINATE` để xác định verdict đến từ script payload hay từ telemetry phụ của Atomic runner.

## 3. Các prereq còn thiếu

| Case | Prereq thiếu | Cách xử lý |
|---|---|---|
| `ART-ACC-001`, `ART-ACC-002` | Module `AtomicTestHarnesses` | Cài prereq bằng `Invoke-AtomicTest T1059.001 -TestNumbers 13,15 -GetPrereqs` |
| `ART-ACC-031` | `C:\AtomicRedTeam\atomics\T1218.010\src\RegSvr32.sct` | Cài prereq bằng `Invoke-AtomicTest T1218.010 -TestNumbers 1 -GetPrereqs` |

Do lần chạy hiện tại không tải được prereq qua network trong môi trường Codex, các case này chưa được tính vào kết luận accuracy cuối cùng.

## 4. Kết quả sau khi chạy lại elevated và tuning `ART-ACC-026`

Sau khi chạy lại `Set=all` bằng quyền Administrator, 29/29 case đã thực thi đều đạt tiêu chí accuracy, không còn case fail. Ba case còn lại bị `SKIPPED_PREREQ`, gồm:

| Case | Nguyên nhân skip | Nhận xét |
|---|---|---|
| `ART-ACC-001` | Atomic vẫn chưa nhận `AtomicTestHarnesses` trong ngữ cảnh prereq của runner | Đây là lỗi prereq/module context của Atomic, không phải lỗi detection của PythonAgent |
| `ART-ACC-002` | Tương tự `ART-ACC-001` | Cần xử lý riêng bằng cách bảo đảm module được import/export đúng trong PowerShell session chạy Atomic |
| `ART-ACC-031` | Thiếu `RegSvr32.sct` tại `C:\AtomicRedTeam\atomics\T1218.010\src\RegSvr32.sct` | File prereq đã được cài thử nhưng có khả năng bị Windows Defender xóa/quarantine nên Atomic vẫn skip |

Kết quả tổng hợp của report sau tuning:

| Chỉ số | Giá trị |
|---|---:|
| Tổng số case chọn | 32 |
| Số case thực thi | 29 |
| Số case skipped prereq | 3 |
| Số case lỗi runtime | 0 |
| Số case pass accuracy | 29 |
| Số case fail accuracy | 0 |
| Accuracy trên nhóm đã thực thi | 100% |

Điểm tuning thực sự được xác nhận là `ART-ACC-026` - Windows PowerShell Logging Disabled. Trước tuning, case này có telemetry qua `eventlog_4688_sensor` nhưng verdict tối đa chỉ đạt `ALERT`, thấp hơn kỳ vọng `TERMINATE`. Sau tuning, PythonAgent bổ sung indicator hẹp cho hành vi vô hiệu hóa PowerShell logging bằng thao tác registry write với giá trị disable (`0`/`DWORD:00000000`). Kết quả sau tuning: `ART-ACC-026` đạt `TERMINATE`.

`ART-ACC-006` không được tuning vì bằng chứng elevated không xác nhận over-response. Case này có verdict tối đa `ALERT`, đúng kỳ vọng hiện tại đối với hành vi NTFS Alternate Data Stream có yếu tố đáng nghi nhưng chưa đủ chắc chắn để terminate.

## 5. Nhận xét về false positive

Trong broad batch, nhiều discovery PowerShell có ML verdict `MALICIOUS`, nhưng final verdict vẫn nằm trong khoảng `ALLOW/ALERT`, không bị `TERMINATE`. Điều này cho thấy policy kết hợp rule + ML hiện tại đã giảm được một phần rủi ro dương tính giả từ ML.

Tuy nhiên, ML vẫn có dấu hiệu nhạy quá mức với discovery/admin script. Vì vậy:

- Chưa nên retrain model ngay chỉ vì Atomic discovery có một số ML malicious.
- Nên tiếp tục dùng rule/policy để giới hạn `TERMINATE`.
- Nếu tập benign lớn sau này vẫn cho FP cao, lúc đó mới nên bổ sung benign dataset và retrain model.

## 6. Việc nên làm tiếp theo

1. Xử lý riêng 3 case skipped prereq nếu cần tăng độ phủ Atomic lên đủ 32/32.
2. Không tuning `ART-ACC-006` ở thời điểm hiện tại vì evidence elevated cho thấy verdict `ALERT` là phù hợp.
3. Tiếp tục dùng nhóm expanded Atomic này như regression/holdout sau mỗi lần chỉnh rule.
4. Nếu xuất hiện false positive ổn định trên nhiều nhóm benign/discovery lớn hơn, lúc đó mới cân nhắc quay lại bài toán retraining model.
