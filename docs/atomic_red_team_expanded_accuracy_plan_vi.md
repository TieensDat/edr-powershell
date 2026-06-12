# Bộ test Atomic Red Team mở rộng để đánh giá telemetry và detection

## 1. Mục tiêu

Bộ test này được xây dựng để mở rộng ngoài 12 Atomic Red Team test ban đầu. Mục tiêu không chỉ là kiểm tra PythonAgent có thu được telemetry hay không, mà còn đánh giá verdict có hợp lý theo ngữ cảnh hành vi hay không.

Điểm khác so với runner cũ:

- Runner cũ: test được xem là pass nếu có telemetry.
- Runner mới: test được xem là pass nếu thỏa cả ba nhóm:
  - `telemetry_pass`: có event agent ghi nhận.
  - `source_pass`: event đến từ sensor phù hợp.
  - `verdict_pass`: `observed_max_verdict` nằm trong khoảng kỳ vọng.

Nguồn tham chiếu:

- Atomic Red Team là thư viện test được ánh xạ với MITRE ATT&CK, dùng để kiểm thử môi trường một cách nhanh và lặp lại được: https://github.com/redcanaryco/atomic-red-team
- MITRE ATT&CK mô tả PowerShell có thể được dùng để discovery, download và thực thi mã: https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK mô tả Ingress Tool Transfer gồm PowerShell, certutil và các tiện ích native để tải file: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK mô tả mshta.exe là signed binary có thể proxy execution của script/HTA: https://attack.mitre.org/techniques/T1218/005/

## 2. File được bổ sung

```text
tests/atomic_red_team/expanded_atomic_accuracy_tests.json
tests/atomic_red_team/run_atomic_accuracy_tests.ps1
```

File `expanded_atomic_accuracy_tests.json` là danh sách test mở rộng. Mỗi test có thêm kỳ vọng:

- `set`: `tuning` hoặc `holdout`.
- `category`: nhóm hành vi.
- `expected_sources_any`: sensor kỳ vọng ghi nhận.
- `expected_min_verdict`: verdict thấp nhất chấp nhận được.
- `expected_max_verdict`: verdict cao nhất chấp nhận được.
- `run_as_admin`: test có nên chạy bằng PowerShell Administrator hay không.
- `rationale`: lý do chọn test và kỳ vọng verdict.

## 3. Nhóm hành vi trong bộ test

| Nhóm | Mục tiêu kiểm tra |
|---|---|
| PowerShell execution | Command variation, EncodedCommand, obfuscated execution, known malicious cmdlets. |
| PowerShell fileless | Registry-staged payload, NTFS alternate data stream. |
| Obfuscation | Base64, registry encoded payload, character array, obfuscated PowerShell. |
| Discovery | Locale, process, directory, user, environment, remote/network discovery. |
| Ingress/download | PowerShell download, certutil, BITSAdmin. |
| Registry/persistence | Run key, RunOnce, registry-staged payload. |
| Registry modification | WDigest credential setting, JavaScript in registry, PowerShell execution policy. |
| Defense evasion | PowerShell logging disabled, tampering-like registry behavior. |
| Scheduled task | schtasks.exe, PowerShell scheduled task, encoded command from registry. |
| LOLBins gọi PowerShell | mshta, regsvr32, rundll32. |

## 4. Nguyên tắc gán expected verdict

Không nên xem mọi Atomic test là malicious cần `TERMINATE`. Atomic Red Team mô phỏng kỹ thuật ATT&CK, nhưng mức độ nguy hiểm phụ thuộc vào chuỗi hành vi.

Quy ước trong bộ test:

- Discovery-only: `ALLOW` hoặc `ALERT`, không được `TERMINATE`.
- Obfuscation-only: thường là `ALERT`, không `TERMINATE` nếu không có payload/chạy tiếp.
- Download-only: `ALERT`, không `TERMINATE` nếu chưa execute.
- Download + execute, registry staging + execute, scheduled task + encoded registry payload: có thể `TERMINATE`.
- AMSI bypass, Defender/logging tampering, WDigest credential registry modification: `TERMINATE`.
- LOLBin gọi PowerShell/script: tối thiểu `ALERT`; `TERMINATE` chỉ hợp lý nếu có remote payload, encoded payload hoặc execution chain rõ hơn.

## 5. Cách chạy bộ tuning

Chạy PythonAgent trước:

```powershell
cd C:\KLTN\mini-edr-powershell
python .\PythonAgent\PythonAgent.py
```

Mở cửa sổ PowerShell khác và chạy:

```powershell
cd C:\KLTN\mini-edr-powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\atomic_red_team\run_atomic_accuracy_tests.ps1 -Set tuning
```

Mặc định lệnh trên chỉ chạy các test không yêu cầu Administrator. Các test có `run_as_admin = true` nên chạy riêng trong cửa sổ PowerShell Administrator:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\atomic_red_team\run_atomic_accuracy_tests.ps1 `
  -Set tuning `
  -AdminOnly `
  -ReportPath .\tests\atomic_red_team\atomic_accuracy_tuning_admin_report.json
```

Nếu muốn chạy cả test thường và test admin trong cùng một lần, dùng `-IncludeAdmin` trong cửa sổ PowerShell Administrator:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\atomic_red_team\run_atomic_accuracy_tests.ps1 `
  -Set tuning `
  -IncludeAdmin `
  -ReportPath .\tests\atomic_red_team\atomic_accuracy_tuning_all_report.json
```

Nếu muốn lưu report với tên cụ thể:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\atomic_red_team\run_atomic_accuracy_tests.ps1 `
  -Set tuning `
  -ReportPath .\tests\atomic_red_team\atomic_accuracy_tuning_report.json
```

## 6. Cách chạy holdout

Chỉ chạy holdout sau khi đã tuning xong bằng nhóm `tuning`.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\atomic_red_team\run_atomic_accuracy_tests.ps1 `
  -Set holdout `
  -ReportPath .\tests\atomic_red_team\atomic_accuracy_holdout_report.json
```

Với holdout admin:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\atomic_red_team\run_atomic_accuracy_tests.ps1 `
  -Set holdout `
  -AdminOnly `
  -ReportPath .\tests\atomic_red_team\atomic_accuracy_holdout_admin_report.json
```

Không nên dùng lỗi trong holdout để tuning ngay lập tức. Nếu dùng holdout để chỉnh rule, cần tạo một holdout mới khác.

## 7. Cách đọc kết quả

Runner sinh ra hai file:

```text
atomic_accuracy_report_YYYYMMDD_HHMMSS.json
atomic_accuracy_report_YYYYMMDD_HHMMSS.csv
```

Các trường quan trọng:

- `status`: test có thực thi hay bị skip prerequisite/error.
- `observed_event_count`: số event agent ghi nhận sau khi chạy test.
- `observed_sources`: sensor ghi nhận event.
- `observed_max_verdict`: verdict cao nhất agent đưa ra trong test đó.
- `telemetry_pass`: đúng/sai theo kỳ vọng telemetry.
- `source_pass`: đúng/sai theo kỳ vọng sensor.
- `verdict_pass`: đúng/sai theo kỳ vọng verdict.
- `accuracy_pass`: kết quả tổng hợp.

## 8. Quy trình tuning đề xuất

1. Chạy lại `verdict_tuning` để đảm bảo baseline logic vẫn ổn.
2. Chạy `Atomic accuracy - tuning set`.
3. Phân loại lỗi:
   - Không có telemetry: thiếu sensor hoặc process chưa nằm trong watch list.
   - Sai source: sensor ghi nhận không đúng kỳ vọng.
   - Verdict quá thấp: rule/feature chưa bắt được hành vi.
   - Verdict quá cao: false positive hoặc over-response.
4. Chỉ tuning trên nhóm `tuning`.
5. Sau mỗi lần tuning, chạy lại:
   - `verdict_tuning`
   - `Atomic accuracy - tuning set`
   - response test nếu có thay đổi response/verdict
6. Khi tuning set ổn định, chạy `holdout`.
7. Nếu holdout fail, ghi nhận là residual risk hoặc tạo vòng tuning mới với holdout khác.

## 9. Lưu ý để tránh overfitting

- Không được sửa rule chỉ để pass một test nếu logic đó làm sai các test benign/discovery.
- Không dùng ML verdict một mình để nâng lên `TERMINATE`.
- Discovery-only không nên bị kill/quarantine.
- Download-only nên là `ALERT`; download + execute mới đủ cơ sở nâng lên `TERMINATE`.
- Event Log 4104 thiếu PID tin cậy nên không dùng riêng nó để kill process.
- Với LOLBins như `mshta.exe`, `regsvr32.exe`, `rundll32.exe`, cần phân biệt telemetry/detection và response. Ghi nhận hoặc alert là hợp lý; terminate cần thêm payload chain rõ ràng.

## 10. Kỳ vọng sau khi mở rộng

Bộ test này có thể phát hiện các vấn đề mà 12 test ban đầu chưa bao phủ:

- `certutil`/`bitsadmin` download có được process sensor ghi nhận hay không.
- Discovery benign có còn bị `TERMINATE` hay không.
- PowerShell download-only có bị over-response hay không.
- Registry/scheduled task persistence có được phân biệt với registry read benign hay không.
- LOLBins gọi PowerShell có được phát hiện qua process sensor hay không.

Kết quả cuối cùng nên được báo cáo theo ba chỉ số riêng:

- Telemetry coverage rate.
- Detection/verdict accuracy rate.
- Over-response / false-positive cases.
