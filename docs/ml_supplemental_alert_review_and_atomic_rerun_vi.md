# Review ALERT còn lại và kế hoạch chạy lại Atomic

Ngày thực hiện: 2026-06-12

## 1. Mục tiêu

Sau khi chuyển ML sang vai trò tín hiệu phụ, số lượng cảnh báo đã giảm mạnh. Bước này review các mẫu còn `ALERT/TERMINATE` để xác định:

- mẫu nào là cảnh báo chấp nhận được,
- mẫu nào là ứng viên false positive,
- mẫu nào cần runtime test,
- mẫu nào chưa đủ context để tuning.

Mục tiêu là tránh tuning quá tay làm mất detection, đồng thời chuẩn bị chạy lại Atomic Red Team trong VM lab để kiểm tra attack simulation sau thay đổi ML policy.

## 2. Nguồn dữ liệu review

Các report được dùng:

```text
datasets/powershell_gallery/behavior_groups_80/reports_ml_supplemental_current/
datasets/chocolatey/behavior_groups_80_casefixed/reports_ml_supplemental_current/
datasets/the_stack/powershell_pilot/reports_ml_supplemental_current/
```

File review chi tiết:

```text
datasets/review/ml_supplemental_alert_review.csv
```

Tổng số mẫu cần review:

| Dataset | ALERT/TERMINATE |
|---|---:|
| PowerShell Gallery | 16 |
| Chocolatey | 27 |
| The Stack pilot | 27 |
| **Tổng** | **70** |

## 3. Phân loại sơ bộ

| Nhãn review | Số mẫu | Ý nghĩa |
|---|---:|---|
| `acceptable_alert` | 27 | Hành vi dual-use/admin/installer/security đủ nhạy cảm để giữ cảnh báo |
| `true_fp_candidate` | 13 | Nghiêng về false positive, có thể tuning tiếp nếu pattern lặp lại rõ |
| `needs_runtime_test` | 3 | Cần chạy runtime trong VM checkpoint trước khi hạ alert |
| `suspicious_public_code` | 4 | Public code đáng nghi, không xem là benign |
| `unknown_needs_context` | 23 | Thiếu context repo/runtime, chưa nên tuning |

Theo dataset:

| Dataset | acceptable_alert | true_fp_candidate | needs_runtime_test | suspicious_public_code | unknown_needs_context |
|---|---:|---:|---:|---:|---:|
| PowerShell Gallery | 3 | 13 | 0 | 0 | 0 |
| Chocolatey | 24 | 0 | 3 | 0 | 0 |
| The Stack pilot | 0 | 0 | 0 | 4 | 23 |

## 4. Nhận xét PowerShell Gallery

PowerShell Gallery còn 16 mẫu cảnh báo.

Trong đó:

- 3 mẫu là `acceptable_alert`:
  - `RunAsUser`: liên quan chạy dưới user context, encoded command, execution policy, registry.
  - `DSInternals`: security/credential-related module, có tính dual-use.

- 13 mẫu là `true_fp_candidate`, gồm các nhóm:
  - AWS completer generated scripts.
  - HP warranty SOAP/API helper.
  - Carbon environment variable helper.
  - VSTeam, PowerShellForGitHub, BuildHelpers.
  - ModuleBuilder.
  - powershell-yaml test fixture.
  - NtpTime, PowerHTML.

Kết luận cho PowerShell Gallery:

- Có thể tuning tiếp một vòng nhỏ cho các pattern thật sự benign như generated completer, test fixture, manifest/API metadata.
- Không nên hạ alert cho `RunAsUser` và `DSInternals` nếu chưa có chính sách trust theo package/source.

## 5. Nhận xét Chocolatey

Chocolatey còn 27 mẫu cảnh báo.

Trong đó:

- 24 mẫu là `acceptable_alert`.
- 3 mẫu là `needs_runtime_test`:
  - `jdk8` - `tools\common.ps1`
  - `openjdk` - `tools\chocolateyBeforeModify.ps1`
  - `sysinternals` - `tools\helpers.ps1`

Phần lớn Chocolatey alert đến từ installer/update scripts có các hành vi:

- tải installer,
- kiểm tra URL/checksum,
- silent install,
- sửa môi trường,
- gọi process hoặc helper.

Kết luận cho Chocolatey:

- Không nên hạ toàn bộ Chocolatey installer xuống `ALLOW`, vì hành vi installer/download là dual-use.
- Chỉ nên hạ alert cho helper/checksum/metadata nếu runtime test xác nhận không tạo telemetry nguy hiểm.
- 3 mẫu `needs_runtime_test` nên được chạy trong VM checkpoint trước khi tuning.

## 6. Nhận xét The Stack

The Stack còn 27 mẫu cảnh báo, gồm:

- 3 mẫu `TERMINATE`.
- 24 mẫu `ALERT`.

Phân loại:

- 4 mẫu `suspicious_public_code`.
- 23 mẫu `unknown_needs_context`.

The Stack là public code ngoài miền, không phải benign corpus đã xác minh. Vì vậy:

- Không được xem alert trên The Stack là false positive mặc định.
- Không nên tuning trực tiếp dựa trên The Stack pilot.
- Chỉ dùng The Stack để kiểm tra generalization và chọn mẫu review.

Kết luận cho The Stack:

- Cần review thủ công 3 mẫu `TERMINATE` trước.
- Nếu muốn dùng The Stack để retrain/tuning, phải gán nhãn thủ công và tách train/validation/holdout.

## 7. Khuyến nghị tuning tiếp

Chưa nên retrain ngay. Hướng tiếp theo:

1. Tuning nhỏ cho PowerShell Gallery `true_fp_candidate` nếu pattern rõ:
   - generated completer,
   - test fixture,
   - manifest/API metadata,
   - vendor SOAP/API helper.

2. Không tuning từ The Stack pilot nếu chưa review thủ công.

3. Chocolatey chỉ tuning thêm sau runtime test 3 helper/common scripts.

4. Sau mỗi tuning nhỏ phải chạy lại:
   - PowerShell Gallery ML-supplemental,
   - Chocolatey ML-supplemental,
   - The Stack pilot,
   - Atomic expanded.

## 8. Chạy lại Atomic trong VM lab

Lần chạy Atomic trên máy hiện tại bị dừng vì Windows Defender chặn file log:

```text
PythonAgent\logs\edr_events.jsonl
Operation did not complete successfully because the file contains a virus or potentially unwanted software.
```

Do đó cần chạy lại Atomic trong VM lab theo quy trình có checkpoint.

### 8.1. Chuẩn bị checkpoint

Trên Hyper-V:

```text
Checkpoint: CP_Atomic_ML_Supplemental_BeforeRun
```

Trước khi chạy:

- VM đã cài Atomic Red Team.
- PythonAgent chạy được.
- PowerShell Script Block Logging đã bật nếu cần Event 4104.
- Nếu dùng 4688, chạy PythonAgent bằng quyền Administrator.
- Đảm bảo thư mục log không bị Defender chặn trong lúc test.

Nếu cần xử lý Defender chặn log trong môi trường lab, chỉ dùng exclusion có kiểm soát cho thư mục log, không exclude toàn bộ repo:

```powershell
Add-MpPreference -ExclusionPath "C:\KLTN\mini-edr-powershell\PythonAgent\logs"
```

Sau khi test xong phải gỡ exclusion:

```powershell
Remove-MpPreference -ExclusionPath "C:\KLTN\mini-edr-powershell\PythonAgent\logs"
```

Lưu ý: chỉ dùng cách này trong VM lab/có checkpoint, và ghi rõ trong báo cáo nếu áp dụng.

### 8.2. Chạy non-admin trước

```powershell
cd C:\KLTN\mini-edr-powershell

powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tests\atomic_red_team\run_atomic_accuracy_with_agent.ps1 `
  -Set all `
  -ReportPath .\tests\atomic_red_team\atomic_accuracy_all_non_admin_ml_supplemental_rerun.json `
  -TimeoutSeconds 30 `
  -SettleSeconds 5
```

### 8.3. Chạy admin cases nếu cần

Chỉ chạy sau khi non-admin pass ổn và VM có checkpoint:

```powershell
cd C:\KLTN\mini-edr-powershell

powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tests\atomic_red_team\run_atomic_accuracy_with_agent.ps1 `
  -Set all `
  -IncludeAdmin `
  -ReportPath .\tests\atomic_red_team\atomic_accuracy_all_include_admin_ml_supplemental_rerun.json `
  -TimeoutSeconds 30 `
  -SettleSeconds 5
```

### 8.4. Tiêu chí đánh giá Atomic

Kết quả cần kiểm tra:

- `Accuracy rate` không giảm so với report trước tuning.
- Các case `EncodedCommand`, fileless, registry/persistence, downloader vẫn đạt kỳ vọng.
- Discovery/benign execution không bị nâng quá mức lên `TERMINATE`.
- ML-only malicious không tự tạo alert nếu rule/risk không xác nhận.

## 9. Quyết định tuning hay retrain

Sau review và Atomic rerun:

- Nếu alert còn lại chủ yếu là `acceptable_alert`, có thể dừng tuning.
- Nếu nhiều `true_fp_candidate` lặp lại theo cùng pattern, tuning rule/policy thêm một vòng nhỏ.
- Nếu ML vẫn báo `MALICIOUS` nhiều trên benign corpus đã xác minh, nhưng policy phải chặn quá nhiều, khi đó mới nên retrain model với benign dataset lớn hơn.

Kết luận hiện tại:

```text
Chưa cần retrain ngay.
Ưu tiên review ALERT còn lại và chạy lại Atomic trong VM lab.
Sau đó mới quyết định tuning tiếp hay retraining.
```
