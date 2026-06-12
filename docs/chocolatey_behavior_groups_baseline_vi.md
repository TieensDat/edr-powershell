# Baseline Chocolatey theo 7 nhóm hành vi benign

Thời điểm thực hiện: 11/06/2026

Mục tiêu của batch này là dùng Chocolatey Community Package Feed làm tập benign độc lập sau PowerShell Gallery. Khác với PowerShell Gallery, Chocolatey chứa nhiều script installer thực tế như `chocolateyInstall.ps1`, `chocolateyUninstall.ps1`, tải MSI/EXE, sửa registry, PATH, service hoặc scheduled task. Vì vậy kết quả `ALERT` không mặc định là false positive; cần phân biệt `true FP` và `acceptable alert`.

Lưu ý an toàn: batch này chỉ tải `.nupkg`, giải nén và phân tích tĩnh script `.ps1`. Không cài Chocolatey package và không thực thi installer.

## 1. Script sử dụng

Thu thập dataset:

```text
tests/chocolatey/collect_chocolatey_behavior_groups.ps1
```

Đánh giá tĩnh bằng PythonAgent:

```text
tests/chocolatey/evaluate_chocolatey_static.py
tests/chocolatey/run_chocolatey_baseline.ps1
```

Output chính:

```text
datasets/chocolatey/behavior_groups_80_casefixed/
```

## 2. Cấu hình thu thập

| Tham số | Giá trị |
|---|---:|
| Số nhóm hành vi | 7 |
| Tổng package mục tiêu | 80 |
| Số package thu được | 68 |
| Số file PowerShell thu được | 135 |
| Tối đa file/package | 3 |
| Kích thước file tối đa | 200 KB |
| Kích thước package tối đa | 50 MB |

Manifest dữ liệu:

```text
datasets/chocolatey/behavior_groups_80_casefixed/metadata/packages_manifest.csv
datasets/chocolatey/behavior_groups_80_casefixed/metadata/files_manifest.csv
datasets/chocolatey/behavior_groups_80_casefixed/metadata/skipped_manifest.csv
datasets/chocolatey/behavior_groups_80_casefixed/metadata/collection_summary.json
```

## 3. Nhóm hành vi

| Nhóm | Package | File |
|---|---:|---:|
| Browser/user apps | 10 | 24 |
| Dev tools | 8 | 14 |
| Runtime/language | 8 | 18 |
| Sysadmin utilities | 11 | 23 |
| Security tools benign | 8 | 15 |
| Package/dependency tools | 12 | 22 |
| Windows maintenance/config | 11 | 19 |
| Tổng | 68 | 135 |

Các item bị skip:

| Lý do skip | Số lượng |
|---|---:|
| Không có script `.ps1` phù hợp hoặc file vượt giới hạn | 20 |
| Package không tìm thấy qua feed | 2 |
| Package quá lớn theo metadata | 9 |

Nhận xét: một số package Chocolatey không chứa script PowerShell trực tiếp hoặc package quá lớn vì đóng gói installer. Việc skip các package này giúp baseline chạy ổn định và tránh timeout.

## 4. Baseline ban đầu

Report ban đầu:

```text
datasets/chocolatey/behavior_groups_80_casefixed/reports_baseline/
```

Kết quả theo nhóm:

| Nhóm | File đánh giá | ALLOW | ALERT | TERMINATE |
|---|---:|---:|---:|---:|
| Browser/user apps | 24 | 19 | 5 | 0 |
| Dev tools | 14 | 13 | 1 | 0 |
| Runtime/language | 18 | 15 | 3 | 0 |
| Sysadmin utilities | 23 | 16 | 7 | 0 |
| Security tools benign | 15 | 12 | 3 | 0 |
| Package/dependency tools | 22 | 19 | 2 | 1 |
| Windows maintenance/config | 19 | 13 | 6 | 0 |
| Tổng | 135 | 107 | 27 | 1 |

Kết quả theo loại script:

| Script type | File đánh giá | ALLOW | ALERT | TERMINATE |
|---|---:|---:|---:|---:|
| `install` | 63 | 44 | 18 | 1 |
| `uninstall` | 39 | 35 | 4 | 0 |
| `beforemodify` | 9 | 8 | 1 | 0 |
| `helper` | 24 | 20 | 4 | 0 |

Nhận xét:

- Phần lớn cảnh báo nằm ở `chocolateyInstall.ps1`, phù hợp với bản chất installer: tải file, gọi MSI/EXE, chỉnh registry/PATH/service.
- `TERMINATE` duy nhất là package `PowerShell`, do script hợp lệ có `schtasks.exe`, registry write và `Invoke-Expression` để phục hồi `PSModulePath` khi nâng WMF/PowerShell. Đây là over-response ở mức response, nhưng vẫn nên giữ `ALERT`.

## 5. Tuning response cho Chocolatey installer context

Điều chỉnh trong PythonAgent:

- Bổ sung nhận diện Chocolatey installer chuẩn thông qua script path như `chocolateyInstall.ps1`, `chocolateyUninstall.ps1`, `chocolateyBeforeModify.ps1`.
- Chỉ cap `TERMINATE -> ALERT` khi script có context Chocolatey chuẩn và không có tín hiệu tuyệt đối như:
  - credential theft;
  - AMSI bypass;
  - chỉnh/tắt Defender hoặc PowerShell logging;
  - clear event log;
  - memory injection nhiều chỉ báo;
  - download-execute trực tiếp.
- Không hạ `ALERT` xuống `ALLOW` cho installer context vì hành vi installer vẫn là dual-use.

Mục tiêu tuning: giảm over-response trên benign installer, không làm mất cảnh báo.

## 6. Kết quả sau tuning

Report sau tuning:

```text
datasets/chocolatey/behavior_groups_80_casefixed/reports_after_choco_terminate_tune/
```

Kết quả theo nhóm:

| Nhóm | File đánh giá | ALLOW | ALERT | TERMINATE |
|---|---:|---:|---:|---:|
| Browser/user apps | 24 | 19 | 5 | 0 |
| Dev tools | 14 | 13 | 1 | 0 |
| Runtime/language | 18 | 15 | 3 | 0 |
| Sysadmin utilities | 23 | 16 | 7 | 0 |
| Security tools benign | 15 | 12 | 3 | 0 |
| Package/dependency tools | 22 | 19 | 3 | 0 |
| Windows maintenance/config | 19 | 13 | 6 | 0 |
| Tổng | 135 | 107 | 28 | 0 |

Kết quả theo loại script:

| Script type | File đánh giá | ALLOW | ALERT | TERMINATE |
|---|---:|---:|---:|---:|
| `install` | 63 | 44 | 19 | 0 |
| `uninstall` | 39 | 35 | 4 | 0 |
| `beforemodify` | 9 | 8 | 1 | 0 |
| `helper` | 24 | 20 | 4 | 0 |

Danh sách cảnh báo duy nhất sau tuning:

```text
datasets/chocolatey/behavior_groups_80_casefixed/reports_after_choco_terminate_tune/unique_alert_or_terminate_results.csv
```

## 7. Nguyên nhân cảnh báo phổ biến

| Reason | Số lần |
|---|---:|
| Network indicator present | 28 |
| Registry access or modification | 14 |
| Obfuscation operators | 10 |
| Downloader behavior | 10 |
| Suspicious LOLBin/process reference | 5 |
| Persistence behavior | 2 |
| Dynamic execution via IEX/Invoke-Expression | 2 |

Nhận xét:

- Đây là pattern hợp lý với Chocolatey: installer thường chứa URL, checksum, registry uninstall key, silent args, MSI/EXE installer và package helper.
- Không nên hạ toàn bộ `ALERT` còn lại xuống `ALLOW`, vì nhiều installer benign có hành vi giống attacker ở mức telemetry.
- Các nhóm cần review tiếp là `sysadmin_utilities`, `windows_maintenance_config`, `browser_user_apps` và `package_dependency_tools`.

## 8. Phân loại sơ bộ ALERT còn lại

Các mẫu còn `ALERT` nên chia thành ba nhóm:

1. Acceptable alert:
   - installer tải MSI/EXE từ vendor;
   - chỉnh registry/PATH/service hợp lệ;
   - cài công cụ admin/security như Sysinternals, OpenSSH, osquery;
   - có scheduled task/service nhưng trong ngữ cảnh installer rõ ràng.

2. True FP candidate:
   - helper chỉ chứa URL/checksum/metadata;
   - registry read phục vụ kiểm tra version/uninstall key;
   - downloader helper không thực thi payload trực tiếp.

3. Needs runtime test:
   - script có `schtasks.exe`, service manipulation, `Invoke-Expression`, hoặc persistence-like behavior;
   - nên chạy thật trong VM checkpoint để xem telemetry runtime thay vì chỉ dựa vào static verdict.

Trong vòng này chỉ tuning `TERMINATE -> ALERT` cho Chocolatey installer chuẩn. Chưa hạ tiếp các `ALERT` còn lại vì cần review thủ công từng mẫu và chạy Atomic regression trước/sau mỗi thay đổi.

## 9. Atomic regression sau tuning Chocolatey

Sau tuning, chạy lại Atomic expanded ở chế độ non-admin:

```text
tests/atomic_red_team/atomic_accuracy_all_non_admin_after_choco_tune_20260611_175444.json
tests/atomic_red_team/atomic_accuracy_all_non_admin_after_choco_tune_20260611_175444.csv
```

Kết quả:

| Chỉ số | Giá trị |
|---|---:|
| Selected | 26 |
| Executed | 21 |
| Skipped prereq | 4 |
| Errors | 1 |
| Accuracy passed | 18 |
| Accuracy failed | 3 |
| Accuracy rate | 85.71% |

Các case fail:

| ID | Nhóm | Nhận xét |
|---|---|---|
| `ART-ACC-019` | Ingress/download | Không có telemetry trong phiên non-admin (`observed_event_count = 0`). |
| `ART-ACC-021` | Registry persistence | Không có telemetry 4688 trong phiên non-admin. |
| `ART-ACC-027` | Scheduled task | Không có telemetry 4688 trong phiên non-admin. |

Nhận xét regression:

- Thay đổi Chocolatey chỉ cap verdict trong context `chocolateyInstall.ps1`/`chocolateyUninstall.ps1`, nên không tác động trực tiếp đến Atomic payload thông thường.
- Các fail trong phiên non-admin là vấn đề telemetry/runtime condition, không phải bằng chứng rule bị hạ sai.
- Với nhóm `reg.exe`/`schtasks.exe`, trước đó đã xác nhận khi PythonAgent chạy Administrator và bật Security Event ID 4688 thì các gap tương ứng pass.

## 10. Kết luận hiện tại

Chocolatey là tập benign độc lập hữu ích vì đại diện cho installer automation thực tế trên Windows.

Kết quả hiện tại:

- Thu thập được 68 package, 135 script.
- Không thực thi installer, chỉ phân tích tĩnh.
- Sau tuning, 0/135 benign bị `TERMINATE`.
- 28/135 script còn `ALERT`; phần lớn là installer hoặc admin/security tool có hành vi dual-use.
- Chưa nên tuning mạnh `ALERT -> ALLOW` nếu chưa review từng mẫu, vì Chocolatey installer có đặc thù khác PowerShell Gallery.

Hướng tiếp theo:

1. Review 28 mẫu `ALERT` còn lại.
2. Phân loại `acceptable alert`, `true FP candidate`, `needs runtime test`.
3. Chỉ hạ `ALERT -> ALLOW` cho pattern thật sự benign như checksum/helper/metadata hoặc registry read không nguy hiểm.
4. Chọn 10-15 package Chocolatey đại diện để chạy runtime trong VM checkpoint.
5. Sau mỗi vòng tuning, chạy lại Chocolatey baseline, PowerShell Gallery holdout và Atomic expanded.

Kết quả review và tuning chi tiết cho 28 mẫu `ALERT` được lưu tại:

```text
docs/chocolatey_alert_review_tuning_vi.md
```
