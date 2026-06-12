# Review 28 mẫu Chocolatey ALERT và tuning giảm FP

Thời điểm thực hiện: 11/06/2026

Mục tiêu của vòng này là review 28 mẫu Chocolatey còn bị `ALERT` sau baseline trước đó, phân biệt:

- `acceptable alert`: cảnh báo hợp lý vì script có hành vi installer/admin dual-use;
- `true FP candidate`: mẫu benign rõ ràng, có thể hạ `ALERT -> ALLOW`;
- `needs runtime test`: script cần chạy thật trong VM checkpoint để xác nhận tác động runtime trước khi tuning tiếp.

Nguyên tắc tuning: chỉ hạ `ALERT -> ALLOW` khi pattern đủ hẹp và benign rõ ràng, ví dụ script update metadata/checksum của Chocolatey AU hoặc script chỉ giải nén archive local có sẵn trong package. Không hạ các installer tải MSI/EXE, sửa registry, tạo service/task hoặc chỉnh PATH hệ thống nếu chưa có runtime evidence.

## 1. Nguồn dữ liệu và report

Dataset Chocolatey:

```text
datasets/chocolatey/behavior_groups_80_casefixed/
```

Report trước tuning FP:

```text
datasets/chocolatey/behavior_groups_80_casefixed/reports_after_choco_terminate_tune/
```

Report sau tuning FP vòng 2:

```text
datasets/chocolatey/behavior_groups_80_casefixed/reports_after_choco_fp_tune_2/
```

Danh sách 24 mẫu còn `ALERT` sau tuning:

```text
datasets/chocolatey/behavior_groups_80_casefixed/reports_after_choco_fp_tune_2/unique_alert_or_terminate_results.csv
```

## 2. Kết quả trước và sau tuning

| Giai đoạn | Tổng file | ALLOW | ALERT | TERMINATE |
|---|---:|---:|---:|---:|
| Baseline ban đầu | 135 | 107 | 27 | 1 |
| Sau tuning Chocolatey `TERMINATE -> ALERT` | 135 | 107 | 28 | 0 |
| Sau review 28 ALERT và tuning FP vòng 2 | 135 | 111 | 24 | 0 |

Diễn giải:

- `TERMINATE` đã được loại bỏ khỏi tập benign Chocolatey.
- 4 mẫu được hạ `ALERT -> ALLOW` vì thuộc pattern benign rõ ràng.
- 24 mẫu còn lại vẫn giữ `ALERT` vì có hành vi installer/admin đáng quan sát.

## 3. Phân loại 28 mẫu ALERT

| Sample | Package | Type | Phân loại | Quyết định | Lý do |
|---|---|---|---|---|---|
| `choco_behavior_000001` | GoogleChrome | install | Acceptable alert | Giữ `ALERT` | Installer tải Chrome từ vendor, có network/download behavior. |
| `choco_behavior_000006` | microsoft-edge | install | Acceptable alert | Giữ `ALERT` | Installer trình duyệt, có download/network và service/update context. |
| `choco_behavior_000011` | Vivaldi | helper/update | True FP candidate | Hạ `ALLOW` | Script `update.ps1` của Chocolatey AU chỉ lấy version từ appcast và cập nhật metadata/checksum, không cài đặt runtime. |
| `choco_behavior_000012` | tor-browser | install | Acceptable alert | Giữ `ALERT` | Installer trình duyệt đặc thù, có URL/network indicator; nên quan sát thay vì allow mặc định. |
| `choco_behavior_000018` | sumatrapdf | helper/update | True FP candidate | Hạ `ALLOW` | Script `update.ps1` dùng Chocolatey AU để lấy latest version, không thực thi installer. |
| `choco_behavior_000033` | postman | install | Acceptable alert | Giữ `ALERT` | Installer dev tool tải package từ Internet. |
| `choco_behavior_000042` | openjdk | beforemodify | Needs runtime test | Giữ `ALERT` | Sửa machine PATH, dùng `Invoke-Expression` hoặc elevation helper. Cần chạy trong checkpoint để xác nhận tác động. |
| `choco_behavior_000045` | golang | install | Acceptable alert | Giữ `ALERT` | Installer runtime language có download/network behavior. |
| `choco_behavior_000056` | jdk8 | helper | Acceptable alert | Giữ `ALERT` | Helper phục vụ Java installer, có downloader/package helper logic. |
| `choco_behavior_000059` | sysinternals | helper | Needs runtime test | Giữ `ALERT` | Ghi registry HKCU để accept EULA cho nhiều Sysinternals tool, gồm công cụ dual-use như PsExec/ProcDump. |
| `choco_behavior_000060` | procexp | install | Acceptable alert | Giữ `ALERT` | Sysinternals installer, có network/registry behavior. |
| `choco_behavior_000062` | procmon | install | Acceptable alert | Giữ `ALERT` | Sysinternals installer, có network/registry behavior. |
| `choco_behavior_000064` | AutoRuns | install | Acceptable alert | Giữ `ALERT` | Sysinternals autorun tool, bản chất nhạy cảm về persistence inspection. |
| `choco_behavior_000066` | TcpView | install | Acceptable alert | Giữ `ALERT` | Sysinternals/network tool installer, có registry/network indicator. |
| `choco_behavior_000067` | openssh | install | Needs runtime test | Giữ `ALERT` | Có service/registry/admin behavior khi cài OpenSSH. |
| `choco_behavior_000068` | openssh | uninstall | Needs runtime test | Giữ `ALERT` | Gỡ service/registry liên quan OpenSSH, cần runtime evidence. |
| `choco_behavior_000083` | openssl | uninstall | Needs runtime test | Giữ `ALERT` | Chỉnh environment variable/PATH trong registry; benign nhưng thay đổi system state. |
| `choco_behavior_000088` | osquery | install | Needs runtime test | Giữ `ALERT` | Cài security agent/tool, có service/ACL/file deployment behavior. |
| `choco_behavior_000089` | osquery | uninstall | Needs runtime test | Giữ `ALERT` | Gỡ service/tool security, có tác động runtime đáng quan sát. |
| `choco_behavior_000106` | PowerShell | install | Needs runtime test | Giữ `ALERT` | Có registry, scheduled task và `Invoke-Expression`; đã cap từ `TERMINATE` xuống `ALERT` vì là Chocolatey installer chuẩn. |
| `choco_behavior_000115` | curl | install | True FP candidate | Hạ `ALLOW` | Script chỉ giải nén ZIP local có sẵn bằng `Get-ChocolateyUnzip`, không có URL/web request/download runtime. |
| `choco_behavior_000116` | Wget | install | True FP candidate | Hạ `ALLOW` | Script chỉ chọn ZIP local x86/x64 và giải nén, không tải từ mạng. |
| `choco_behavior_000117` | adobereader | install | Acceptable alert | Giữ `ALERT` | Installer lớn, có download/registry/process behavior. |
| `choco_behavior_000119` | jre8 | install | Needs runtime test | Giữ `ALERT` | Java installer có download/registry/process behavior; nên kiểm tra runtime. |
| `choco_behavior_000120` | jre8 | uninstall | Needs runtime test | Giữ `ALERT` | Uninstall Java có registry/process behavior. |
| `choco_behavior_000125` | microsoft-teams.install | install | Needs runtime test | Giữ `ALERT` | MSI installer có tùy chọn all-user/autostart/persistence-like behavior. |
| `choco_behavior_000128` | ccleaner | install | Acceptable alert | Giữ `ALERT` | System utility installer, có registry/network behavior. |
| `choco_behavior_000133` | RSAT | install | Needs runtime test | Giữ `ALERT` | Công cụ quản trị Windows, có registry/download/admin behavior. |

## 4. Rule/policy đã tuning

Điều chỉnh trong `PythonAgent/PythonAgent.py`:

- Nhận diện script update metadata của Chocolatey AU:
  - file `update.ps1`;
  - có marker như `au_GetLatest`, `au_SearchReplace`, `Update-Package`, `ChecksumFor`;
  - không có signal runtime mạnh như service/task/registry persistence/direct execution.
- Nhận diện script Chocolatey cài package từ archive local:
  - file `chocolateyInstall.ps1`;
  - dùng `Get-ChocolateyUnzip` hoặc `FileFullPath`;
  - không có URL, `Invoke-WebRequest`, `Install-ChocolateyPackage`, `Get-ChocolateyWebFile`, `Start-Process`, `reg add`, service/task.

Các pattern này chỉ làm `final_verdict` hạ xuống `ALLOW`; `rule_verdict` gốc vẫn được ghi trong log để phục vụ audit.

## 5. Kết quả Chocolatey sau tuning vòng 2

| Nhóm | File đánh giá | ALLOW | ALERT | TERMINATE |
|---|---:|---:|---:|---:|
| browser_user_apps | 24 | 21 | 3 | 0 |
| dev_tools | 14 | 13 | 1 | 0 |
| runtime_language | 18 | 15 | 3 | 0 |
| sysadmin_utilities | 23 | 16 | 7 | 0 |
| security_tools_benign | 15 | 12 | 3 | 0 |
| package_dependency_tools | 22 | 21 | 1 | 0 |
| windows_maintenance_config | 19 | 13 | 6 | 0 |
| Tổng | 135 | 111 | 24 | 0 |

Nhận xét:

- Tỷ lệ `ALERT` trên tập Chocolatey giảm từ 28/135 xuống 24/135.
- Không còn `TERMINATE` trên tập benign Chocolatey.
- 24 alert còn lại có lý do hợp lý: installer tải từ Internet, registry/PATH/service/task, hoặc công cụ admin/security dual-use.

## 6. Regression với PowerShell Gallery holdout

Report:

```text
datasets/powershell_gallery/behavior_groups_80/reports_after_choco_fp_tune_2/
```

| Nhóm | File đánh giá | ALLOW | ALERT | TERMINATE |
|---|---:|---:|---:|---:|
| cloud_automation | 43 | 43 | 0 | 0 |
| dsc_config_management | 30 | 30 | 0 | 0 |
| package_module_management | 27 | 26 | 1 | 0 |
| admin_windows_maintenance | 31 | 30 | 1 | 0 |
| devops_build_test | 28 | 28 | 0 | 0 |
| security_audit_compliance_benign | 26 | 26 | 0 | 0 |
| utility_user_scripts | 27 | 27 | 0 | 0 |
| Tổng | 212 | 210 | 2 | 0 |

Nhận xét:

- Tuning Chocolatey không làm tăng FP trên PowerShell Gallery holdout.
- Kết quả giữ ở mức 2/212 `ALERT`, 0 `TERMINATE`.

## 7. Regression với Atomic expanded

Report:

```text
tests/atomic_red_team/atomic_accuracy_all_non_admin_after_choco_fp_tune_2_20260611_183213.json
tests/atomic_red_team/atomic_accuracy_all_non_admin_after_choco_fp_tune_2_20260611_183213.csv
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

Ba case fail trong nhóm executed:

| ID | Nhóm | Technique | Lý do |
|---|---|---|---|
| `ART-ACC-021` | registry_persistence | T1547.001 | `observed_event_count = 0`, không nhận telemetry trong phiên non-admin. |
| `ART-ACC-027` | scheduled_task | T1053.005 | `observed_event_count = 0`, không nhận telemetry trong phiên non-admin. |
| `ART-ACC-029` | scheduled_task | T1053.005 | `observed_event_count = 0`, expected `TERMINATE`, nhưng không có telemetry. |

Nhận xét regression:

- Các fail là telemetry gap trong phiên non-admin, không phải do hạ rule Chocolatey.
- Các rule mới chỉ nhận diện path/context Chocolatey AU và local archive extraction, nên không ảnh hưởng trực tiếp đến Atomic payload.
- Với nhóm registry/scheduled task, cần chạy lại ở chế độ Administrator + Security Event ID 4688 nếu muốn xác nhận telemetry đầy đủ.

## 8. Gói Chocolatey nên chạy runtime trong VM checkpoint

Không nên chạy toàn bộ package Chocolatey trên máy thật vì installer có thể thay đổi registry, service, PATH, scheduled task hoặc cài phần mềm nặng. Nên tạo checkpoint Hyper-V trước khi chạy.

Đề xuất 15 package đại diện:

| Package | Lý do chọn | Kỳ vọng |
|---|---|---|
| GoogleChrome | Installer tải từ vendor | `ALERT`, không `TERMINATE`. |
| Vivaldi | AU metadata/update script đã hạ `ALLOW` | Static `ALLOW`; runtime installer nếu có download vẫn có thể `ALERT`. |
| curl | Local archive extraction | `ALLOW` nếu chỉ giải nén local. |
| openjdk | Sửa machine PATH qua beforemodify | `ALERT`, cần xác nhận không over-response. |
| sysinternals | Registry EULA, dual-use tools | `ALERT` hoặc acceptable alert. |
| openssh | Service/registry/admin behavior | `ALERT`, không tự động `TERMINATE` nếu không có malicious chain. |
| openssl | PATH/env cleanup | Có thể là candidate tuning sau runtime nếu chỉ sửa PATH an toàn. |
| osquery | Security tool/service/ACL | `ALERT`, acceptable. |
| PowerShell | WMF installer, scheduled task, registry, IEX | `ALERT`, không `TERMINATE` trong Chocolatey context chuẩn. |
| adobereader | Vendor installer lớn | `ALERT`. |
| jre8 | Java install/uninstall | `ALERT`, cần xem event thực tế. |
| microsoft-teams.install | MSI all-user/autostart option | `ALERT`, cần xem persistence-like event. |
| RSAT | Windows admin feature/tool | `ALERT`, cần xem process/registry event. |
| ccleaner | System utility installer | `ALERT`, acceptable. |
| postman | Dev tool installer | `ALERT`, đại diện installer dev bình thường. |

Quy trình runtime đề xuất:

1. Tạo checkpoint VM: `CP_Chocolatey_Runtime_Before`.
2. Bật PythonAgent, C++ Agent nếu cần, và Security Event ID 4688.
3. Chạy từng package một, không chạy song song.
4. Sau mỗi package, lưu:
   - `edr_events.jsonl`;
   - verdict cao nhất;
   - source telemetry;
   - process/file/eventlog evidence;
   - thay đổi hệ thống nếu có.
5. Revert checkpoint sau mỗi nhóm package hoặc sau mỗi package nhạy cảm như `openssh`, `osquery`, `PowerShell`, `RSAT`.
6. Chỉ tuning tiếp khi có bằng chứng runtime cho thấy `ALERT` là true FP.

## 9. Kết luận vòng tuning này

Vòng này đã đạt mục tiêu giảm FP có kiểm soát:

- Hạ đúng 4 mẫu benign rõ ràng từ `ALERT` về `ALLOW`.
- Không còn `TERMINATE` trên Chocolatey benign dataset.
- PowerShell Gallery holdout không xấu đi.
- Atomic expanded không cho thấy rule bị hạ sai; các fail còn lại thuộc telemetry gap ở non-admin.

Không nên tiếp tục hạ 24 `ALERT` còn lại bằng phân tích tĩnh đơn thuần. Bước tiếp theo nên là runtime test trong VM checkpoint với 15 package đại diện ở trên.
