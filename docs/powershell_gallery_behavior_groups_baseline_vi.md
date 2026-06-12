# Baseline PowerShell Gallery theo 7 nhóm hành vi benign

Thời điểm thực hiện: 11/06/2026

Mục tiêu của batch này là thu thập một bộ PowerShell Gallery nhỏ, có phân tầng theo hành vi benign, để chạy baseline và xác định nhóm benign nào làm PythonAgent báo động sai.

## 1. Cấu hình thu thập

Script sử dụng:

```text
tests/powershell_gallery/collect_powershell_gallery_behavior_groups.ps1
```

Cấu hình:

| Tham số | Giá trị |
|---|---:|
| Số nhóm hành vi | 7 |
| Tổng package mục tiêu | 80 |
| Số package thu được | 79 |
| Số file PowerShell thu được | 212 |
| Tối đa file/package | 3 |
| Kích thước file tối đa | 200 KB |
| Kích thước package tối đa | 50 MB |

Các nhóm hành vi:

1. `cloud_automation`
2. `dsc_config_management`
3. `package_module_management`
4. `admin_windows_maintenance`
5. `devops_build_test`
6. `security_audit_compliance_benign`
7. `utility_user_scripts`

Manifest dữ liệu:

```text
datasets/powershell_gallery/behavior_groups_80/metadata/packages_manifest.csv
datasets/powershell_gallery/behavior_groups_80/metadata/files_manifest.csv
datasets/powershell_gallery/behavior_groups_80/metadata/skipped_manifest.csv
```

## 2. Kết quả thu thập theo nhóm

| Nhóm | Package | File |
|---|---:|---:|
| Cloud automation | 15 | 43 |
| DSC/config management | 10 | 30 |
| Package/module management | 10 | 27 |
| Admin/Windows maintenance | 12 | 31 |
| DevOps/build/test | 10 | 28 |
| Security/audit/compliance benign | 9 | 26 |
| Utility/user scripts | 13 | 27 |
| Tổng | 79 | 212 |

Các item bị skip:

- `SqlChangeAutomation`: package lớn hơn giới hạn 50 MB.
- `Microsoft365DSC`: lỗi đường dẫn quá dài khi giải nén.
- `HardeningKitty`: không tìm thấy package tương ứng qua API PowerShell Gallery trong lần chạy này.

## 3. Kết quả baseline theo nhóm

Script sử dụng:

```text
tests/powershell_gallery/run_behavior_group_baseline.ps1
```

Kết quả tổng hợp:

| Nhóm | File đánh giá | ALLOW | ALERT | TERMINATE | Alert/Terminate |
|---|---:|---:|---:|---:|---:|
| Cloud automation | 43 | 0 | 43 | 0 | 43 |
| DSC/config management | 30 | 26 | 4 | 0 | 4 |
| Package/module management | 27 | 10 | 16 | 1 | 17 |
| Admin/Windows maintenance | 31 | 19 | 12 | 0 | 12 |
| DevOps/build/test | 28 | 15 | 13 | 0 | 13 |
| Security/audit/compliance benign | 26 | 6 | 19 | 1 | 20 |
| Utility/user scripts | 27 | 18 | 9 | 0 | 9 |
| Tổng | 212 | 94 | 116 | 2 | 118 |

Report chi tiết:

```text
datasets/powershell_gallery/behavior_groups_80/reports/
```

## 4. Hai mẫu benign bị TERMINATE

| Sample | Nhóm | Package | File | Nhận xét |
|---|---|---|---|---|
| `psg_behavior_000095` | Package/module management | `PowerShellForGitHub` | `build\scripts\Wait-RunningBuild.ps1` | Script DevOps hợp lệ, dùng Azure DevOps API và token để chờ pipeline build. Bị `TERMINATE` do kết hợp downloader/network/obfuscation-like operator. Đây là ứng viên FP nghiêm trọng cần xem xét. |
| `psg_behavior_000176` | Security/audit/compliance benign | `DSInternals` | `DSInternals.psd1` | Manifest module bảo mật/AD auditing có nhiều cmdlet và mô tả nhạy về password/hash/AD. Đây là benign-by-provenance nhưng nằm sát vùng dual-use, cần cân nhắc label riêng thay vì coi như benign thông thường. |

## 5. Nhóm gây ALERT nhiều nhất

Các nhóm có tỷ lệ cảnh báo cao:

1. `cloud_automation`: 43/43 file bị `ALERT`.
2. `security_audit_compliance_benign`: 20/26 file ở mức `ALERT/TERMINATE`.
3. `package_module_management`: 17/27 file ở mức `ALERT/TERMINATE`.

Các nhóm tương đối lành hơn:

1. `dsc_config_management`: 26/30 file `ALLOW`.
2. `utility_user_scripts`: 18/27 file `ALLOW`.
3. `admin_windows_maintenance`: 19/31 file `ALLOW`.

## 6. Nguyên nhân FP phổ biến

Các reason xuất hiện nhiều nhất trên các nhóm:

- `Network indicator present`
- `Base64 payload or FromBase64String`
- `High entropy content`
- `Obfuscation operators`
- `Registry access or modification`

Nhận xét:

- `cloud_automation` bị alert mạnh vì các module cloud thường chứa nhiều URL, API path, token/auth helper, generated code và metadata.
- `security_audit_compliance_benign` có rủi ro dual-use cao: nhiều module hợp lệ phục vụ audit nhưng chứa từ khóa giống kỹ thuật attacker.
- `package_module_management` dễ bị alert do các script build/install/download hợp lệ.

## 7. Kết quả sau tuning hai mẫu TERMINATE

Sau khi phân tích hai mẫu benign bị `TERMINATE`, PythonAgent được điều chỉnh theo hướng bảo thủ hơn đối với hành động response:

- Không coi dot-sourcing đơn lẻ trong script DevOps là bằng chứng đủ mạnh cho chuỗi download-execute.
- Không tự động `TERMINATE` module manifest chỉ vì metadata hoặc tên cmdlet có từ khóa liên quan credential dumping.
- Vẫn giữ `TERMINATE` cho các tín hiệu có độ tin cậy cao như Mimikatz, `sekurlsa`, `logonpasswords`, AMSI bypass, tắt logging PowerShell, chỉnh Defender, clear event log hoặc chuỗi download-execute rõ ràng.

Kết quả chạy lại:

| Nhóm | File đánh giá | ALLOW | ALERT | TERMINATE | Alert/Terminate |
|---|---:|---:|---:|---:|---:|
| Cloud automation | 43 | 0 | 43 | 0 | 43 |
| DSC/config management | 30 | 26 | 4 | 0 | 4 |
| Package/module management | 27 | 10 | 17 | 0 | 17 |
| Admin/Windows maintenance | 31 | 19 | 12 | 0 | 12 |
| DevOps/build/test | 28 | 15 | 13 | 0 | 13 |
| Security/audit/compliance benign | 26 | 6 | 20 | 0 | 20 |
| Utility/user scripts | 27 | 18 | 9 | 0 | 9 |
| Tổng | 212 | 94 | 118 | 0 | 118 |

Report sau tuning:

```text
datasets/powershell_gallery/behavior_groups_80/reports_after_terminate_tune/
```

Nhận xét:

- Hai mẫu `TERMINATE` trước đó đã được hạ xuống `ALERT`, phù hợp hơn với bản chất benign/dual-use của dữ liệu.
- Không phát sinh `TERMINATE` mới trên 212 file benign.
- Số lượng `ALERT` tăng từ 116 lên 118 do hai mẫu trước đây vẫn được giữ ở mức cảnh báo, không bị hạ quá sâu xuống `ALLOW`.
- Đây là kết quả hợp lý cho tuning giai đoạn đầu: giảm over-response nghiêm trọng trước, chưa tối ưu mạnh false positive ở mức `ALERT`.

## 8. Phân cụm ALERT cần tuning tiếp

Ba nhóm được ưu tiên phân tích tiếp là `cloud_automation`, `security_audit_compliance_benign` và `package_module_management`.

### 8.1. Cloud automation

Kết quả: 43/43 file bị `ALERT`.

Reason phổ biến:

| Reason | Số lần |
|---|---:|
| Base64 payload or FromBase64String | 43 |
| Network indicator present | 40 |
| High entropy content | 37 |
| Obfuscation operators | 3 |
| Browser data reconnaissance | 2 |
| Dynamic execution via IEX/Invoke-Expression | 2 |

Các package xuất hiện nhiều: `Az.*`, `AWS.Tools.*`, `Microsoft.Graph.*`.

Nhận xét kỹ thuật:

- Nhóm cloud thường chứa URL, endpoint API, tên miền dịch vụ, token/auth helper và generated code.
- Việc có network indicator trong nhóm này là hành vi bình thường, không đồng nghĩa với downloader độc hại.
- Hướng tuning phù hợp là phân biệt "network/API client hợp lệ" với "download rồi thực thi". Không nên whitelist toàn bộ package vì sẽ làm mất khả năng phát hiện khi module cloud bị abuse.

### 8.2. Security/audit/compliance benign

Kết quả: 20/26 file bị `ALERT`, 0 `TERMINATE`.

Reason phổ biến:

| Reason | Số lần |
|---|---:|
| Base64 payload or FromBase64String | 20 |
| Network indicator present | 20 |
| High entropy content | 18 |
| Browser data reconnaissance | 2 |
| Credential dumping keyword | 1 |
| Obfuscation operators | 1 |

Các package xuất hiện nhiều: `Az.Security`, `Az.SecurityInsights`, `Microsoft.Graph.Security`, `DSInternals`, `ORCA`, `SecurityPolicy`.

Nhận xét kỹ thuật:

- Đây là nhóm dual-use: công cụ audit/compliance hợp lệ có thể chứa từ khóa giống kỹ thuật tấn công.
- Kết quả sau tuning đã đúng hơn ở mức response: không còn tự động `TERMINATE` chỉ vì manifest hoặc metadata nhạy.
- Không nên hạ toàn bộ nhóm này xuống `ALLOW`; mức `ALERT` vẫn hợp lý khi có hành vi truy cập bảo mật, kiểm tra cấu hình hoặc keyword nhạy. Tuning tiếp theo nên tập trung giảm alert cho manifest/generated metadata, còn script audit thật vẫn nên giữ cảnh báo.

### 8.3. Package/module management

Kết quả: 17/27 file bị `ALERT`, 0 `TERMINATE`.

Reason phổ biến:

| Reason | Số lần |
|---|---:|
| Network indicator present | 16 |
| Base64 payload or FromBase64String | 15 |
| High entropy content | 12 |
| Downloader behavior | 2 |
| Obfuscation operators | 2 |

Các package xuất hiện nhiều: `Az.Tools.Installer`, `Microsoft.PowerShell.PSResourceGet`, `PackageManagement`, `PowerShellGet`, `ModuleBuilder`.

Nhận xét kỹ thuật:

- Nhóm này có nhiều hành vi tải module, kiểm tra repository, build/test package và gọi API.
- `Downloader behavior` trong nhóm package management không luôn là độc hại; cần xem có đi kèm execution, encoded payload, persistence hoặc defense evasion hay không.
- Sau tuning, mẫu `PowerShellForGitHub\build\scripts\Wait-RunningBuild.ps1` không còn bị `TERMINATE`, nhưng vẫn `ALERT` vì có API/network/token context. Đây là mức hợp lý hơn cho giai đoạn hiện tại.

## 9. Baseline theo nhiều lát cắt

Để tránh tuning theo cảm tính, baseline sau tuning được chạy thêm theo nhiều lát cắt:

- Theo nhóm hành vi.
- Theo loại file: `.ps1`, `.psm1`, `.psd1`.
- Theo cặp nhóm hành vi + loại file.

Script đã được mở rộng để tạo summary theo slice:

```text
tests/powershell_gallery/run_behavior_group_baseline.ps1
```

Kết quả report:

```text
datasets/powershell_gallery/behavior_groups_80/reports_sliced_after_terminate_tune/
```

### 9.1. Theo loại file

| Loại file | File đánh giá | ALLOW | ALERT | TERMINATE |
|---|---:|---:|---:|---:|
| `.ps1` | 116 | 53 | 63 | 0 |
| `.psm1` | 61 | 29 | 32 | 0 |
| `.psd1` | 35 | 12 | 23 | 0 |

Nhận xét:

- `.ps1` có số lượng alert lớn nhất vì đây là script thực thi trực tiếp.
- `.psm1` có tỷ lệ alert cao ở các module cloud/package do generated code, alias module và API wrapper.
- `.psd1` là manifest/metadata nhưng vẫn có 23/35 alert khi đánh giá trực tiếp bằng detector. Trong runtime thực tế, file sensor hiện có logic loại bỏ module manifest thông thường, nên nhóm này cần được phân tích riêng để không làm sai lệch kết luận FP vận hành.

### 9.2. Ba cụm ưu tiên theo loại file

| Nhóm | `.ps1` ALERT/Tổng | `.psm1` ALERT/Tổng | `.psd1` ALERT/Tổng |
|---|---:|---:|---:|
| Cloud automation | 28/28 | 12/12 | 3/3 |
| Security/audit/compliance benign | 13/19 | 4/4 | 3/3 |
| Package/module management | 6/16 | 8/8 | 3/3 |

Nhận xét:

- `cloud_automation` là cụm FP lớn nhất: alert xuất hiện trên cả script, module và manifest.
- `security_audit_compliance_benign` có bản chất dual-use, nên không nên hạ toàn bộ xuống `ALLOW`; cần phân biệt metadata/generated code với hành vi audit thật.
- `package_module_management` có nhiều alert trên `.psm1` và `.psd1`; hướng xử lý là tách download/install hợp lệ khỏi download-execute hoặc persistence.

## 10. Quy trình tuning lặp lại

Mỗi vòng tuning nên thực hiện theo quy trình cố định:

1. Chạy baseline PowerShell Gallery theo slice:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\powershell_gallery\run_behavior_group_baseline.ps1 `
  -FilesManifest .\datasets\powershell_gallery\behavior_groups_80\metadata\files_manifest.csv `
  -OutputRoot .\datasets\powershell_gallery\behavior_groups_80\reports_sliced_<ten_vong_tuning> `
  -AgentPath .\PythonAgent\PythonAgent.py
```

2. Ghi lại các chỉ số chính:

- Tổng `ALLOW`, `ALERT`, `TERMINATE`.
- Tỷ lệ `ALERT` theo category.
- Tỷ lệ `ALERT` theo `.ps1`, `.psm1`, `.psd1`.
- Các reason xuất hiện nhiều nhất.
- Top package/file bị alert.

3. Chọn tuning candidate theo nguyên tắc:

- Ưu tiên giảm `TERMINATE` sai trước `ALERT` sai.
- Không whitelist package cụ thể nếu có thể tránh.
- Chỉ hạ verdict khi thiếu chuỗi hành vi nguy hiểm như defense evasion, persistence, credential theft, download-execute hoặc memory injection.
- Với `.psd1`, xem đây là metadata/manifest; không đánh đồng với script thực thi.
- Với `.psm1`, kiểm tra liệu đó là generated wrapper/alias module hay module có logic thực thi nguy hiểm.

4. Tuning rule/policy trong PythonAgent.

5. Chạy lại baseline PowerShell Gallery theo cùng slice để so sánh trước/sau.

6. Chạy lại Atomic expanded để kiểm tra regression trên tập malicious/attack behavior:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\atomic_red_team\run_atomic_accuracy_with_agent.ps1 `
  -Set all `
  -IncludeAdmin `
  -TimeoutSeconds 30 `
  -SettleSeconds 5
```

Lưu ý: bước Atomic expanded có thể cần quyền Administrator và chỉ nên chạy trong máy lab/checkpoint. Nếu tuning làm giảm FP nhưng làm fail các Atomic case có kỳ vọng `ALERT`/`TERMINATE`, cần rollback hoặc siết lại điều kiện.

## 11. Metadata cần giữ lại cho phục vụ tuning sau này

Kết quả đánh giá hiện đã giữ lại metadata PowerShell Gallery trong output:

- `source_dataset`
- `label`
- `category`
- `package_name`
- `package_version`
- `author`
- `license_url`
- `project_url`
- `download_count`
- `original_relative_path`
- `file_extension`
- `file_size_bytes`
- `raw_sha256`
- `normalized_sha256`

Metadata này dùng để:

- truy ngược nguồn mẫu gây FP;
- phân nhóm package theo hành vi;
- phát hiện package/fork trùng hoặc gần trùng;
- phục vụ chọn mẫu benign độc lập cho các vòng tuning sau;
- không dùng như whitelist cứng trong runtime EDR nếu chưa có cơ chế trust/provenance rõ ràng.

## 12. Vòng tuning FP lần 1

Sau khi chạy baseline theo nhiều lát cắt, nguyên nhân FP lớn nhất không đến từ hành vi thực thi độc hại mà đến từ:

- Authenticode signature block trong các script/module đã ký số, chứa nhiều chuỗi base64 certificate.
- Chuỗi dài trong URL/API path/generated metadata bị regex base64 nhận nhầm.
- Các tín hiệu cấu trúc như `Import-Module`, dot-sourcing nội bộ module và `-Recurse` bị cộng vào `behavior_score` dù không đi kèm chuỗi hành vi nguy hiểm.

Các thay đổi đã thực hiện trong PythonAgent:

- Loại bỏ Authenticode signature block trước khi trích xuất feature.
- Siết lại `has_base64_payload`: không coi mọi chuỗi dài thuộc alphabet base64 là payload; loại trừ token dạng path/URL dễ đọc và yêu cầu entropy đủ cao.
- Không cộng các tín hiệu yếu `has_import_module`, `has_recurse_param`, `has_dot_sourcing_exec` vào `behavior_score` khi chúng đứng riêng lẻ. Các feature này vẫn được giữ lại và dot-sourcing vẫn được dùng trong chuỗi nguy hiểm nếu đi kèm download/encoded/evasion.

Report sau tuning:

```text
datasets/powershell_gallery/behavior_groups_80/reports_sliced_after_fp_tune_2/
```

### 12.1. So sánh theo nhóm hành vi

| Nhóm | ALERT trước tuning FP | ALERT sau tuning FP | TERMINATE sau tuning FP |
|---|---:|---:|---:|
| Cloud automation | 43 | 2 | 0 |
| DSC/config management | 4 | 0 | 0 |
| Package/module management | 17 | 3 | 0 |
| Admin/Windows maintenance | 12 | 5 | 0 |
| DevOps/build/test | 13 | 1 | 0 |
| Security/audit/compliance benign | 20 | 0 | 0 |
| Utility/user scripts | 9 | 2 | 0 |
| Tổng | 118 | 13 | 0 |

### 12.2. So sánh theo loại file

| Loại file | ALERT trước tuning FP | ALERT sau tuning FP | TERMINATE sau tuning FP |
|---|---:|---:|---:|
| `.ps1` | 63 | 8 | 0 |
| `.psm1` | 32 | 4 | 0 |
| `.psd1` | 23 | 1 | 0 |

Nhận xét:

- `ALERT` giảm từ 118/212 xuống 13/212.
- Không phát sinh `TERMINATE` trên tập benign.
- Giảm mạnh nhất ở `cloud_automation` và `security_audit_compliance_benign`, đúng với mục tiêu tuning.
- Các `ALERT` còn lại chủ yếu nằm ở script có downloader/API thực, dynamic execution, encoded/bypass hoặc hành vi admin nhạy. Các mẫu này không nên hạ tiếp nếu chưa có tập malicious đối chứng rộng hơn.

### 12.3. Atomic expanded regression

Sau tuning, đã chạy lại Atomic expanded ở chế độ non-admin:

```text
tests/atomic_red_team/atomic_accuracy_all_non_admin_report_20260611_144043.json
tests/atomic_red_team/atomic_accuracy_all_non_admin_report_20260611_144043.csv
```

Kết quả:

| Chỉ số | Giá trị |
|---|---:|
| Selected | 26 |
| Executed | 23 |
| Skipped prereq | 3 |
| Errors | 0 |
| Accuracy passed | 20 |
| Accuracy failed | 3 |
| Accuracy rate | 86.96% |

Ba case fail:

| ID | Nhóm | Nguyên nhân |
|---|---|---|
| `ART-ACC-021` | Registry persistence | Không thu được telemetry (`observed_event_count = 0`). |
| `ART-ACC-027` | Scheduled task | Không thu được telemetry (`observed_event_count = 0`). |
| `ART-ACC-029` | Scheduled task + encoded registry payload | Không thu được telemetry (`observed_event_count = 0`). |

Nhận xét regression:

- Các case fail không phải do rule hạ verdict sai, mà do không có event đầu vào.
- Phiên chạy hiện tại không chạy với quyền Administrator, vì vậy `eventlog_4688_sensor` không đọc được Security Log 4688 để bắt các tiến trình ngắn hạn như `reg.exe` và `schtasks.exe`.
- Đã chạy lại nhóm gap trong PowerShell Administrator sau khi bật Audit Process Creation/4688. Report: `tests/atomic_red_team/atomic_gap_4688_report_20260611_150401.json`.

Kết quả xác nhận lại với quyền Administrator và 4688:

| ID | Nguồn telemetry | Số event | Verdict cao nhất | Kết quả |
|---|---|---:|---|---|
| `ART-ACC-021` | `eventlog_4688_sensor` | 1 | `ALERT` | Pass |
| `ART-ACC-027` | `eventlog_4688_sensor` | 1 | `ALERT` | Pass |
| `ART-ACC-029` | `eventlog_4688_sensor` | 3 | `TERMINATE` | Pass |

Kết luận: ba case gap trước đó là vấn đề điều kiện thu thập telemetry khi chạy non-admin, không phải regression của logic detection/response. Với PythonAgent chạy quyền Administrator và Security Event ID 4688 được bật, hệ thống bắt được `reg.exe`, `schtasks.exe` và chuỗi scheduled task + encoded registry payload đúng kỳ vọng.

## 13. Review 13 mẫu ALERT còn lại và tuning verdict

Sau vòng tuning FP lần 1, còn 13/212 mẫu PowerShell Gallery ở mức `ALERT`. Các mẫu này được review thủ công theo ba tiêu chí:

1. Có chuỗi hành vi nguy hiểm rõ ràng hay không: encoded/evasion, persistence, credential theft, download-execute, memory injection.
2. Alert đến từ metadata/generated code/API client benign hay đến từ logic thực thi nhạy.
3. Nếu hạ verdict thì điều kiện hạ có tổng quát hay chỉ là whitelist theo package.

Kết quả phân loại:

| Sample | Package | File | Phân loại | Quyết định |
|---|---|---|---|---|
| `psg_behavior_000118` | `Carbon` | `Remove-EnvironmentVariable.ps1` | True FP | Hạ `ALLOW`: dùng `FromBase64String` để decode tên biến môi trường, không có execution/evasion. |
| `psg_behavior_000119` | `Carbon` | `Set-EnvironmentVariable.ps1` | True FP | Hạ `ALLOW`: base64 chỉ là dữ liệu cấu hình, không phải payload. |
| `psg_behavior_000125` | `HPWarranty` | `Invoke-HPEntSOAPRequest.ps1` | True FP | Hạ `ALLOW`: SOAP/API client hợp lệ, không có download-execute. |
| `psg_behavior_000123` | `HPWarranty` | `Invoke-HPIncSOAPRequest.ps1` | True FP | Hạ `ALLOW`: SOAP/API client hợp lệ. |
| `psg_behavior_000114` | `RunAsUser` | `Invoke-AsCurrentUser.ps1` | Acceptable alert | Giữ `ALERT`: có `EncodedCommand`, `ExecutionPolicy Bypass`, registry access và khởi chạy PowerShell trong user context khác. |
| `psg_behavior_000042` | `AWS.Tools.EC2` | `AWS.Tools.EC2.Completers.psm1` | True FP | Hạ `ALLOW`: generated argument completer, `Invoke-Expression` dùng để resolve .NET type/cmdlet metadata. |
| `psg_behavior_000039` | `AWS.Tools.S3` | `AWS.Tools.S3.Completers.psm1` | True FP | Hạ `ALLOW`: generated completer tương tự AWS EC2. |
| `psg_behavior_000146` | `VSTeam` | `VSTeam.psm1` | True FP | Hạ `ALLOW`: decode PAT/token từ environment variable, không có execution chain. |
| `psg_behavior_000093` | `BuildHelpers` | `Add-TestResultToAppveyor.ps1` | True FP | Hạ `ALLOW`: upload test result qua AppVeyor API, không tải và thực thi payload. |
| `psg_behavior_000090` | `ModuleBuilder` | `ModuleBuilder.psm1` | Acceptable alert | Giữ `ALERT`: module benign nhưng có base64/deflate/module generation và obfuscation-like operators; đây là hành vi dual-use nên không hạ xuống `ALLOW`. |
| `psg_behavior_000095` | `PowerShellForGitHub` | `Wait-RunningBuild.ps1` | True FP | Hạ `ALLOW`: polling Azure DevOps API bằng PAT, không có defense evasion/persistence/download-execute. |
| `psg_behavior_000196` | `PowerHTML` | `PowerHTML.psd1` | True FP | Hạ `ALLOW`: manifest `.psd1`, alert do metadata/tags như `Invoke-WebRequest`. |
| `psg_behavior_000187` | `powershell-yaml` | `powershell-yaml.Tests.ps1` | True FP | Hạ `ALLOW`: Pester test tải dependency test vào `$TestDrive`, không có execution/evasion/persistence. |

Điều chỉnh policy trong PythonAgent:

- Chỉ hạ `ALERT` xuống `ALLOW` khi `rule_verdict = ALERT`, ML không xác nhận malicious, risk không ở mức `HIGH`, và không có high-confidence terminate signal.
- Bổ sung các ngữ cảnh benign có điều kiện: static `.psd1` manifest, generated argument completer, base64-data decode, network/API client benign.
- Không hạ verdict nếu có tín hiệu runtime mạnh như `EncodedCommand`, `ExecutionPolicy Bypass`, hidden window, persistence, Defender/logging tampering, suspicious process, TCP listener/client hoặc ASCII/char reconstruction.
- Siết lại static metadata context: chỉ áp dụng cho `.psd1` manifest. `.psm1` có dynamic module generation như `ModuleBuilder` vẫn giữ `ALERT`.

Report sau review/tuning:

```text
datasets/powershell_gallery/behavior_groups_80/reports_sliced_after_fp_review_tune/
```

Kết quả tổng hợp:

| Nhóm | File đánh giá | ALLOW | ALERT | TERMINATE |
|---|---:|---:|---:|---:|
| Cloud automation | 43 | 43 | 0 | 0 |
| DSC/config management | 30 | 30 | 0 | 0 |
| Package/module management | 27 | 26 | 1 | 0 |
| Admin/Windows maintenance | 31 | 30 | 1 | 0 |
| DevOps/build/test | 28 | 28 | 0 | 0 |
| Security/audit/compliance benign | 26 | 26 | 0 | 0 |
| Utility/user scripts | 27 | 27 | 0 | 0 |
| Tổng | 212 | 210 | 2 | 0 |

Hai mẫu còn `ALERT`:

| Sample | Package | Lý do giữ ALERT |
|---|---|---|
| `psg_behavior_000090` | `ModuleBuilder` | Có base64/deflate/module generation và nhiều operator dạng obfuscation-like. Dù benign theo provenance, hành vi này đủ dual-use để giữ cảnh báo. |
| `psg_behavior_000114` | `RunAsUser` | Có `EncodedCommand`, `ExecutionPolicy Bypass`, registry access và khởi chạy PowerShell dưới context user khác. Đây là hành vi admin hợp lệ nhưng nhạy về mặt EDR. |

Kết quả sau vòng này:

- `TERMINATE` trên benign: 0/212.
- `ALERT` trên benign: giảm từ 13/212 xuống 2/212.
- 2 mẫu còn lại được xem là acceptable alert, không phải true FP cần hạ tiếp trong giai đoạn hiện tại.
- Cách tuning không dùng whitelist package, mà dựa trên ngữ cảnh hành vi và loại file.

Regression Atomic sau tuning:

```text
tests/atomic_red_team/atomic_accuracy_all_non_admin_after_fp_review_tune_20260611_164315.json
```

Kết quả non-admin:

| Chỉ số | Giá trị |
|---|---:|
| Selected | 26 |
| Executed | 21 |
| Skipped prereq | 4 |
| Errors | 1 |
| Accuracy passed | 18 |
| Accuracy failed | 3 |
| Accuracy rate | 85.71% |

Ba case fail vẫn là `ART-ACC-021`, `ART-ACC-027`, `ART-ACC-029`, đều do không có telemetry 4688 trong phiên non-admin. Đây là cùng nhóm đã được xác nhận pass 3/3 khi chạy PythonAgent Administrator và bật Security Event ID 4688 tại report:

```text
tests/atomic_red_team/atomic_gap_4688_report_20260611_150401.json
```

Nhận xét: vòng tuning này làm giảm FP trên benign PowerShell Gallery nhưng không hạ các tín hiệu runtime mạnh. Kết quả Atomic non-admin không cho thấy regression do tuning rule/combine verdict; các fail còn lại thuộc điều kiện triển khai sensor 4688.

## 14. Kết luận sau vòng tuning hiện tại

Batch phân nhóm đã đạt mục tiêu: tổng file vừa phải, chạy nhanh, không timeout, và đủ để chỉ ra các cụm FP chính.

Kết luận kỹ thuật:

- Hệ thống đã giảm over-response nghiêm trọng: 0/212 benign bị `TERMINATE`.
- FP ở mức `ALERT` giảm mạnh: 118/212 xuống 2/212 sau khi review 13 mẫu còn lại.
- Việc tuning dựa trên nguyên nhân kỹ thuật tổng quát, không dựa trên whitelist package cụ thể.
- Atomic regression sau khi xác nhận bằng quyền Administrator/4688 không còn chỉ ra rule regression ở ba case gap `reg.exe`/`schtasks.exe`; các gap này phụ thuộc vào điều kiện triển khai sensor 4688.

Không nên tuning bằng whitelist package. Nên tuning theo ngữ cảnh:

- benign module/manifest/generated code có nhiều URL/API path nhưng không có chain thực thi nguy hiểm;
- security/audit module dual-use nên có mức cảnh báo phù hợp, nhưng không tự động `TERMINATE` nếu chỉ là manifest/metadata;
- DevOps script dùng API/token hợp lệ không nên bị `TERMINATE` nếu không có defense evasion, persistence, credential dump hoặc download-execute chain rõ ràng.
