# Vòng tuning FP nhỏ sau khi chuyển ML thành tín hiệu phụ

## 1. Mục tiêu

Vòng tuning này tập trung vào 13 mẫu `true_fp_candidate` còn lại trong bộ PowerShell Gallery sau khi chính sách ML đã được đổi thành tín hiệu phụ. Mục tiêu là giảm cảnh báo sai trên script benign rõ ngữ cảnh, nhưng vẫn giữ `ALERT` cho các script có hành vi dual-use hoặc dynamic code generation.

## 2. Thay đổi chính

- Bổ sung benign-context cho các nhóm:
  - generated argument completer;
  - SOAP/API admin helper;
  - CI/build API helper;
  - test fixture của module;
  - module manifest `.psd1`;
  - base64/data helper không có execution chain.
- Sửa thứ tự policy: khi ML confidence cao làm verdict tạm lên `TERMINATE`, policy sẽ cap xuống `ALERT` rồi tiếp tục xét benign-context, thay vì return sớm.
- ML vẫn không được tự nâng verdict nếu thiếu evidence từ rule/risk. Các case có high-confidence terminate signal vẫn giữ `TERMINATE`.

## 3. Kết quả PowerShell Gallery sau tuning

| Nhóm | Số file | ALLOW | ALERT | TERMINATE |
|---|---:|---:|---:|---:|
| cloud_automation | 43 | 43 | 0 | 0 |
| dsc_config_management | 30 | 30 | 0 | 0 |
| package_module_management | 27 | 26 | 1 | 0 |
| admin_windows_maintenance | 31 | 30 | 1 | 0 |
| devops_build_test | 28 | 28 | 0 | 0 |
| security_audit_compliance_benign | 26 | 26 | 0 | 0 |
| utility_user_scripts | 27 | 27 | 0 | 0 |

Tổng hợp: 212 file, 210 `ALLOW`, 2 `ALERT`, 0 `TERMINATE`.

Hai cảnh báo còn giữ lại:

| Package | File | Lý do giữ ALERT |
|---|---|---|
| RunAsUser | `Public\Invoke-AsCurrentUser.ps1` | Có `EncodedCommand`, `ExecutionPolicy bypass`, registry access và liên quan ngữ cảnh chạy dưới user khác. Đây là admin/security dual-use, nên giữ cảnh báo là hợp lý. |
| ModuleBuilder | `ModuleBuilder.psm1` | Có base64, obfuscation operator và scriptblock/dynamic code generation. Dù là module build hợp pháp, hành vi đủ nhạy cảm để giữ `ALERT` phục vụ review. |

## 4. Holdout: Chocolatey

| Nhóm | Số file | ALLOW | ALERT | TERMINATE |
|---|---:|---:|---:|---:|
| browser_user_apps | 24 | 20 | 4 | 0 |
| dev_tools | 14 | 13 | 1 | 0 |
| runtime_language | 18 | 15 | 3 | 0 |
| sysadmin_utilities | 23 | 16 | 7 | 0 |
| security_tools_benign | 15 | 12 | 3 | 0 |
| package_dependency_tools | 22 | 21 | 1 | 0 |
| windows_maintenance_config | 19 | 13 | 6 | 0 |

Tổng hợp: 135 file, 110 `ALLOW`, 25 `ALERT`, 0 `TERMINATE`.

Nhận xét: kết quả Chocolatey gần như giữ nguyên so với trước vòng tuning. Điều này cho thấy tuning cho PowerShell Gallery không làm hạ quá rộng các installer/helper script của Chocolatey. Với Chocolatey, nhiều `ALERT` vẫn được xem là acceptable alert trong static analysis vì installer thường có download, registry, service hoặc uninstall behavior.

## 5. Holdout: The Stack

Kết quả pilot The Stack: 150 file, 138 `ALLOW`, 9 `ALERT`, 3 `TERMINATE`.

The Stack không phải benign corpus đã xác thực, nên các cảnh báo còn lại được xem là review candidate, không kết luận trực tiếp là false positive. Việc vẫn còn `ALERT/TERMINATE` trên The Stack cho thấy policy chưa bị whitelist quá mức sau tuning.

## 6. Chocolatey runtime test cần chạy trong VM checkpoint

Ba helper Chocolatey cần kiểm tra runtime trước khi quyết định có hạ thêm hay không:

| Package | Version | Static file | Mục tiêu runtime |
|---|---|---|---|
| jdk8 | 8.0.211 | `tools\common.ps1` | Xác minh helper download/install có sinh telemetry nguy hiểm thật hay chỉ là installer helper. |
| openjdk | 25.0.0.1 | `tools\chocolateyBeforeModify.ps1` | Xác minh beforeModify hook có hành vi registry/process đáng cảnh báo hay không. |
| sysinternals | 2026.5.7 | `tools\helpers.ps1` | Xác minh helper có tạo process/registry/network đáng cảnh báo hay chỉ hỗ trợ cài đặt. |

Script chuẩn bị:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\chocolatey\run_selected_chocolatey_runtime_tests.ps1
```

Lệnh trên chạy ở chế độ `--noop` để kiểm tra trước. Khi đã ở VM checkpoint và muốn chạy thật:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\chocolatey\run_selected_chocolatey_runtime_tests.ps1 -ExecuteInstall
```

Sau khi chạy thật, cần thu thập:

- output của script runtime;
- `PythonAgent\logs\edr_events.jsonl`;
- verdict tương ứng của ba package;
- ảnh màn hình hoặc CSV report;
- restore checkpoint để quay lại trạng thái sạch.

## 7. Atomic expanded cần chạy lại trong VM lab

Sau vòng tuning, cần chạy lại Atomic expanded trong VM lab, tốt nhất với:

- PythonAgent chạy elevated;
- Security Event ID 4688 đã bật;
- prerequisite AtomicTestHarnesses và `RegSvr32.sct` đã có;
- Defender không chặn file log của PythonAgent.

Nếu Atomic expanded vẫn pass và các FP còn lại lặp lại rõ ràng, có thể tuning tiếp. Nếu ML vẫn báo lệch mạnh trên benign corpus dù policy đã chặn ML-only escalation, lúc đó mới nên chuyển sang hướng retraining model với benign dataset lớn hơn.
