# So sánh baseline rule/risk-only và ML + rule/risk

Ngày chạy: 2026-06-12

## 1. Mục tiêu

Mục tiêu của bước này là chạy lại PowerShell Gallery và Chocolatey với ML model được bật để so sánh với kết quả rule/risk-only trước đó.

Các baseline trước đó chủ yếu dùng:

```text
rule + risk score + policy tuning
```

Lần chạy mới dùng:

```text
ML model + rule + risk score + policy tuning
```

Lưu ý: hai tập PowerShell Gallery và Chocolatey đang được dùng như tập benign/near-benign để đánh giá false positive candidate. Vì vậy nếu bật ML làm số `ALERT` tăng mạnh, đây là tín hiệu cần phân tích cẩn thận về khả năng over-alert của model.

## 2. Thay đổi kỹ thuật

Đã bổ sung tùy chọn bật ML cho các evaluator:

```text
tests/powershell_gallery/evaluate_powershell_gallery_static.py --enable-ml
tests/chocolatey/evaluate_chocolatey_static.py --enable-ml
```

Đã bổ sung switch cho runner:

```text
tests/powershell_gallery/run_behavior_group_baseline.ps1 -EnableML
tests/chocolatey/run_chocolatey_baseline.ps1 -EnableML
```

Khi bật `EnableML`, evaluator gọi:

```python
agent.load_ml_model()
```

sau đó mới gọi:

```python
agent.build_detection_result(event)
```

## 3. Phạm vi chạy

Để tránh thời gian chạy quá dài, lần này chỉ chạy theo lát cắt `category`, không chạy thêm `extension` hoặc `category+extension`.

PowerShell Gallery:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tests\powershell_gallery\run_behavior_group_baseline.ps1 `
  -FilesManifest .\datasets\powershell_gallery\behavior_groups_80\metadata\files_manifest.csv `
  -OutputRoot .\datasets\powershell_gallery\behavior_groups_80\reports_ml_enabled_current `
  -AgentPath .\PythonAgent\PythonAgent.py `
  -SkipSliceBaselines `
  -EnableML
```

Chocolatey:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tests\chocolatey\run_chocolatey_baseline.ps1 `
  -FilesManifest .\datasets\chocolatey\behavior_groups_80_casefixed\metadata\files_manifest.csv `
  -OutputRoot .\datasets\chocolatey\behavior_groups_80_casefixed\reports_ml_enabled_current `
  -AgentPath .\PythonAgent\PythonAgent.py `
  -SkipSliceBaselines `
  -EnableML
```

## 4. Kết quả tổng hợp

| Dataset | Mode | Evaluated | ALLOW | ALERT | TERMINATE | ML verdict |
|---|---|---:|---:|---:|---:|---|
| PowerShell Gallery | Rule/risk-only | 212 | 210 | 2 | 0 | `UNKNOWN`: 212 |
| PowerShell Gallery | ML + rule/risk | 212 | 69 | 143 | 0 | `MALICIOUS`: 157, `BENIGN`: 55 |
| Chocolatey | Rule/risk-only | 135 | 111 | 24 | 0 | `UNKNOWN`: 135 |
| Chocolatey | ML + rule/risk | 135 | 63 | 72 | 0 | `MALICIOUS`: 70, `BENIGN`: 65 |

## 5. PowerShell Gallery theo nhóm hành vi

| Nhóm | Evaluated | Rule-only ALERT | ML + rule/risk ALERT | Chênh lệch |
|---|---:|---:|---:|---:|
| `cloud_automation` | 43 | 0 | 20 | +20 |
| `dsc_config_management` | 30 | 0 | 28 | +28 |
| `package_module_management` | 27 | 1 | 19 | +18 |
| `admin_windows_maintenance` | 31 | 1 | 20 | +19 |
| `devops_build_test` | 28 | 0 | 20 | +20 |
| `security_audit_compliance_benign` | 26 | 0 | 16 | +16 |
| `utility_user_scripts` | 27 | 0 | 20 | +20 |
| **Tổng** | **212** | **2** | **143** | **+141** |

ML verdict tổng hợp trên PowerShell Gallery:

| ML verdict | Số mẫu |
|---|---:|
| `MALICIOUS` | 157 |
| `BENIGN` | 55 |

## 6. Chocolatey theo nhóm hành vi

| Nhóm | Evaluated | Rule-only ALERT | ML + rule/risk ALERT | Chênh lệch |
|---|---:|---:|---:|---:|
| `browser_user_apps` | 24 | 3 | 10 | +7 |
| `dev_tools` | 14 | 1 | 7 | +6 |
| `runtime_language` | 18 | 3 | 13 | +10 |
| `sysadmin_utilities` | 23 | 7 | 10 | +3 |
| `security_tools_benign` | 15 | 3 | 5 | +2 |
| `package_dependency_tools` | 22 | 1 | 15 | +14 |
| `windows_maintenance_config` | 19 | 6 | 12 | +6 |
| **Tổng** | **135** | **24** | **72** | **+48** |

ML verdict tổng hợp trên Chocolatey:

| ML verdict | Số mẫu |
|---|---:|
| `MALICIOUS` | 70 |
| `BENIGN` | 65 |

## 7. Nhận xét

Kết quả cho thấy khi bật ML, số lượng `ALERT` tăng mạnh trên cả hai tập:

- PowerShell Gallery: từ 2/212 lên 143/212.
- Chocolatey: từ 24/135 lên 72/135.

Không có mẫu nào bị `TERMINATE` trong hai tập khi chạy ML-enabled. Điều này cho thấy policy tuning hiện tại vẫn đang ngăn ML đẩy benign script lên mức response cứng, nhưng ML vẫn làm tăng đáng kể lượng cảnh báo cần review.

PowerShell Gallery bị ảnh hưởng mạnh hơn Chocolatey. Nguyên nhân có thể là các module PowerShell Gallery chứa nhiều logic admin, cloud automation, DSC, package management, network endpoint, download helper hoặc dynamic script pattern. Đây là các đặc trưng dễ giống với mẫu malicious trong dataset huấn luyện cũ.

Chocolatey tăng ít hơn nhưng vẫn đáng kể, đặc biệt ở nhóm `package_dependency_tools` và `runtime_language`, vì installer script thường có hành vi tải file, checksum, URL, silent install, sửa môi trường hoặc gọi process.

## 8. Kết luận kỹ thuật

Kết quả này cho thấy model ML hiện tại không nên được dùng độc lập để quyết định verdict trên benign script thực tế. Vai trò hợp lý hơn của ML ở giai đoạn này là:

- tín hiệu phụ trợ,
- ưu tiên mẫu cần review,
- kết hợp với rule/risk/context,
- không tự động nâng verdict nếu không có evidence hành vi đủ mạnh.

Rule/risk-only sau tuning đang cho kết quả bảo thủ hơn trên benign corpus. ML-enabled giúp phát hiện thêm nhiều mẫu đáng nghi, nhưng đồng thời tạo nguy cơ false positive cao. Đây là bằng chứng cho thấy nếu muốn dùng ML mạnh hơn trong verdict cuối, cần có thêm một trong các hướng sau:

1. Calibration lại confidence threshold.
2. Bổ sung benign dataset lớn hơn vào quá trình retraining.
3. Tách model theo loại source/context.
4. Dùng ML như score phụ thay vì verdict trực tiếp.
5. Gán nhãn thủ công một phần PowerShell Gallery/Chocolatey/The Stack để kiểm tra generalization.

## 9. File kết quả

PowerShell Gallery ML-enabled:

```text
datasets/powershell_gallery/behavior_groups_80/reports_ml_enabled_current/
```

Chocolatey ML-enabled:

```text
datasets/chocolatey/behavior_groups_80_casefixed/reports_ml_enabled_current/
```

File tổng hợp ở thư mục gốc:

```text
behavior_group_baseline_summary.csv
behavior_group_baseline_summary.json
chocolatey_baseline_summary.csv
chocolatey_baseline_summary.json
```

Trong từng thư mục category có các file:

```text
evaluation_summary.json
evaluation_results.csv
alert_or_terminate_results.csv
package_verdict_summary.csv
```
