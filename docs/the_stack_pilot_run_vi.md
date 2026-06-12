# Báo cáo chạy pilot The Stack

Ngày thực hiện: 2026-06-11

## 1. Mục tiêu

Mục tiêu của bước này là thu thập một tập pilot nhỏ từ The Stack để kiểm tra pipeline trước khi lấy tập lớn. Pipeline được kiểm tra theo hướng an toàn:

- Chỉ thu thập và phân tích tĩnh mã PowerShell public.
- Không thực thi script từ The Stack.
- Dedup với dữ liệu đã dùng trong các vòng tuning trước.
- Chạy static baseline bằng logic detection hiện tại của PythonAgent nếu thu thập thành công.

The Stack không được xem là tập benign tuyệt đối. Đây là tập mã nguồn public ngoài miền, dùng để kiểm tra khả năng generalization và phát hiện các pattern có nguy cơ false positive.

## 2. Thành phần đã chuẩn bị

Đã bổ sung các file phục vụ pipeline:

```text
tests/the_stack/collect_the_stack_pilot.py
tests/the_stack/evaluate_the_stack_static.py
tests/the_stack/run_the_stack_pilot_baseline.ps1
```

Collector có cấu hình pilot:

| Tham số | Giá trị |
|---|---:|
| Dataset | `bigcode/the-stack` |
| Data dir | `data/powershell` |
| Tổng file mục tiêu | 150 |
| `.ps1` | 90 |
| `.psm1` | 40 |
| `.psd1` | 20 |
| Max file size | 200 KB |
| Min file size | 200 bytes |
| Max file/repository | 5 |
| Max stream items | 50000 |

Các dependency đã được cài đặt để chạy collector:

```text
datasets
huggingface-hub
pyarrow
```

## 3. Kết quả chạy collector

Lệnh đã chạy:

```powershell
python .\tests\the_stack\collect_the_stack_pilot.py `
  --output-root .\datasets\the_stack\powershell_pilot `
  --target-total 150 `
  --target-ps1 90 `
  --target-psm1 40 `
  --target-psd1 20 `
  --max-stream-items 50000
```

Sau khi thiết lập `HF_TOKEN`, collector đã truy cập được gated dataset và thu thập đủ pilot.

```text
status: completed
processed_stream_items: 817
selected_total: 150
selected_by_extension:
  .ps1: 90
  .psm1: 40
  .psd1: 20
```

Cấu hình dedup đã dùng:

| Nguồn dedup | Số dòng manifest | Raw hash | Normalized hash |
|---|---:|---:|---:|
| PowerShell Gallery behavior groups | 212 | 192 | 192 |
| Chocolatey behavior groups | 135 | 134 | 134 |

Các file đầu ra chính:

```text
datasets/the_stack/powershell_pilot/metadata/files_manifest.csv
datasets/the_stack/powershell_pilot/metadata/collection_summary.json
datasets/the_stack/powershell_pilot/extracted_scripts/
```

Lưu ý: trong quá trình tải có xuất hiện cảnh báo retry từ Hugging Face, nhưng collector vẫn hoàn tất và tạo đủ manifest. Đây là hiện tượng network/retry ở bước streaming, không làm mất kết quả pilot.

## 4. Kết quả static baseline

Sau khi có `files_manifest.csv`, đã chạy static baseline bằng logic detection hiện tại của PythonAgent.

Lệnh đã chạy:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tests\the_stack\run_the_stack_pilot_baseline.ps1 `
  -FilesManifest .\datasets\the_stack\powershell_pilot\metadata\files_manifest.csv `
  -OutputRoot .\datasets\the_stack\powershell_pilot\reports `
  -AgentPath .\PythonAgent\PythonAgent.py
```

Kết quả tổng hợp:

| Chỉ số | Giá trị |
|---|---:|
| Tổng file đánh giá | 150 |
| Skipped | 0 |
| `ALLOW` | 137 |
| `ALERT` | 10 |
| `TERMINATE` | 3 |
| Tổng mẫu cần review | 13 |
| ML verdict | `UNKNOWN` cho 150/150 mẫu |

Kết quả theo loại file:

| Extension | Tổng file | ALLOW | ALERT | TERMINATE |
|---|---:|---:|---:|---:|
| `.ps1` | 90 | 81 | 8 | 1 |
| `.psm1` | 40 | 36 | 2 | 2 |
| `.psd1` | 20 | 20 | 0 | 0 |

Kết quả theo size bucket:

| Size bucket | Tổng file | ALLOW | ALERT | TERMINATE |
|---|---:|---:|---:|---:|
| `< 1 KB` | 28 | 28 | 0 | 0 |
| `1 KB - 10 KB` | 89 | 81 | 7 | 1 |
| `10 KB - 50 KB` | 33 | 28 | 3 | 2 |

Các file report:

```text
datasets/the_stack/powershell_pilot/reports/evaluation_summary.json
datasets/the_stack/powershell_pilot/reports/evaluation_results.csv
datasets/the_stack/powershell_pilot/reports/alert_or_terminate_results.csv
datasets/the_stack/powershell_pilot/reports/summary_by_extension.csv
datasets/the_stack/powershell_pilot/reports/summary_by_size_bucket.csv
datasets/the_stack/powershell_pilot/reports/top_alert_reasons.csv
```

## 5. Các mẫu cần review

Có 13/150 mẫu có verdict cuối là `ALERT` hoặc `TERMINATE`. Cần nhấn mạnh rằng The Stack là mã nguồn public ngoài miền, không phải tập benign đã xác minh. Vì vậy:

- `ALERT` trên The Stack là ứng viên cần review, không tự động xem là false positive.
- `TERMINATE` trên code public cần được review thủ công 100% để phân biệt over-response với code dual-use/nguy hiểm thật.
- Không tuning trực tiếp từ pilot nếu chưa thấy pattern lặp lại rõ ràng.

Ba mẫu `TERMINATE` trong pilot:

| Sample | Repo | Path | Extension | Reason chính |
|---|---|---|---|---|
| `stack_pilot_000114` | `ocalvo/PwrSudo` | `PwrSudo.psm1` | `.psm1` | Dynamic execution, downloader, network, registry access |
| `stack_pilot_000121` | `proxb/PoshDesktops` | `PoshDesktop.psm1` | `.psm1` | Network indicator, high risk score |
| `stack_pilot_000039` | `vilega/O365Troubleshooters` | `ActionPlans/Start-Office365Relay.ps1` | `.ps1` | Credential-related keyword, network indicator |

Một điểm cần giải thích trong báo cáo: lý do `Network indicator present` xuất hiện rất nhiều là vì mã nguồn public thường chứa URL, domain, endpoint, documentation link hoặc logic kết nối dịch vụ. Do đó chỉ số này có giá trị như tín hiệu review, không đủ để kết luận độc hại nếu đứng riêng.

## 6. Nhận xét ban đầu

Kết quả pilot cho thấy pipeline The Stack đã hoạt động end-to-end:

- Thu thập được dữ liệu từ gated dataset.
- Dedup với PowerShell Gallery và Chocolatey.
- Lưu được metadata phục vụ truy vết.
- Chạy được static baseline bằng PythonAgent.
- Sinh được danh sách mẫu cần review.

Kết quả này chưa nên dùng để tính false positive rate, vì nhãn của The Stack là `unknown_public_code`, không phải `benign`. Giá trị chính của pilot là kiểm tra khả năng generalization và phát hiện nhóm pattern cần review ngoài miền PowerShell Gallery/Chocolatey.

## 7. Chạy lại baseline với ML model

Sau lần baseline rule-only, evaluator được bổ sung tùy chọn bật ML:

```text
tests/the_stack/evaluate_the_stack_static.py --enable-ml
tests/the_stack/run_the_stack_pilot_baseline.ps1 -EnableML
```

Lệnh chạy lại:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tests\the_stack\run_the_stack_pilot_baseline.ps1 `
  -FilesManifest .\datasets\the_stack\powershell_pilot\metadata\files_manifest.csv `
  -OutputRoot .\datasets\the_stack\powershell_pilot\reports_ml_enabled `
  -AgentPath .\PythonAgent\PythonAgent.py `
  -EnableML
```

Model được load thành công:

```text
ML enabled: true
Feature columns: 165
```

Kết quả so sánh:

| Kịch bản | ALLOW | ALERT | TERMINATE | ML verdict |
|---|---:|---:|---:|---|
| Rule/risk-only baseline | 137 | 10 | 3 | `UNKNOWN`: 150 |
| ML-enabled baseline | 38 | 109 | 3 | `MALICIOUS`: 130, `BENIGN`: 20 |

Kết quả ML-enabled theo loại file:

| Extension | Tổng file | ALLOW | ALERT | TERMINATE |
|---|---:|---:|---:|---:|
| `.ps1` | 90 | 30 | 59 | 1 |
| `.psm1` | 40 | 7 | 31 | 2 |
| `.psd1` | 20 | 1 | 19 | 0 |

Thống kê confidence:

| ML verdict | Số mẫu | Confidence trung bình | Min | Max |
|---|---:|---:|---:|---:|
| `BENIGN` | 20 | 0.97 | 0.83 | 1.00 |
| `MALICIOUS` | 130 | 0.78 | 0.58 | 0.97 |

Có 85 mẫu có `rule_verdict=ALLOW` nhưng final verdict chuyển thành `ALERT` do `ml_verdict=MALICIOUS`. Điều này cho thấy model học từ dataset TLCN trước đó có xu hướng gán nhãn malicious cho nhiều mã PowerShell public ngoài miền. Đây là tín hiệu quan trọng về khả năng generalization của model, không nên diễn giải là hệ thống phát hiện tốt hơn nếu chưa có manual review.

Nhận xét khoa học:

- Rule/risk-only baseline bảo thủ hơn và tạo danh sách review nhỏ hơn: 13/150 mẫu.
- ML-enabled baseline tạo danh sách review lớn hơn nhiều: 112/150 mẫu.
- The Stack không phải tập benign đã xác minh, nhưng tỷ lệ `MALICIOUS` 130/150 trên mã public cho thấy model có nguy cơ over-alert khi gặp code ngoài phân phối huấn luyện.
- Kết quả này củng cố nhận định trước đó: ML không nên được dùng độc lập để quyết định verdict cuối, mà cần kết hợp rule, risk, source context và ngưỡng confidence.

Các file report ML-enabled:

```text
datasets/the_stack/powershell_pilot/reports_ml_enabled/evaluation_summary.json
datasets/the_stack/powershell_pilot/reports_ml_enabled/evaluation_results.csv
datasets/the_stack/powershell_pilot/reports_ml_enabled/alert_or_terminate_results.csv
datasets/the_stack/powershell_pilot/reports_ml_enabled/summary_by_extension.csv
datasets/the_stack/powershell_pilot/reports_ml_enabled/summary_by_size_bucket.csv
datasets/the_stack/powershell_pilot/reports_ml_enabled/top_alert_reasons.csv
```

## 8. Hướng xử lý tiếp theo

Các bước tiếp theo:

1. Review thủ công 3 mẫu `TERMINATE`.
2. Review 10 mẫu `ALERT` từ rule/risk-only baseline.
3. Lấy mẫu đại diện từ 109 `ALERT` của ML-enabled baseline để đánh giá xu hướng over-alert của model.
4. Phân loại từng mẫu theo nhãn:
   - `acceptable_alert`
   - `true_fp_candidate`
   - `suspicious_public_code`
   - `unknown_needs_context`
5. Chỉ tuning rule/policy tiếp nếu có pattern lặp lại rõ ràng và an toàn, ví dụ URL trong comment/documentation hoặc manifest metadata.
6. Không dùng The Stack pilot để retrain ngay. Nếu cần dùng cho ML, phải tách train/validation/holdout và gán nhãn thủ công.
7. Nếu pilot ổn định, mở rộng sang holdout lớn hơn 500-1000 file.

## 9. Kết luận tạm thời

Pilot The Stack đã chạy thành công với 150 file PowerShell public ngoài miền. Ở chế độ rule/risk-only, hệ thống cho phép 137/150 mẫu, cảnh báo 10/150 mẫu và terminate 3/150 mẫu. Khi bật ML model, số mẫu cảnh báo tăng mạnh lên 109/150, trong khi `TERMINATE` vẫn là 3/150.

Kết quả này cho thấy The Stack là bước kiểm tra generalization hữu ích: rule/policy hiện tại tương đối bảo thủ hơn, còn ML model cần được đánh giá thêm về khả năng over-alert trên mã nguồn PowerShell public ngoài miền.
