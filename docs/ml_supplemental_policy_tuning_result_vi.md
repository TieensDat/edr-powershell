# Kết quả tuning vai trò ML thành tín hiệu phụ

Ngày chạy: 2026-06-12

## 1. Mục tiêu

Mục tiêu của bước này là giảm tình trạng ML làm tăng quá nhiều cảnh báo trên benign/admin/devops script.

Trước tuning, khi bật ML, model có thể tự nâng nhiều mẫu từ `ALLOW` lên `ALERT` dù rule/risk chưa xác nhận đủ evidence. Điều này làm số lượng cảnh báo tăng mạnh trên PowerShell Gallery, Chocolatey và The Stack.

Sau tuning, ML được chuyển sang vai trò tín hiệu phụ:

```text
ML không tự quyết định final verdict.
ML chỉ được dùng để nâng verdict khi có evidence từ rule/risk hoặc chuỗi hành vi mạnh hỗ trợ.
```

## 2. Thay đổi kỹ thuật

File chỉnh sửa chính:

```text
PythonAgent/PythonAgent.py
```

Đã bổ sung helper:

```python
has_ml_supporting_rule_or_risk_evidence(features, rule_verdict, risk_level)
```

Điều kiện xem là có evidence hỗ trợ ML:

- `rule_verdict` là `ALERT` hoặc `TERMINATE`.
- `risk_level` là `HIGH`.
- Có high-confidence terminate signal.
- Có `download_execute_chain` hoặc `decode_execute_chain`.
- `final_risk_score` đạt ngưỡng high risk.

Ý nghĩa:

- Nếu ML báo `MALICIOUS` nhưng rule/risk không xác nhận, final verdict có thể vẫn là `ALLOW`.
- `ml_verdict` và `ml_confidence` vẫn được ghi log để phục vụ review.
- ML không còn tự tạo cảnh báo hàng loạt trên benign corpus.

## 3. Kết quả tổng hợp

| Dataset | Mode | Evaluated | ALLOW | ALERT | TERMINATE | Nhận xét |
|---|---|---:|---:|---:|---:|---|
| PowerShell Gallery | Rule/risk-only | 212 | 210 | 2 | 0 | Baseline bảo thủ sau tuning rule |
| PowerShell Gallery | ML trực tiếp trước tuning | 212 | 69 | 143 | 0 | Over-alert rất mạnh |
| PowerShell Gallery | ML tín hiệu phụ sau tuning | 212 | 196 | 16 | 0 | Giảm mạnh alert do ML |
| Chocolatey | Rule/risk-only | 135 | 111 | 24 | 0 | Baseline rule/risk |
| Chocolatey | ML trực tiếp trước tuning | 135 | 63 | 72 | 0 | Alert tăng rõ |
| Chocolatey | ML tín hiệu phụ sau tuning | 135 | 108 | 27 | 0 | Gần với rule/risk-only |
| The Stack pilot | Rule/risk-only | 150 | 137 | 10 | 3 | Public code ngoài miền |
| The Stack pilot | ML trực tiếp trước tuning | 150 | 38 | 109 | 3 | Over-alert rất mạnh |
| The Stack pilot | ML tín hiệu phụ sau tuning | 150 | 123 | 24 | 3 | Giảm mạnh alert, vẫn giữ mẫu cần review |

## 4. Nhận xét theo dataset

### 4.1. PowerShell Gallery

Sau khi chuyển ML thành tín hiệu phụ:

```text
ALERT giảm từ 143 xuống 16.
TERMINATE vẫn bằng 0.
```

Kết quả này cho thấy phần lớn cảnh báo ML trước đó là do ML tự nâng verdict trên benign/admin script mà không có đủ evidence rule/risk hỗ trợ.

So với rule/risk-only, số `ALERT` vẫn tăng từ 2 lên 16. Nhóm tăng cần review tiếp là:

- cloud automation,
- admin/windows maintenance,
- package/module management,
- utility/user scripts.

### 4.2. Chocolatey

Sau tuning:

```text
ALERT giảm từ 72 xuống 27.
TERMINATE vẫn bằng 0.
```

Kết quả gần với rule/risk-only hơn:

```text
Rule/risk-only: 24 ALERT
ML tín hiệu phụ: 27 ALERT
```

Điều này cho thấy policy mới giữ được tín hiệu ML nhưng không làm tăng cảnh báo quá mức trên installer/package scripts.

### 4.3. The Stack

The Stack là tập public code ngoài miền, không phải benign đã xác minh.

Sau tuning:

```text
ALERT/TERMINATE giảm từ 112 xuống 27.
TERMINATE giữ nguyên 3.
```

Điều này cho thấy ML vẫn được ghi nhận, nhưng không tự biến hầu hết public code thành `ALERT`.

## 5. Atomic expanded

Đã thử chạy lại Atomic expanded non-admin bằng:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tests\atomic_red_team\run_atomic_accuracy_with_agent.ps1 `
  -Set all `
  -ReportPath .\tests\atomic_red_team\atomic_accuracy_all_non_admin_ml_supplemental_report_20260612_130442.json `
  -TimeoutSeconds 30 `
  -SettleSeconds 5
```

Kết quả: test runtime không hoàn tất vì Windows Defender chặn file log:

```text
PythonAgent\logs\edr_events.jsonl
Operation did not complete successfully because the file contains a virus or potentially unwanted software.
```

Do đó chưa có report Atomic hoàn chỉnh cho vòng ML-supplemental này.

Quan sát từ stdout của PythonAgent trước khi bị chặn:

- PythonAgent load ML thành công.
- Một số event ML báo `MALICIOUS` nhưng final verdict vẫn `ALLOW` khi rule/risk không xác nhận.
- Điều này phù hợp với mục tiêu mới: ML là tín hiệu phụ, không tự nâng verdict hàng loạt.

Atomic cần chạy lại trong VM lab với checkpoint và cấu hình phù hợp, ví dụ:

- tạo checkpoint trước khi chạy,
- đảm bảo Defender không chặn chính file log EDR,
- hoặc đưa thư mục log lab vào exclusion có kiểm soát,
- sau khi chạy xong phải restore hoặc kiểm tra sạch môi trường.

## 6. Đánh giá

Kết quả sau tuning tốt hơn đáng kể so với ML trực tiếp:

- PowerShell Gallery giảm `ALERT` từ 143 xuống 16.
- Chocolatey giảm `ALERT` từ 72 xuống 27.
- The Stack giảm `ALERT/TERMINATE` từ 112 xuống 27.

ML vẫn chưa nên được dùng như verdict chính, nhưng đã phù hợp hơn với vai trò:

- tín hiệu phụ,
- trường dữ liệu phục vụ review,
- yếu tố hỗ trợ khi rule/risk đã có evidence,
- cơ sở để chọn mẫu retraining sau này.

## 7. Kết luận

Việc chuyển ML sang vai trò tín hiệu phụ là hướng xử lý hợp lý ở giai đoạn hiện tại. Nó giảm đáng kể false positive candidate trên benign corpus mà vẫn giữ lại khả năng ghi nhận `ml_verdict` để phục vụ phân tích.

Chưa cần retrain ngay sau bước này. Việc cần làm tiếp theo là:

1. Review các mẫu còn `ALERT` trong PowerShell Gallery, Chocolatey và The Stack.
2. Chạy lại Atomic expanded trong VM lab sau khi xử lý blocker Defender/log.
3. Nếu sau review vẫn còn pattern FP lặp lại, tiếp tục tuning rule/policy nhỏ.
4. Chỉ chuyển sang retraining khi policy tuning không còn giảm được FP mà không làm mất detection.

## 8. File kết quả

PowerShell Gallery:

```text
datasets/powershell_gallery/behavior_groups_80/reports_ml_supplemental_current/
```

Chocolatey:

```text
datasets/chocolatey/behavior_groups_80_casefixed/reports_ml_supplemental_current/
```

The Stack:

```text
datasets/the_stack/powershell_pilot/reports_ml_supplemental_current/
```

Atomic stdout/stderr:

```text
tests/atomic_red_team/logs/pythonagent_atomic_accuracy_20260612_130445.out.log
tests/atomic_red_team/logs/pythonagent_atomic_accuracy_20260612_130445.err.log
```
