# Kết quả tuning verdict PythonAgent

## 1. Mục tiêu tuning

Mục tiêu của lần tuning này là giảm dương tính giả do ML model đẩy các hành vi quản trị lành tính lên `ALERT`, đồng thời tránh nâng `TERMINATE` quá mức đối với các dấu hiệu suspicious đơn lẻ như `EncodedCommand` hoặc `WindowStyle Hidden`.

Việc tuning không thay thế model ML, mà bổ sung lớp policy sau bước `combine_verdict` để kết hợp thêm ngữ cảnh rule, risk level, source và nhóm chỉ báo hành vi.

## 2. Thay đổi chính

- Bổ sung nhận diện chuỗi `[char]`/ASCII reconstruction ở dạng có ngoặc, ví dụ `([char]73)+([char]69)+([char]88)`.
- Đưa `ascii_char_sequence` vào nhóm obfuscation và alert flag.
- Bổ sung nhóm tín hiệu `TERMINATE` có độ tin cậy cao:
  - AMSI bypass.
  - Defender tampering hoặc clear event log.
  - Download + execute chain.
  - Cụm memory injection API từ 3 chỉ báo trở lên.
  - Persistence kết hợp encoded/hidden/no-profile execution.
- Hạ `TERMINATE` xuống `ALERT` nếu chỉ có dấu hiệu suspicious đơn lẻ và chưa có chuỗi hành vi nguy hiểm.
- Hạ `ALERT` xuống `ALLOW` cho một số ngữ cảnh quản trị/lành tính khi rule là `ALLOW`, risk thấp hoặc trung bình, nhưng ML vẫn dự đoán `MALICIOUS/SUSPICIOUS`.

## 3. Kết quả trước và sau tuning

| Bộ test | Tổng số case | Pass | Fail | Pass rate |
|---|---:|---:|---:|---:|
| Trước tuning | 21 | 11 | 10 | 52.38% |
| Sau tuning | 21 | 21 | 0 | 100% |

Report sau tuning:

```text
tests/verdict_tuning/verdict_tuning_report_after_20260610_174407.json
tests/verdict_tuning/verdict_tuning_report_after_20260610_174407.csv
```

## 4. Các thay đổi verdict đáng chú ý

| Case | Trước tuning | Sau tuning | Ý nghĩa |
|---|---|---|---|
| VT-BEN-005 | ALERT | ALLOW | Giảm FP cho registry read phục vụ locale/admin discovery. |
| VT-BEN-007 | ALERT | ALLOW | Giảm FP cho thao tác file tạm có cleanup rõ ràng. |
| VT-SUS-101 | TERMINATE | ALERT | EncodedCommand benign không bị terminate nếu chưa có chuỗi nguy hiểm. |
| VT-SUS-103 | ALLOW | ALERT | Bắt được char/ASCII reconstruction là hành vi obfuscation đáng nghi. |
| VT-SUS-105 | TERMINATE | ALERT | Hidden PowerShell benign chỉ cảnh báo, không chặn cứng. |
| VT-MAL-203 | ALERT | TERMINATE | AMSI bypass được nâng lên mức response cao. |
| VT-MAL-204 | ALERT | TERMINATE | Defender tampering được nâng lên mức response cao. |
| VT-MAL-206 | ALERT | TERMINATE | Cụm memory injection API được nâng lên mức response cao. |
| VT-BRD-301 | ALERT | ALLOW | SecureString/PSCredential trong ngữ cảnh benign không còn bị ML kéo lên ALERT. |
| VT-BRD-302 | ALERT | ALLOW | Đọc Event Log không bị coi là hành vi phá hoại nếu không có clear log. |

## 5. Đánh giá

Kết quả sau tuning phù hợp hơn với mục tiêu prototype trong môi trường lab: hệ thống vẫn ưu tiên `TERMINATE` cho hành vi có độ tin cậy cao như bypass, tampering, download-execute, persistence và memory injection, nhưng không chặn cứng các hành vi discovery hoặc quản trị phổ biến.

Tuy nhiên, kết quả 100% chỉ có ý nghĩa trên bộ `verdict_tuning` hiện tại. Để tránh overfitting vào bộ test nhỏ, cần tiếp tục chạy lại các nhóm test lớn hơn như Atomic Red Team, response test, benign script set và nếu có thể là tập benign PowerShell lớn hơn.
