# Kiểm tra generalization sau tuning với fleschutz/PowerShell

## 1. Mục tiêu

Tập `fleschutz/PowerShell` được sử dụng như holdout sau tuning, không dùng làm tập tuning chính. Mục tiêu là kiểm tra hệ thống sau khi đã giảm FP trên PowerShell Gallery và Chocolatey có còn giữ được khả năng phân biệt các script PowerShell ngoài miền hay không.

Nguồn dữ liệu:

- Repository: `https://github.com/fleschutz/PowerShell`
- Nội dung: bộ sưu tập script PowerShell độc lập trong thư mục `scripts`
- License: `CC0-1.0`
- Số file `.ps1` thu thập: 681

## 2. Cách chạy

Repo được tải về:

```powershell
git clone --depth 1 https://github.com/fleschutz/PowerShell.git datasets\fleschutz\PowerShell
```

Tạo manifest và chạy static baseline với ML bật:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\fleschutz\run_fleschutz_holdout_baseline.ps1 -EnableML
```

Kết quả được lưu tại:

```text
datasets\fleschutz\powershell_scripts\reports_ml_supplemental_current
```

## 3. Kết quả tổng quan

| Chỉ số | Giá trị |
|---|---:|
| Số file đánh giá | 681 |
| Skipped | 0 |
| ALLOW | 641 |
| ALERT | 36 |
| TERMINATE | 4 |
| ML MALICIOUS | 677 |
| ML BENIGN | 4 |

Nhận xét chính: mặc dù ML vẫn gán `MALICIOUS` cho gần như toàn bộ tập holdout, policy hiện tại không cho ML tự nâng verdict nếu thiếu evidence từ rule/risk. Vì vậy kết quả cuối cùng chỉ còn 40/681 file ở mức `ALERT` hoặc `TERMINATE`.

## 3.1. So sánh với chế độ rule/risk-only

Để kiểm tra vai trò thực tế của ML sau tuning, tập holdout được chạy lại một lần nữa nhưng không load ML model. Khi đó toàn bộ `ml_verdict` là `UNKNOWN`, verdict cuối chỉ dựa trên rule, risk score và policy tuning.

Kết quả rule/risk-only:

| Chế độ | ALLOW | ALERT | TERMINATE | Ghi chú |
|---|---:|---:|---:|---|
| ML-enabled | 641 | 36 | 4 | ML được bật, nhưng chỉ là tín hiệu phụ |
| Rule/risk-only | 641 | 36 | 4 | ML không được load |

Đối chiếu từng file cho thấy `changed_count = 0`, nghĩa là không có file nào đổi verdict giữa hai chế độ. Kết quả này cho thấy chính sách hiện tại đã khóa ML đúng vai trò phụ trên tập holdout: ML không còn tự tạo cảnh báo mới nếu thiếu bằng chứng từ rule/risk.

## 4. Kết quả theo nhóm hành vi

| Nhóm | Số file | ALLOW | ALERT | TERMINATE |
|---|---:|---:|---:|---:|
| user_state_changing | 200 | 186 | 12 | 2 |
| discovery_readonly | 160 | 155 | 4 | 1 |
| admin_state_changing | 20 | 18 | 1 | 1 |
| utility_misc | 174 | 160 | 14 | 0 |
| media_user_utility | 83 | 81 | 2 | 0 |
| dev_build_utility | 24 | 22 | 2 | 0 |
| network_web_utility | 20 | 19 | 1 | 0 |

## 5. Kết quả theo mức an toàn runtime

| Nhóm runtime | Số file | ALLOW | ALERT | TERMINATE |
|---|---:|---:|---:|---:|
| vm_checkpoint_required | 227 | 208 | 16 | 3 |
| static_or_manual_review | 454 | 433 | 20 | 1 |

Các script cần VM checkpoint thường là nhóm có khả năng thay đổi trạng thái hệ thống như install, poweroff/reboot, Defender, firewall, scheduled task hoặc thay đổi cấu hình người dùng.

## 6. Review các TERMINATE

| File | Verdict | Nhận xét |
|---|---|---|
| `install-scoop.ps1` | TERMINATE | Có chuỗi `Invoke-RestMethod ... | Invoke-Expression`, là download-execute chain. `TERMINATE` có thể chấp nhận trong prototype vì hành vi tương tự fileless downloader. |
| `install-chocolatey.ps1` | TERMINATE | Có `iwr https://community.chocolatey.org/install.ps1 ... | iex`, là download-execute chain. `TERMINATE` có thể chấp nhận trong static detection. |
| `windefender.ps1` | TERMINATE | Có thao tác `Set-MpPreference` để bật/tắt Defender realtime monitoring. Đây là hành vi nhạy cảm, `TERMINATE` phù hợp với chính sách response conservative. |
| `list-cli-tools.ps1` | TERMINATE | Đây là discovery/read-only script nhưng gọi nhiều CLI qua `Invoke-Expression`, bao gồm các LOLBin như `bitsadmin`, `certutil`, `cmd`. Đây là over-response candidate cần ghi nhận, nhưng chưa tuning vì tập này là holdout. |

## 7. Diễn giải kết quả

Kết quả này khá tốt cho mục tiêu generalization:

- Hệ thống không bị ML kéo toàn bộ benign public scripts lên `ALERT`.
- Tỷ lệ `ALLOW` đạt 641/681 file, cho thấy policy sau tuning đã giảm đáng kể FP từ ML.
- Các `TERMINATE` chủ yếu rơi vào hành vi download-execute hoặc Defender tampering, phù hợp với rule hiện tại.
- Có ít nhất một candidate cần review (`list-cli-tools.ps1`), cho thấy hệ thống vẫn còn khả năng over-response với script discovery dùng `Invoke-Expression` để gọi nhiều command-line tools.

## 8. Kết luận

Tập `fleschutz/PowerShell` có thể được sử dụng trong báo cáo như một holdout generalization sau tuning. Kết quả hỗ trợ nhận định rằng hệ thống hiện tại không chỉ tối ưu cho PowerShell Gallery/Chocolatey, mà vẫn hoạt động tương đối ổn trên một tập script PowerShell công khai ngoài miền.

Không nên tuning tiếp trực tiếp trên tập này ở giai đoạn hiện tại. Nếu muốn xử lý tiếp, chỉ nên xem xét khi các pattern over-response lặp lại trên nhiều holdout khác nhau, ví dụ discovery script dùng `Invoke-Expression` để gọi tool version/check command.
