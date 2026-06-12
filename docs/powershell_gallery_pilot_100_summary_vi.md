# Kết quả pilot thu thập PowerShell Gallery 100 package

Thời điểm thực hiện: 10/06/2026 - 11/06/2026

Mục tiêu của pilot này là kiểm tra khả năng thu thập một tập benign độc lập từ PowerShell Gallery và chạy thử qua logic detection hiện tại của PythonAgent để đánh giá sơ bộ false positive.

## 1. Phạm vi thu thập

Script sử dụng:

```text
tests/powershell_gallery/collect_powershell_gallery_pilot.ps1
```

Nguồn dữ liệu:

```text
https://www.powershellgallery.com/api/v2/Packages()
```

Tiêu chí chọn ban đầu:

- Lấy các package latest version.
- Sắp xếp theo `DownloadCount` giảm dần.
- Chỉ tải offline file `.nupkg`.
- Không cài đặt module.
- Không thực thi script/module tải về.
- Chỉ trích xuất các file `.ps1`, `.psm1`, `.psd1`.

## 2. Kết quả thu thập

| Chỉ số | Kết quả |
|---|---:|
| Số package mục tiêu | 100 |
| Số package tải và giải nén thành công | 100 |
| Số file PowerShell trích xuất | 1495 |
| Số package bị skip | 1 |

Package bị skip:

| Package | Version | Lý do |
|---|---|---|
| `Az.MachineLearningServices` | `2.0.0` | Lỗi đường dẫn quá dài khi giải nén file trong package |

Các manifest sinh ra:

```text
datasets/powershell_gallery/pilot_100/metadata/packages_manifest.csv
datasets/powershell_gallery/pilot_100/metadata/files_manifest.csv
datasets/powershell_gallery/pilot_100/metadata/skipped_manifest.csv
```

## 3. Kết quả chạy thử PythonAgent

Script đánh giá:

```text
tests/powershell_gallery/evaluate_powershell_gallery_static.py
```

### 3.1. Chạy mẫu phân tầng theo package

Cấu hình:

- Tối đa 3 file mỗi package.
- Tối đa 300 file.
- Giới hạn 200 KB/file.
- Bao gồm `.ps1`, `.psm1`, `.psd1`.

Kết quả:

| Chỉ số | Kết quả |
|---|---:|
| File đánh giá | 263 |
| File skip do giới hạn/lỗi đọc | 1 |
| `ALLOW` | 11 |
| `ALERT` | 252 |
| `TERMINATE` | 0 |

Report:

```text
datasets/powershell_gallery/pilot_100/reports_stratified_3_per_package/
```

### 3.2. Chạy riêng file `.ps1`

Cấu hình:

- Chỉ lấy `.ps1`.
- Tối đa 5 file mỗi package.
- Tối đa 300 file.
- Giới hạn 200 KB/file.

Kết quả:

| Chỉ số | Kết quả |
|---|---:|
| File đánh giá | 273 |
| File skip | 7 |
| `ALLOW` | 2 |
| `ALERT` | 271 |
| `TERMINATE` | 0 |

Report:

```text
datasets/powershell_gallery/pilot_100/reports_ps1_only/
```

## 4. Nhận xét ban đầu

Kết quả có hai điểm quan trọng:

1. Không xuất hiện `TERMINATE` trên tập benign pilot.

Điều này cho thấy chính sách response hiện tại đang tương đối an toàn ở mức hành động nặng. PythonAgent chưa tự động đưa các mẫu benign PowerShell Gallery lên mức ngăn chặn cao nhất.

2. Tỷ lệ `ALERT` rất cao.

Ở cả hai lát cắt thử nghiệm, phần lớn mẫu benign bị gắn `ALERT`. Đây là dấu hiệu false positive ở mức cảnh báo. Các lý do xuất hiện nhiều nhất gồm:

- `Network indicator present`
- `Base64 payload or FromBase64String`
- `High entropy content`
- `Registry access or modification`
- một số benign indicators như module, manifest, secure string, credential helper

Nhiều package phổ biến như nhóm `Az.*`, `Microsoft.Graph.*`, `PackageManagement`, `PowerShellGet`, `DellBIOSProvider` chứa nhiều generated module, URL metadata, secure string helper, resource string hoặc Autorest-generated scripts. Các đặc điểm này dễ kích hoạt feature base64, entropy và network indicator dù là benign-by-provenance.

## 5. Ý nghĩa với tuning giảm FP

Pilot này cho thấy hướng tuning tiếp theo nên tập trung vào giảm `ALERT` không cần thiết, chưa cần tập trung vào `TERMINATE`.

Các nhóm cần phân tích sâu hơn:

| Nhóm FP | Nguyên nhân có thể |
|---|---|
| Azure/Graph Autorest module | Generated code, nhiều URL/API path, helper function |
| `.psd1` manifest/resource string | Metadata, URL, GUID, resource text có entropy cao |
| SecureString/credential helper hợp lệ | Dễ bị hiểu là credential-related behavior |
| Package/admin module có network metadata | Domain/API endpoint hợp lệ nhưng vẫn bị tính là network indicator |

## 6. Hạn chế của pilot

- Chưa loại trùng với dataset TLCN cũ.
- Chưa kiểm tra license chi tiết.
- Chưa static triage để loại package rủi ro.
- Mẫu bị thiên lệch về package phổ biến, đặc biệt nhóm `Az.*`.
- Đánh giá hiện tại là static, chưa replay để sinh 4104/4688 thực tế.
- Giới hạn 200 KB/file nên chưa bao phủ các module lớn.

## 7. Kết luận tạm thời

Pipeline thu thập PowerShell Gallery đã hoạt động và có thể tạo benign corpus độc lập. Kết quả test thử cho thấy hệ thống hiện tại đã kiểm soát tốt over-response ở mức `TERMINATE`, nhưng còn rất nhạy ở mức `ALERT` đối với benign PowerShell module/script thực tế.

Do đó, bước tiếp theo nên là phân cụm FP theo loại file/package và tuning policy/rule để giảm cảnh báo trên các benign context phổ biến, trong khi vẫn phải chạy lại Atomic Red Team expanded để đảm bảo không làm giảm khả năng phát hiện hành vi nguy hiểm.
