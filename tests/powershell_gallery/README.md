# PowerShell Gallery benign pilot

Mục tiêu của thư mục này là thu thập thử nghiệm 100 package từ PowerShell Gallery ở dạng offline, trích các file `.ps1`, `.psm1`, `.psd1`, sau đó chạy qua logic detection hiện tại của `PythonAgent` để đo nhanh mức `ALLOW/ALERT/TERMINATE` trên benign-by-provenance.

## 1. Thu thập pilot 100 package

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\powershell_gallery\collect_powershell_gallery_pilot.ps1 `
  -TargetPackages 100 `
  -CandidatePages 5 `
  -PageSize 100 `
  -MaxPackageSizeMB 50 `
  -OutputRoot .\datasets\powershell_gallery\pilot_100
```

Script chỉ tải package `.nupkg` và giải nén offline. Script không cài đặt module và không thực thi nội dung tải về.

## 2. Chạy đánh giá static bằng PythonAgent

```powershell
python .\tests\powershell_gallery\evaluate_powershell_gallery_static.py `
  --files-manifest .\datasets\powershell_gallery\pilot_100\metadata\files_manifest.csv `
  --agent-path .\PythonAgent\PythonAgent.py `
  --output-dir .\datasets\powershell_gallery\pilot_100\reports
```

Các kết quả chính:

- `evaluation_summary.json`
- `evaluation_results.csv`
- `alert_or_terminate_results.csv`
- `package_verdict_summary.csv`

## 3. Lưu ý

Pilot này chưa loại trùng với dataset TLCN cũ. Mục tiêu hiện tại chỉ là kiểm tra đường ống thu thập và chạy thử detection trên một benign corpus nhỏ.
