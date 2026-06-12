# Hướng Dẫn Cài Atomic Red Team Trên Máy Test Windows 10

Tài liệu này dùng cho kịch bản đo hiệu năng `attack workload` khi muốn chạy đồng thời:

- Synthetic attack workload của project.
- Atomic Red Team selected tests.

## 1. Mục tiêu

Cài Invoke-AtomicRedTeam và thư mục atomics vào máy Windows 10 test để script của project có thể chạy:

```powershell
.\scripts\measure_attack_workload.ps1 -Mode Both
```

Runner của project đang mặc định dùng:

```text
C:\AtomicRedTeam\atomics
C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1
```

Vì vậy nên cài Atomic Red Team theo đúng đường dẫn `C:\AtomicRedTeam`.

## 2. Điều kiện trước khi cài

Máy test cần có:

- Windows 10/11.
- PowerShell 5.1 trở lên.
- Internet để tải module và atomics.
- Quyền Administrator khuyến nghị nếu cài vào `C:\AtomicRedTeam`.
- VM snapshot/checkpoint trước khi cài.

Lưu ý: thư mục atomics có thể chứa payload hoặc test definition dễ bị antivirus cảnh báo. Đây là hành vi bình thường khi dùng Atomic Red Team trong lab. Nên chỉ chạy trong máy ảo test.

## 3. Cài Invoke-AtomicRedTeam và atomics

Mở PowerShell bằng quyền Administrator và chạy:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Install-Module -Name powershell-yaml -Scope CurrentUser -Force

IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
```

Sau khi cài xong, kiểm tra:

```powershell
Test-Path C:\AtomicRedTeam\atomics
Test-Path C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1
```

Cả hai lệnh nên trả về:

```text
True
```

## 4. Import module và kiểm tra nhanh

Chạy:

```powershell
Import-Module powershell-yaml -Force
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 -Force

Invoke-AtomicTest T1059.001 -ShowDetailsBrief -PathToAtomicsFolder C:\AtomicRedTeam\atomics
```

Nếu lệnh hiển thị danh sách test của `T1059.001`, môi trường Atomic đã sẵn sàng.

## 5. Bổ sung runner Atomic vào gói runtime

Gói runtime cần có tối thiểu các file sau:

```text
tests\atomic_red_team\run_selected_atomic_tests.ps1
tests\atomic_red_team\selected_atomic_tests.json
```

Nếu dùng zip runtime mới nhất của project thì các file này đã được thêm vào release. Nếu máy test đang dùng zip cũ, copy thư mục sau từ repo sang máy test:

```text
tests\atomic_red_team
```

## 6. Kiểm tra PythonAgent trước khi chạy Atomic

Tại thư mục runtime, chạy:

```powershell
.\scripts\start_python_agent.ps1 -Force
Invoke-RestMethod http://127.0.0.1:9001/health
```

Nếu cần AMSI bridge:

```powershell
.\scripts\start_cpp_agent.ps1
```

Đảm bảo health trả về:

```text
status = running
```

## 7. Chạy attack workload kết hợp Synthetic + Atomic

Khuyến nghị restore về checkpoint `CP03_PythonAgent_CPPAgent_OK` trước mỗi lần đo.

Chạy:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_attack_workload.ps1 -Mode Both -Label attack_both_run1 -DurationSeconds 600 -SampleIntervalSeconds 1
```

Lặp lại 4 lần:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_attack_workload.ps1 -Mode Both -Label attack_both_run1 -DurationSeconds 600 -SampleIntervalSeconds 1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_attack_workload.ps1 -Mode Both -Label attack_both_run2 -DurationSeconds 600 -SampleIntervalSeconds 1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_attack_workload.ps1 -Mode Both -Label attack_both_run3 -DurationSeconds 600 -SampleIntervalSeconds 1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_attack_workload.ps1 -Mode Both -Label attack_both_run4 -DurationSeconds 600 -SampleIntervalSeconds 1
```

Ghi số liệu từ phần Summary:

- SystemCpuAvgPercent
- AvailableMemoryAvgMB
- DiskBytesPerSecAvg
- PythonCpuAvgPercent
- PythonPrivateMemoryAvgMB
- AgentConsoleCpuAvgPercent
- AgentConsolePrivateMemoryAvgMB

Sau mỗi run, kiểm tra thêm log:

```powershell
Get-Content .\PythonAgent\logs\edr_events.jsonl -Tail 20
```

## 8. Lưu ý khi dùng Atomic cho đo hiệu năng

- Dùng cùng `selected_atomic_tests.json` giữa các lần đo.
- Không đổi danh sách Atomic test giữa run1-run4.
- Nên để response tắt khi đo attack workload; response đo riêng ở kịch bản response.
- Nếu Atomic chạy lâu hơn `DurationSeconds`, tăng `DurationSeconds` lên 900 giây.
- Nếu antivirus xóa payload trong `C:\AtomicRedTeam`, kết quả Atomic có thể bị thiếu. Cần ghi chú trong báo cáo.
- Nếu chỉ cần đánh giá telemetry đáng nghi ổn định và lặp lại, dùng `Mode Synthetic`.
- Nếu cần chứng minh theo MITRE ATT&CK, dùng thêm `Mode Atomic` hoặc `Mode Both`.

## 9. Nguồn tham khảo

- Atomic Red Team Invoke-AtomicRedTeam Getting Started: https://www.atomicredteam.io/docs/invoke-atomicredteam/getting-started
- Invoke-AtomicRedTeam GitHub: https://github.com/redcanaryco/invoke-atomicredteam

