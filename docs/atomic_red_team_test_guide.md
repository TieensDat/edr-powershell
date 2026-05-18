# Huong dan test PythonAgent voi Atomic Red Team

Tai lieu nay mo ta cach chuan bi mot may Windows moi de chay lai bo test Atomic Red Team cho Mini EDR PowerShell. Muc tieu la danh gia kha nang thu thap telemetry va phan loai hanh vi PowerShell cua PythonAgent.

## 1. Pham vi danh gia

Bo test hien tai khong chay toan bo Atomic Red Team. Project chi chon 12 test phu hop voi pham vi agent:

- PowerShell command execution.
- Encoded command.
- Obfuscation.
- PowerShell download.
- System/process/file discovery.
- Known malicious PowerShell cmdlets.

Ket qua mong doi la agent ghi nhan duoc telemetry, tao log bang chung, va dua ra verdict `ALERT` hoac `TERMINATE` voi hanh vi dang nghi.

## 2. Yeu cau moi truong

May dung de test nen la Windows lab/VM, khong nen la may production.

Yeu cau toi thieu:

- Windows 10/11.
- PowerShell 5.1 va PowerShell 7 (`pwsh`).
- Python 3.10+.
- Git.
- Quyen Administrator cho mot so thao tac cai dat va test.
- Internet de tai PowerShell modules va Atomic Red Team repo.

Kiem tra nhanh:

```powershell
python --version
powershell -NoProfile -Command "$PSVersionTable.PSVersion"
pwsh --version
git --version
```

## 3. Chuan bi project

Clone project ve may test:

```powershell
git clone https://github.com/TieensDat/edr-powershell.git C:\KLTN\mini-edr-powershell
Set-Location C:\KLTN\mini-edr-powershell
```

Cai dependency cho PythonAgent:

```powershell
python -m pip install -r PythonAgent\requirements.txt
```

Kiem tra cac file can co:

```text
PythonAgent\PythonAgent.py
tests\atomic_red_team\selected_atomic_tests.json
tests\atomic_red_team\run_selected_atomic_tests.ps1
```

## 4. Cai Invoke-AtomicRedTeam va AtomicTestHarnesses

Mo PowerShell bang quyen Administrator, sau do chay:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
Install-Module Invoke-AtomicRedTeam -Scope CurrentUser -Force
Install-Module AtomicTestHarnesses -Scope CurrentUser -Force
```

Kiem tra module:

```powershell
Get-Module -ListAvailable Invoke-AtomicRedTeam
Get-Module -ListAvailable AtomicTestHarnesses
```

## 5. Chuan bi Atomic Red Team repo

Script test mac dinh tim Atomic Red Team tai:

```text
C:\AtomicRedTeam\atomics
```

Cach khuyen dung:

```powershell
New-Item -ItemType Directory -Path C:\AtomicRedTeam -Force | Out-Null
git clone https://github.com/redcanaryco/atomic-red-team.git C:\AtomicRedTeam\atomic-red-team
```

Neu repo duoc clone theo cau truc tren, copy hoac tro tham so `-AtomicsPath` ve thu muc `atomics`:

```text
C:\AtomicRedTeam\atomic-red-team\atomics
```

Neu muon dung dung duong dan mac dinh cua script, co the copy thu muc:

```powershell
Copy-Item -Path C:\AtomicRedTeam\atomic-red-team\atomics -Destination C:\AtomicRedTeam\atomics -Recurse -Force
```

## 6. Bat PowerShell Script Block Logging

Event sensor cua agent dua vao Event ID 4104 trong log:

```text
Microsoft-Windows-PowerShell/Operational
```

Bat bang Local Group Policy:

```text
Computer Configuration
-> Administrative Templates
-> Windows Components
-> Windows PowerShell
-> Turn on PowerShell Script Block Logging
-> Enabled
```

Cap nhat policy:

```powershell
gpupdate /force
```

Kiem tra log:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 5
```

Neu may khong co Group Policy Editor, co the bat bang registry trong PowerShell Administrator:

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force | Out-Null
```

## 7. Chay PythonAgent

Tu thu muc project:

```powershell
Set-Location C:\KLTN\mini-edr-powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start_python_agent.ps1 -Force
```

Kiem tra health:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:9001/health
```

Ket qua can co:

```text
status = running
eventlog_4104_sensor = True
process_sensor = True
file_sensor = True
```

Neu `eventlog_4104_sensor = False`, can kiem tra lai `pywin32` va quyen doc Windows Event Log.

## 8. Chay bo 12 Atomic tests

Tu thu muc project, chay:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass `
  -File .\tests\atomic_red_team\run_selected_atomic_tests.ps1 `
  -AtomicsPath "C:\AtomicRedTeam\atomics" `
  -SelectedTestsPath ".\tests\atomic_red_team\selected_atomic_tests.json" `
  -ReportPath ".\tests\atomic_red_team\selected_atomic_report.json" `
  -TimeoutSeconds 45 `
  -SettleSeconds 6
```

Neu Atomic Red Team nam o duong dan khac, doi `-AtomicsPath`, vi du:

```powershell
-AtomicsPath "C:\AtomicRedTeam\atomic-red-team\atomics"
```

## 9. Truong hop T1059.001-18

Test `T1059.001-18 - PowerShell Invoke Known Malicious Cmdlets` co the can quyen Administrator va module `AtomicTestHarnesses`. Neu report chinh bao skipped prereq cho test nay, hay chay rieng trong PowerShell Administrator:

```powershell
Set-Location C:\KLTN\mini-edr-powershell

@(
  [pscustomobject]@{
    technique = "T1059.001"
    test_number = "18"
    name = "PowerShell Invoke Known Malicious Cmdlets"
  }
) | ConvertTo-Json -Depth 4 | Set-Content -Path .\tests\atomic_red_team\selected_atomic_T1059_001_18.json -Encoding UTF8

pwsh -NoProfile -ExecutionPolicy Bypass `
  -File .\tests\atomic_red_team\run_selected_atomic_tests.ps1 `
  -AtomicsPath "C:\AtomicRedTeam\atomics" `
  -SelectedTestsPath ".\tests\atomic_red_team\selected_atomic_T1059_001_18.json" `
  -ReportPath ".\tests\atomic_red_team\selected_atomic_T1059_001_18_report.json" `
  -TimeoutSeconds 45 `
  -SettleSeconds 6
```

## 10. Doc ket qua

Report chinh:

```text
tests\atomic_red_team\selected_atomic_report.json
```

Report rieng cho T1059.001-18 neu co:

```text
tests\atomic_red_team\selected_atomic_T1059_001_18_report.json
```

Log bang chung cua PythonAgent:

```text
PythonAgent\logs\edr_events.jsonl
PythonAgent\logs\edr_features_g296.csv
```

Kiem tra tong quan:

```powershell
Get-Content .\tests\atomic_red_team\selected_atomic_report.json -Raw | ConvertFrom-Json |
  Select-Object total_selected, executed, skipped_prereq, errors, executed_with_telemetry, telemetry_success_rate_percent
```

Kiem tra tung test:

```powershell
$r = Get-Content .\tests\atomic_red_team\selected_atomic_report.json -Raw | ConvertFrom-Json
$r.results | Select-Object id, status, passed, observed_event_count, observed_max_verdict
```

## 11. Baseline mong doi

Ket qua gan nhat cua project:

| Chi so | Gia tri mong doi |
|---|---:|
| Tong so test | 12 |
| So test co telemetry | 12 |
| Ti le telemetry | 100% |
| Verdict thap nhat chap nhan | `ALERT` voi hanh vi dang nghi |
| Test co the can chay rieng | `T1059.001-18` |

Danh sach 12 test:

| Atomic ID | Noi dung |
|---|---|
| T1059.001-13 | PowerShell command parameter variations |
| T1059.001-15 | PowerShell encoded command parameter variations |
| T1059.001-17 | PowerShell command execution |
| T1059.001-18 | PowerShell known malicious cmdlets |
| T1027-2 | Base64-encoded PowerShell |
| T1027-7 | Obfuscated PowerShell command |
| T1027-11 | Obfuscated command via character array |
| T1105-10 | PowerShell download |
| T1105-15 | File download via PowerShell |
| T1082-37 | System locale and regional discovery |
| T1057-3 | Process discovery with Get-Process |
| T1083-2 | File and directory discovery |

## 12. Loi thuong gap

| Loi | Nguyen nhan co the | Cach xu ly |
|---|---|---|
| `agent_health_ok = false` | PythonAgent chua chay | Chay `scripts\start_python_agent.ps1`, kiem tra `/health` |
| `eventlog_4104_sensor = false` | Thieu `pywin32` hoac loi doc Event Log | Chay `pip install -r PythonAgent\requirements.txt`, mo PowerShell Admin |
| Test bi `SKIPPED_PREREQ` | Thieu module/prereq cua Atomic | Chay lai PowerShell Admin, cai `AtomicTestHarnesses`, kiem tra prereq |
| Khong co 4104 | Script Block Logging chua bat | Bat policy/registry va `gpupdate /force` |
| `Invoke-AtomicTest` khong tim thay | Chua cai module | `Install-Module Invoke-AtomicRedTeam -Scope CurrentUser -Force` |
| `AtomicsPath` khong ton tai | Sai duong dan repo Atomic | Doi tham so `-AtomicsPath` |

## 13. Don dep sau khi test

Dung PythonAgent:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\stop_python_agent.ps1
```

Neu can xoa log runtime de chay lai tu dau:

```powershell
Remove-Item .\PythonAgent\logs\edr_events.jsonl -Force -ErrorAction SilentlyContinue
Remove-Item .\PythonAgent\logs\edr_features_g296.csv -Force -ErrorAction SilentlyContinue
```

## 14. Cach viet ket luan vao bao cao

Neu ket qua dat 12/12 telemetry, co the ghi:

```text
Trong bo 12 Atomic Red Team tests duoc chon, PythonAgent ghi nhan duoc telemetry cho 12/12 truong hop. Ket qua nay cho thay agent co kha nang quan sat cac hanh vi PowerShell dang nghi gom encoded command, obfuscation, download va discovery thong qua process sensor va Event Log 4104 sensor. Cac verdict `ALERT` va `TERMINATE` duoc sinh ra dua tren rule-based detection, feature extraction G2.96 va ML model neu duoc kich hoat.
```

Can neu ro gioi han:

```text
Ket qua nay chi danh gia tap Atomic tests co chon loc trong moi truong lab, chua thay the cho danh gia EDR production ve self-protection, overhead, tamper resistance va false positive tren tap du lieu lon.
```
