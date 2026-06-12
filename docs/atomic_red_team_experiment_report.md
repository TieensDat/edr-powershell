# Bao cao kich ban 1: Test PythonAgent voi Atomic Red Team

**Sinh vien thuc hien:** Dang Tien Dat (22162010) & Vu Dinh Khang (22162015)  
**Nganh / Chuyen nganh:** An toan thong tin  
**Ten de tai:** Xay dung he thong phat hien va tu dong ngan chan ma doc PowerShell dua tren phan tich hanh vi trong moi truong Windows  
**Giang vien huong dan:** ThS. Nguyen Dang Quang  
**Loai bao cao:** Bao cao kich ban thuc nghiem  
**Kich ban thuc nghiem:** Kiem thu PythonAgent voi Atomic Red Team  
**Moi truong thuc hien:** Windows lab / may ao kiem thu  
**Thoi diem thuc hien:** Thang 05/2026

**Muc dich bao cao:**  
Bao cao nay trinh bay qua trinh kiem thu PythonAgent bang Atomic Red Team, bao gom muc tieu thuc nghiem, moi truong trien khai, cac buoc chay test, bang chung demo va ket qua thu duoc. Noi dung duoc dung lam minh chung cho phan thuc nghiem cua khoa luan tot nghiep.

## 1. Muc tieu thuc nghiem

Kich ban nay su dung Atomic Red Team de danh gia kha nang thu thap telemetry va phan loai hanh vi PowerShell dang nghi cua PythonAgent. Day la nhom test tan cong chuan hoa, duoc xay dung dua tren MITRE ATT&CK, dung de kiem tra agent trong moi truong lab.

Muc tieu chinh:

- Kiem tra agent co thu thap duoc telemetry khi PowerShell thuc thi cac hanh vi dang nghi hay khong.
- Danh gia cac nguon telemetry gom `process_sensor` va `eventlog_4104_sensor`.
- Kiem tra module phan tich co sinh verdict `ALERT` hoac `TERMINATE` voi cac hanh vi rui ro hay khong.
- Tao bang chung thuc nghiem cho chuong danh gia cua khoa luan.

Pham vi thuc nghiem nay tap trung vao telemetry va detection. Response khong phai muc tieu chinh cua kich ban Atomic Red Team.

## 2. Moi truong thuc nghiem

| Thanh phan | Gia tri |
|---|---|
| Project | `C:\KLTN\mini-edr-powershell` |
| Agent endpoint | `http://127.0.0.1:9001` |
| Atomic tests | `tests\atomic_red_team\selected_atomic_tests.json` |
| Atomic repo | `C:\AtomicRedTeam\atomics` |
| Report chinh | `tests\atomic_red_team\selected_atomic_report.json` |
| Report rieng cho T1059.001-18 | `tests\atomic_red_team\selected_atomic_T1059_001_18_report.json` |
| Log telemetry | `PythonAgent\logs\edr_events.jsonl` |
| ML model | Enabled |

Cac module/cau hinh can co:

- PowerShell 7 (`pwsh`).
- `Invoke-AtomicRedTeam`.
- `AtomicTestHarnesses`.
- PowerShell Script Block Logging bat Event ID 4104.
- PythonAgent dang chay va endpoint `/health` tra ve `running`.

## 3. Danh sach Atomic tests

Bo test gom 12 test PowerShell duoc chon theo muc tieu cua de tai:

| Atomic ID | Nhom hanh vi | Noi dung |
|---|---|---|
| T1059.001-13 | Command execution | PowerShell command parameter variations |
| T1059.001-15 | Encoded command | PowerShell encoded command parameter variations |
| T1059.001-17 | Command execution | PowerShell command execution |
| T1059.001-18 | Known malicious cmdlets | Invoke known malicious PowerShell cmdlets |
| T1027-2 | Obfuscation | Base64-encoded PowerShell |
| T1027-7 | Obfuscation | Obfuscated PowerShell command |
| T1027-11 | Obfuscation | Obfuscated command via character array |
| T1105-10 | Download | PowerShell download |
| T1105-15 | Download | File download via PowerShell |
| T1082-37 | Discovery | System locale and regional settings |
| T1057-3 | Discovery | Process discovery with Get-Process |
| T1083-2 | Discovery | File and directory discovery |

## 4. Quy trinh test

Quy trinh thuc nghiem duoc thuc hien theo cac buoc:

1. Khoi dong PythonAgent.
2. Kiem tra trang thai agent qua endpoint `/health`.
3. Chay script `run_selected_atomic_tests.ps1`.
4. Script doc danh sach test tu `selected_atomic_tests.json`.
5. Script goi Invoke-AtomicRedTeam de thuc thi tung Atomic test.
6. Sau moi test, script cho agent thu telemetry trong vai giay.
7. Script doc `PythonAgent\logs\edr_events.jsonl`.
8. Script tong hop so event, source, rule verdict, ML verdict va final verdict.
9. Ket qua duoc ghi vao file report JSON.

Lenh chay report chinh:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass `
  -File .\tests\atomic_red_team\run_selected_atomic_tests.ps1 `
  -AtomicsPath "C:\AtomicRedTeam\atomics" `
  -SelectedTestsPath ".\tests\atomic_red_team\selected_atomic_tests.json" `
  -ReportPath ".\tests\atomic_red_team\selected_atomic_report.json" `
  -TimeoutSeconds 45 `
  -SettleSeconds 6
```

Ghi chu: `T1059.001-18` can quyen Administrator nen duoc chay rieng bang PowerShell Administrator. Ket qua cuoi cung cua 12 test duoc tong hop tu report chinh va report rieng cua test nay.

## 5. Cac buoc thuc hien test, cau lenh su dung va hinh anh chung minh

Phan nay mo ta cac buoc co the thuc hien khi demo truc tiep hoac khi chay lai thuc nghiem Atomic Red Team tren may lab. Muc tieu la chung minh duoc luong: Atomic Red Team thuc thi hanh vi PowerShell, PythonAgent thu thap telemetry, phan tich hanh vi va ghi ket qua ra report.

### 5.1. Buoc 1: Mo PowerShell tai thu muc project

```powershell
cd C:\KLTN\mini-edr-powershell
```

Hinh anh can chup: Terminal dang dung tai thu muc `C:\KLTN\mini-edr-powershell`.

### 5.2. Buoc 2: Khoi dong PythonAgent

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start_python_agent.ps1 -Force
```

Kiem tra trang thai agent:

```powershell
Invoke-RestMethod http://127.0.0.1:9001/health
```

Ket qua mong doi:

- `status = running`
- `ml_enabled = true`
- `process_sensor = true`
- `eventlog_4104_sensor = true`

Hinh anh can chup: Ket qua `/health` cho thay PythonAgent dang chay va cac sensor can thiet da duoc bat.

### 5.3. Buoc 3: Xoa log/report demo cu

```powershell
Remove-Item .\PythonAgent\logs\edr_events.jsonl -Force -ErrorAction SilentlyContinue
Remove-Item .\PythonAgent\logs\edr_features_g296.csv -Force -ErrorAction SilentlyContinue
Remove-Item .\tests\atomic_red_team\demo_atomic_report.json -Force -ErrorAction SilentlyContinue
```

Buoc nay giup ket qua demo khong bi lan voi lan chay truoc.

### 5.4. Buoc 4: Tao file danh sach Atomic tests dung cho demo

Tao file:

```text
tests\atomic_red_team\demo_atomic_tests.json
```

Noi dung file:

```json
[
  {
    "technique": "T1027",
    "test_number": "2",
    "name": "Execute base64-encoded PowerShell"
  },
  {
    "technique": "T1027",
    "test_number": "11",
    "name": "Obfuscated PowerShell Command via Character Array"
  },
  {
    "technique": "T1105",
    "test_number": "15",
    "name": "File Download via PowerShell"
  }
]
```

Neu muon tao bang lenh PowerShell:

```powershell
@(
  [pscustomobject]@{
    technique = "T1027"
    test_number = "2"
    name = "Execute base64-encoded PowerShell"
  },
  [pscustomobject]@{
    technique = "T1027"
    test_number = "11"
    name = "Obfuscated PowerShell Command via Character Array"
  },
  [pscustomobject]@{
    technique = "T1105"
    test_number = "15"
    name = "File Download via PowerShell"
  }
) | ConvertTo-Json -Depth 4 | Set-Content .\tests\atomic_red_team\demo_atomic_tests.json -Encoding UTF8
```

Hinh anh can chup: File `demo_atomic_tests.json` hien thi danh sach Atomic tests duoc chon de demo.

### 5.5. Buoc 5: Chay Atomic Red Team test

Neu Atomic Red Team dat tai `C:\AtomicRedTeam\atomics`, chay:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass `
  -File .\tests\atomic_red_team\run_selected_atomic_tests.ps1 `
  -AtomicsPath "C:\AtomicRedTeam\atomics" `
  -SelectedTestsPath ".\tests\atomic_red_team\demo_atomic_tests.json" `
  -ReportPath ".\tests\atomic_red_team\demo_atomic_report.json" `
  -TimeoutSeconds 45 `
  -SettleSeconds 6
```

Neu Atomic Red Team nam trong thu muc clone repo, vi du `C:\AtomicRedTeam\atomic-red-team\atomics`, thay tham so `-AtomicsPath`:

```powershell
-AtomicsPath "C:\AtomicRedTeam\atomic-red-team\atomics"
```

Ket qua mong doi tren terminal:

- `Selected` bang so test trong file demo.
- `Executed` bang so test da chay.
- `Executed with telemetry` lon hon 0.
- `Telemetry success rate` dat 100% neu toan bo test deu co telemetry.
- Report duoc ghi vao `tests\atomic_red_team\demo_atomic_report.json`.

Hinh anh can chup: Terminal hien thi ket qua chay Atomic Red Team, gom so test duoc chon, so test da chay, so test co telemetry va telemetry success rate.

### 5.6. Buoc 6: Doc ket qua tong hop tu report JSON

```powershell
$r = Get-Content .\tests\atomic_red_team\demo_atomic_report.json -Raw | ConvertFrom-Json
$r | Select-Object total_selected, executed, skipped_prereq, errors, executed_with_telemetry, telemetry_success_rate_percent
```

Xem ket qua tung test:

```powershell
$r.results | Select-Object id, status, observed_event_count, observed_sources, observed_max_verdict
```

Ket qua mong doi:

- `observed_event_count > 0`
- `observed_sources` co `process_sensor` hoac `eventlog_4104_sensor`
- `observed_max_verdict` la `ALERT` hoac `TERMINATE`

Hinh anh can chup: Ket qua doc `demo_atomic_report.json`, the hien tung Atomic ID, so event quan sat duoc, source ghi nhan va max verdict.

### 5.7. Buoc 7: Kiem tra telemetry log cua PythonAgent

```powershell
Get-Content .\PythonAgent\logs\edr_events.jsonl -Tail 5
```

Xem mot event theo dang rut gon:

```powershell
Get-Content .\PythonAgent\logs\edr_events.jsonl -Tail 1 | ConvertFrom-Json |
  Select-Object source, process, rule_verdict, ml_enabled, ml_verdict, final_verdict
```

Hinh anh can chup: Log `edr_events.jsonl` the hien `source`, `rule_verdict`, `ml_verdict` va `final_verdict` cua event duoc PythonAgent ghi nhan.

### 5.8. Buoc 8: Dung PythonAgent sau khi demo

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\stop_python_agent.ps1
```

### 5.9. Truong hop chay lai toan bo 12 Atomic tests

Neu can chay lai toan bo 12 test thay vi demo 3 test, su dung file danh sach chinh:

```text
tests\atomic_red_team\selected_atomic_tests.json
```

Lenh chay:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass `
  -File .\tests\atomic_red_team\run_selected_atomic_tests.ps1 `
  -AtomicsPath "C:\AtomicRedTeam\atomics" `
  -SelectedTestsPath ".\tests\atomic_red_team\selected_atomic_tests.json" `
  -ReportPath ".\tests\atomic_red_team\selected_atomic_report.json" `
  -TimeoutSeconds 45 `
  -SettleSeconds 6
```

Ghi chu: `T1059.001-18` co the can chay rieng bang PowerShell Administrator do yeu cau elevation.

### 5.10. Bang chung file sau khi chay test

Can luu lai cac file:

```text
tests\atomic_red_team\demo_atomic_report.json
tests\atomic_red_team\selected_atomic_report.json
tests\atomic_red_team\selected_atomic_T1059_001_18_report.json
PythonAgent\logs\edr_events.jsonl
PythonAgent\logs\edr_features_g296.csv
```

## 6. Ket qua tong hop

Ket qua tong hop sau khi ghep report chinh va report rieng cua `T1059.001-18`:

| Chi so | Ket qua |
|---|---:|
| Tong so Atomic tests | 12 |
| So test da thuc thi | 12 |
| So test co telemetry | 12 |
| Ti le telemetry thanh cong | 100% |
| Tong so event agent ghi nhan | 93 |
| So test co max verdict `TERMINATE` | 6 |
| So test co max verdict `ALERT` | 6 |
| So test co max verdict `ALLOW` | 0 |
| ML enabled trong qua trinh test | Co |

## 7. Ket qua tung test

| Atomic ID | Noi dung kiem tra | Telemetry events | Source ghi nhan | Max verdict |
|---|---|---:|---|---|
| T1059.001-13 | PowerShell command parameter variations | 37 | `process_sensor`, `eventlog_4104_sensor` | TERMINATE |
| T1059.001-15 | PowerShell encoded command parameter variations | 25 | `process_sensor`, `eventlog_4104_sensor` | TERMINATE |
| T1059.001-17 | PowerShell command execution | 2 | `eventlog_4104_sensor` | ALERT |
| T1059.001-18 | Known malicious PowerShell cmdlets | 3 | `eventlog_4104_sensor` | TERMINATE |
| T1027-2 | Base64-encoded PowerShell | 4 | `process_sensor`, `eventlog_4104_sensor` | ALERT |
| T1027-7 | Obfuscated PowerShell command | 3 | `eventlog_4104_sensor` | ALERT |
| T1027-11 | Obfuscated command via character array | 5 | `process_sensor`, `eventlog_4104_sensor` | ALERT |
| T1105-10 | PowerShell download | 3 | `process_sensor`, `eventlog_4104_sensor` | TERMINATE |
| T1105-15 | File download via PowerShell | 2 | `eventlog_4104_sensor` | TERMINATE |
| T1082-37 | System locale and regional discovery | 3 | `process_sensor`, `eventlog_4104_sensor` | TERMINATE |
| T1057-3 | Process discovery with Get-Process | 3 | `process_sensor`, `eventlog_4104_sensor` | ALERT |
| T1083-2 | File and directory discovery | 3 | `process_sensor`, `eventlog_4104_sensor` | ALERT |

## 8. Phan tich ket qua

Ket qua cho thay PythonAgent ghi nhan duoc telemetry tren toan bo 12 Atomic tests duoc chon. Cac test lien quan den PowerShell command line va encoded command duoc ghi nhan boi ca `process_sensor` va `eventlog_4104_sensor`. Cac test ma hanh vi chinh nam trong noi dung script block duoc ghi nhan chu yeu boi `eventlog_4104_sensor`.

Nhom T1059.001-13 va T1059.001-15 tao nhieu bien the command line nen so event cao nhat, lan luot la 37 va 25 event. Day la hai test co gia tri tot de danh gia kha nang quan sat command-line PowerShell va encoded command.

Luu y ve cach hieu so luong event: so event trong report Atomic hien tai la so telemetry tho duoc ghi nhan sau khi chay tung Atomic test, khong phai so lenh doc hai duy nhat. Mot Atomic test co the sinh nhieu event do nhieu nguyen nhan: lenh prereq, module test harness, `process_sensor` ghi nhan command line, `eventlog_4104_sensor` ghi nhan script block, hoac mot noi dung PowerShell bi tach thanh nhieu script block. Vi vay, so event dung de chung minh kha nang quan sat telemetry, khong nen dien giai truc tiep thanh so lan tan cong doc lap.

Vi du, T1059.001-13 khong phai mot lenh PowerShell don gian. Theo dinh nghia Atomic goc, test nay goi module AtomicTestHarnesses:

```text
Out-ATHPowerShellCommandLineParameter
  -CommandLineSwitchType Hyphen
  -CommandParamVariation C
  -UseEncodedArguments
  -EncodedArgumentsParamVariation EA
  -Execute
  -ErrorAction Stop
```

Muc tieu cua test la sinh va thuc thi cac bien the tham so dong lenh PowerShell, vi du cac dang rut gon/bien the cua `-Command`, cach truyen command argument va encoded argument. Do do mot test co the tao nhieu process/script block telemetry, dan toi 37 event duoc ghi nhan boi ca `process_sensor` va `eventlog_4104_sensor`.

Nguoc lai, T1059.001-17 la mot kich ban command execution don le. Atomic YAML mo ta test nay la chay:

```text
powershell.exe -e #{obfuscated_code}
```

Trong do payload mac dinh giai ma ra hanh vi don gian kieu `Invoke-Expression` ket hop `Write-Host "Hello, from PowerShell!"`. Vi chi co mot lan thuc thi chinh va hanh vi ngan, agent ghi nhan 2 event tu `eventlog_4104_sensor`. Su chenh lech 37 event so voi 2 event vi vay phan anh khac biet trong thiet ke test case va nguon telemetry, khong phai do agent xu ly sai hoac bo sot cung mot loai hanh vi.

Nhom T1027 cho thay agent co kha nang phat hien cac hanh vi obfuscation co ban nhu Base64, chuoi bi lam roi va mang ky tu. Cac test nay deu tao verdict `ALERT`, phu hop voi muc do rui ro can canh bao.

Nhom T1105 lien quan den download bi danh gia cao hon, dat max verdict `TERMINATE`. Mot so lenh download co the bi loi do dieu kien mang hoac moi truong, nhung agent van ghi nhan duoc telemetry va phan loai hanh vi dua tren command/script block.

Test T1059.001-18 duoc chay rieng bang quyen Administrator do prereq yeu cau elevation. Agent ghi nhan 3 event tu `eventlog_4104_sensor`, ML duoc kich hoat va max verdict la `TERMINATE`. Ket qua nay phu hop voi baseline vi test goi cac known malicious cmdlets trong PowerShell.

Luu y dien giai test T1082-37: day la kich ban discovery ve locale/regional settings, ban than hanh vi doc locale he thong khong tuong duong voi ma doc. Trong report, T1082-37 co max verdict `TERMINATE` vi event duoc chay trong ngu canh Atomic Red Team, duoc ghi nhan boi ca `process_sensor` va `eventlog_4104_sensor`, rule co event o muc `ALERT` va ML tra ve `MALICIOUS`. Theo logic ket hop verdict hien tai cua PythonAgent, ML `MALICIOUS` voi confidence cao khi di kem rule `ALERT` hoac risk context co the nang final verdict len `TERMINATE`. Vi vay, ket qua nay nen duoc hieu la detection trong ngu canh mo phong tan cong, khong phai ket luan rang moi lenh kiem tra locale deu can bi chan.

Ve mat danh gia khoa hoc, T1082-37 la diem can neu ro nhu mot nguy co false positive hoac chinh sach terminate con nhay voi nhom discovery-only. Voi he thong thuc te, cac hanh vi discovery don le nhu kiem tra locale nen duoc uu tien o muc `ALERT` hoac chi nang len `TERMINATE` khi di kem tin hieu nguy hiem hon nhu `EncodedCommand`, downloader, credential dumping, AMSI bypass, persistence hoac chuoi hanh vi nhieu buoc. Do do, T1082-37 duoc tinh la telemetry/detection pass trong kich ban Atomic Red Team, dong thoi duoc dua vao danh sach can tuning va danh gia them bang tap lenh quan tri benign.

## 9. Nhan xet ve nguon telemetry

| Source | Vai tro trong kich ban Atomic |
|---|---|
| `process_sensor` | Hieu qua voi cac test co command line ro rang nhu encoded command, command parameter, discovery |
| `eventlog_4104_sensor` | Quan trong nhat voi PowerShell vi ghi nhan noi dung script block sau khi PowerShell xu ly |
| `file_sensor` | Khong phai source chinh cua kich ban nay vi Atomic tests chu yeu thuc thi truc tiep qua PowerShell |
| `amsi_cpp_bridge` | Khong phai muc tieu cua kich ban Atomic nay; duoc danh gia rieng o kich ban AMSI end-to-end |

## 10. Ket luan

Trong kich ban test voi Atomic Red Team, PythonAgent dat ket qua phu hop voi muc tieu cua khoa luan:

- Thu thap telemetry thanh cong voi 12/12 Atomic tests.
- Ghi nhan duoc cac hanh vi PowerShell dang nghi gom encoded command, obfuscation, download va discovery.
- Sinh duoc verdict `ALERT` hoac `TERMINATE`, khong co test nao dung o max verdict `ALLOW`.
- Tao duoc report JSON va log bang chung phuc vu chuong thuc nghiem.
- Cho thay Event Log 4104 la nguon telemetry quan trong trong phat hien hanh vi PowerShell.

Ket qua nay co the su dung lam bang chung cho chuong thuc nghiem, nhung can neu ro day la tap test co chon loc trong moi truong lab, chua thay the cho danh gia EDR production-grade.

## 11. Gioi han cua kich ban

- Chi chay 12 Atomic tests phu hop voi pham vi PowerShell cua agent, khong chay toan bo MITRE ATT&CK.
- Mot so Atomic tests co the sinh loi phu thuoc moi truong, vi du network hoac prereq, nhung muc tieu chinh van la telemetry va detection.
- Chua danh gia false positive tren tap benign lon.
- Chua danh gia overhead he thong.
- Chua danh gia kha nang chong tamper/self-protection.
- Chua danh gia response trong kich ban Atomic nay.

## 12. Cau viet ngan de dua vao bao cao

Co the dua doan sau vao bao cao khoa luan:

```text
Kich ban thuc nghiem dau tien su dung Atomic Red Team de danh gia kha nang thu thap telemetry va phan loai hanh vi PowerShell dang nghi cua PythonAgent. Nhom nghien cuu lua chon 12 Atomic tests thuoc cac ky thuat T1059.001, T1027, T1105, T1082, T1057 va T1083. Ket qua cho thay agent ghi nhan duoc telemetry trong 12/12 truong hop, dat ti le 100%. Cac verdict cao nhat duoc sinh ra gom 6 test TERMINATE va 6 test ALERT, khong co test nao dung o muc ALLOW. Dieu nay cho thay module telemetry va detection cua agent co kha nang quan sat va phan loai cac hanh vi PowerShell nhu encoded command, obfuscation, download va discovery trong moi truong lab.
```
