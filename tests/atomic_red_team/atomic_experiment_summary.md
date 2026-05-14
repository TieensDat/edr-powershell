# Bao cao thuc nghiem Atomic Red Team cho PowerShell EDR Agent

## 1. Muc tieu

Thuc nghiem nay dung Atomic Red Team de danh gia kha nang thu thap telemetry va phan loai hanh vi PowerShell dang nghi cua PythonAgent. Pham vi kiem tra tap trung vao hai nguon telemetry chinh cua agent hien tai:

- `process_sensor`: ghi nhan tien trinh va command line PowerShell.
- `eventlog_4104_sensor`: ghi nhan PowerShell Script Block Logging, Event ID 4104.

## 2. Moi truong va du lieu dau vao

- Project: `C:\KLTN\mini-edr-powershell`
- Agent endpoint: `http://127.0.0.1:9001`
- Atomic tests: `tests\atomic_red_team\selected_atomic_tests.json`
- Report chinh: `tests\atomic_red_team\selected_atomic_report.json`
- Report rieng cho test can quyen Administrator: `tests\atomic_red_team\selected_atomic_T1059_001_18_report.json`
- ML model: enabled
- Event log output: `PythonAgent\logs\edr_events.jsonl`

Ghi chu: `T1059.001-18` can quyen Administrator nen duoc chay rieng trong cua so PowerShell Admin. Ket qua tong hop ben duoi duoc ghep tu report chinh va report rieng cua test nay.

## 3. Ket qua tong hop

| Chi so | Ket qua |
|---|---:|
| Tong so atomic test | 12 |
| So test da thuc thi | 12 |
| So test co telemetry | 12 |
| Ti le telemetry thanh cong | 100% |
| Tong so event agent ghi nhan | 93 |
| Test co verdict cao nhat `TERMINATE` | 6 |
| Test co verdict cao nhat `ALERT` | 6 |
| Test co verdict cao nhat `ALLOW` | 0 |

## 4. Ket qua tung test

| Atomic ID | Noi dung kiem tra | Telemetry | Max verdict |
|---|---|---:|---|
| T1059.001-13 | PowerShell command parameter variations | 37 | TERMINATE |
| T1059.001-15 | PowerShell encoded command parameter variations | 25 | TERMINATE |
| T1059.001-17 | PowerShell command execution | 2 | ALERT |
| T1059.001-18 | PowerShell known malicious cmdlets | 3 | TERMINATE |
| T1027-2 | Base64-encoded PowerShell | 4 | ALERT |
| T1027-7 | Obfuscated PowerShell command | 3 | ALERT |
| T1027-11 | Obfuscated command via character array | 5 | ALERT |
| T1105-10 | PowerShell download | 3 | TERMINATE |
| T1105-15 | File download via PowerShell | 2 | TERMINATE |
| T1082-37 | System locale and regional discovery | 3 | TERMINATE |
| T1057-3 | Process discovery with Get-Process | 3 | ALERT |
| T1083-2 | File and directory discovery | 3 | ALERT |

## 5. Nhan xet

Ket qua cho thay agent da thu thap duoc telemetry tren tat ca 12 kich ban Atomic Red Team duoc chon. Cac test lien quan den command line va encoded command duoc ghi nhan boi ca `process_sensor` va `eventlog_4104_sensor`, trong khi mot so test chu yeu duoc nhan dien qua `eventlog_4104_sensor`. Dieu nay phu hop voi dac thu cua PowerShell Script Block Logging, vi nhieu hanh vi nguy hiem nam trong noi dung script block thay vi chi nam tren command line.

Voi `T1059.001-18`, agent ghi nhan 3 event tu `eventlog_4104_sensor`, ML duoc kich hoat va verdict cao nhat la `TERMINATE`. Day la ket qua phu hop voi baseline mong doi vi test nay goi cac known malicious cmdlets trong PowerShell.

## 6. Ket luan

Trong pham vi thuc nghiem Atomic Red Team da chon, PythonAgent dat ket qua phu hop de lam bang chung cho chuong thuc nghiem:

- Thu thap telemetry thanh cong: 12/12 test.
- Phat hien duoc cac hanh vi PowerShell fileless, encoded command, obfuscation, download va discovery.
- ML model duoc kich hoat trong qua trinh test.
- Verdict cua agent khong dung o muc ghi log, ma da phan loai duoc muc do rui ro `ALERT` hoac `TERMINATE`.

Gioi han can neu ro trong bao cao: day la ket qua danh gia theo tap Atomic tests co chon loc, tap trung vao telemetry va detection cho PowerShell. Ket qua nay chua thay the cho danh gia EDR toan dien ve response, self-protection, system overhead va benchmark voi san pham bao mat khac.

## 7. Hinh anh nen chen vao bao cao

Neu can truc quan hoa trong chuong thuc nghiem, nen chup cac hinh sau:

1. **Hinh 4.x - Ket qua chay 11 Atomic tests trong selected report**  
   Noi dung can chup: terminal hien thi `Selected: 12`, `Executed: 11`, `Skipped prereq: 1`, `Executed with telemetry: 11`, `Telemetry success rate: 100%`.

2. **Hinh 4.x - Ket qua chay rieng T1059.001-18 bang PowerShell Admin**  
   Noi dung can chup: terminal hien thi `Selected: 1`, `Executed: 1`, `Skipped prereq: 0`, `Executed with telemetry: 1`, `Telemetry success rate: 100%`.

3. **Hinh 4.x - File report JSON cua T1059.001-18**  
   Noi dung can chup: cac truong `status: EXECUTED`, `observed_event_count: 3`, `observed_sources: eventlog_4104_sensor`, `observed_max_verdict: TERMINATE`.

4. **Hinh 4.x - Mau log agent trong edr_events.jsonl**  
   Noi dung can chup: mot event co `source`, `rule_verdict`, `ml_verdict`, `final_verdict` de chung minh agent da ghi nhan va phan loai telemetry.
