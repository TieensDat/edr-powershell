# Tong hop ket qua thuc nghiem

Tai lieu nay tong hop cac ket qua thuc nghiem hien co cua project Mini EDR PowerShell. Cac so lieu duoc lay tu report trong thu muc `tests/`.

## 1. Bang tong hop chung

| Hang muc | Muc tieu danh gia | Tong test | Dat | Khong dat | Ti le | Bang chung |
|---|---|---:|---:|---:|---:|---|
| File Sensor | Kha nang bat file script tao/sua/di chuyen va bo qua file khong lien quan | 20 | 20 | 0 | 100% | `tests/file_sensor/file_sensor_report.json` |
| Process Sensor | Kha nang bat PowerShell/process command line dang nghi va bo qua process khong lien quan | 20 | 20 | 0 | 100% | `tests/process_sensor/process_sensor_report.json` |
| Event Log 4104 Sensor | Kha nang doc PowerShell Script Block Logging Event ID 4104 | 20 | 20 | 0 | 100% | `tests/event_sensor/event_sensor_report.json` |
| ML Model | Kha nang load model, dong bo feature columns va phan loai malicious sample | 1 | 1 | 0 | 100% | `tests/ml_model/ml_model_report.json` |
| Atomic Red Team | Kha nang thu thap telemetry va phan loai hanh vi PowerShell theo ATT&CK | 12 | 12 | 0 | 100% telemetry | `tests/atomic_red_team/atomic_experiment_summary.md` |
| Response Engine | Kha nang terminate/quarantine/log-only/delegate theo final verdict va source | 15 | 15 | 0 | 100% | `tests/response/response_report.json` |
| AMSI Bridge E2E | Kha nang C++ Agent nhan AMSI-style telemetry, forward Python va terminate process | 1 | 1 | 0 | 100% | `tests/amsi_bridge/amsi_bridge_e2e_report.json` |
| Registered AMSI Provider E2E | Kha nang PowerShell goi AmsiProvider.dll da dang ky, C++ Agent forward Python va terminate process | 1 | 1 | 0 | 100% | `tests/amsi_bridge/registered_amsi_provider_report.json` |

## 2. File Sensor

| Chi so | Ket qua |
|---|---:|
| Run ID | `FSRUN_20260507_203232` |
| Tong test | 20 |
| Passed | 20 |
| Failed | 0 |
| Success rate | 100% |
| Agent health | OK |

Pham vi kiem tra:

- Bat file script duoc tao moi: `.ps1`, `.psm1`, `.psd1`, `.js`, `.vbs`, `.bat`, `.cmd`.
- Bat file script bi sua noi dung.
- Bat su kien move/rename tu file tam sang script extension.
- Xu ly file bi lock tam thoi.
- Bo qua `.txt`, `.log`, `.csv`, file rong va file vuot nguong dung luong.

Ket luan: File Sensor dat yeu cau cho khoa luan ve kha nang thu thap telemetry file script trong thu muc watch.

## 3. Process Sensor

| Chi so | Ket qua |
|---|---:|
| Run ID | `PSRUN_20260507_210632` |
| Tong test | 20 |
| Passed | 20 |
| Failed | 0 |
| Success rate | 100% |
| Agent health | OK |

Pham vi kiem tra:

- Bat `powershell.exe` voi command don gian, `NoProfile`, `ExecutionPolicy Bypass`, `EncodedCommand`, `WindowStyle Hidden`.
- Bat command line dai, quoted command, IEX, Invoke-WebRequest, Start-Process token.
- Bat PowerShell chay bang `-File` va `-Command`.
- Bo qua process khong nam trong pham vi nhu `cmd.exe`, `notepad.exe`, `timeout.exe`.
- Bo qua PowerShell executable khong co command line huu ich.

Ket luan: Process Sensor dat yeu cau ve thu thap command line PowerShell va giam nhieu doi voi process khong lien quan.

## 4. Event Log 4104 Sensor

| Chi so | Ket qua |
|---|---:|
| Run ID | `EVRUN_20260508_145005` |
| Tong test | 20 |
| Passed | 20 |
| Failed | 0 |
| Success rate | 100% |
| Agent health | OK |

Pham vi kiem tra:

- Bat Script Block Logging voi Write-Host, Write-Output, NoProfile, ExecutionPolicy Bypass.
- Bat decoded script block cua EncodedCommand.
- Bat IEX, Invoke-WebRequest, command chain bang semicolon, variable assignment.
- Bat function definition/invocation, script file, multiline script, pipeline, here-string.
- Xac nhan `cmd.exe` va `notepad.exe` khong sinh Event ID 4104.

Ket luan: Event Log 4104 Sensor da dat 20/20. Diem can neu trong bao cao: Event ID 4104 phu thuoc cau hinh Script Block Logging cua Windows va khong cung cap PID runtime dang tin cay cho response truc tiep.

## 5. ML Model

| Chi so | Ket qua |
|---|---:|
| Run ID | `MLRUN_20260508_105924` |
| Test ID | `ML001` |
| Agent ML enabled | True |
| Event found | True |
| ML verdict | `MALICIOUS` |
| ML confidence | 1.0 |
| Rule verdict | `ALERT` |
| Risk level | `HIGH` |
| Final verdict | `TERMINATE` |
| Passed | True |

Ket luan: Agent da load duoc model, dung feature columns runtime va dua ra verdict ML hop le. Ket qua nay chung minh pipeline feature extraction -> ML inference -> verdict combination da hoat dong.

## 6. Atomic Red Team

Ket qua Atomic duoc tong hop tu:

- Report chinh: `tests/atomic_red_team/selected_atomic_report.json`
- Report rieng cho test can Administrator: `tests/atomic_red_team/selected_atomic_T1059_001_18_report.json`
- Bao cao tong hop: `tests/atomic_red_team/atomic_experiment_summary.md`

| Chi so | Ket qua |
|---|---:|
| Tong Atomic test | 12 |
| Thuc thi thanh cong | 12 |
| Co telemetry | 12 |
| Telemetry success rate | 100% |
| Tong event agent ghi nhan | 93 |
| Test co max verdict `TERMINATE` | 6 |
| Test co max verdict `ALERT` | 6 |
| Test co max verdict `ALLOW` | 0 |
| ML enabled trong qua trinh test | True |

### Ket qua tung Atomic test

| Atomic ID | Noi dung | Event | Max verdict |
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

Ket luan: Atomic Red Team cho thay agent co kha nang thu thap telemetry va phan loai cac hanh vi PowerShell lien quan den command execution, encoded command, obfuscation, download va discovery.

## 7. Response Engine

| Chi so | Ket qua |
|---|---:|
| Run ID | `RSRUN_20260509_141332` |
| Response enabled | True |
| Tong test | 15 |
| Passed | 15 |
| Failed | 0 |
| Success rate | 100% |
| Quarantine path | `PythonAgent/quarantine` |

Pham vi kiem tra:

- `process_sensor` + `TERMINATE` -> terminate process.
- `file_sensor` + `TERMINATE` -> quarantine file.
- `ALERT` va `ALLOW` -> khong can thiep pha huy.
- `eventlog_4104_sensor` + `TERMINATE` -> `LOG_ONLY`.
- `amsi_cpp_bridge` + `TERMINATE` -> `DELEGATED_TO_CPP_AGENT`.
- Protected command line, self PID, missing PID/path, outside watch path.
- Idempotent quarantine voi file da bi quarantine.
- Process da thoat truoc khi response.
- Agent van healthy sau response.

Ket luan: Response Engine da dat muc proof-of-concept phu hop cho khoa luan: opt-in, chi xu ly `TERMINATE`, phan biet theo source, co protected list, quarantine va log bang chung.

## 8. AMSI Bridge End-to-End

Da bo sung test harness:

```text
tests/amsi_bridge/run_amsi_bridge_e2e_test.ps1
```

Muc tieu cua test:

- Khoi dong `AgentConsole.exe`.
- Tao process muc tieu `powershell.exe` dang sleep.
- Gui `ScanMessage` dung layout C++ vao Named Pipe `\\.\pipe\EdrAmsiPipe`.
- C++ Agent forward telemetry sang `PythonAgent` qua `/telemetry`.
- PythonAgent tra `final_verdict = TERMINATE`.
- C++ Agent nhan remote verdict `TERMINATE` va terminate process muc tieu.
- Ghi bang chung vao `tests/amsi_bridge/amsi_bridge_e2e_report.json`.

Ket qua hien tai:

```text
Run ID: AMSI_E2E_20260509_150914
Status: EXECUTED
Passed: True
Event source: amsi_cpp_bridge
Event final verdict: TERMINATE
Event response action: DELEGATED_TO_CPP_AGENT
C++ saw Python TERMINATE: True
C++ terminated target process: True
Target alive after: False
```

Lenh da dung de chay:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\amsi_bridge\run_amsi_bridge_e2e_test.ps1 -AgentConsolePath bin\AgentConsole.exe
```

Ket qua nay chung minh duong AMSI bridge o muc E2E qua Named Pipe: AMSI-style telemetry -> C++ Agent -> PythonAgent detection -> verdict `TERMINATE` -> C++ Agent terminate process. Luu y: test nay bom `ScanMessage` truc tiep vao Named Pipe, chua dang ky `AmsiProvider.dll` vao Windows AMSI bang `regsvr32`.

Da chay them test voi `AmsiProvider.dll` da dang ky vao Windows AMSI bang `regsvr32`:

```text
Run ID: AMSI_REAL_20260509_152023
Status: EXECUTED
Passed: True
Event source: amsi_cpp_bridge
Event final verdict: TERMINATE
Event response action: DELEGATED_TO_CPP_AGENT
C++ saw AMSI PID: True
C++ forwarded Python: True
C++ terminated target process: True
Target alive after: False
```

Report bang chung:

```text
tests/amsi_bridge/registered_amsi_provider_report.json
```

Ket qua nay chung minh duong AMSI that: PowerShell -> registered `AmsiProvider.dll` -> Named Pipe -> `AgentConsole.exe` -> `PythonAgent` -> verdict `TERMINATE` -> C++ Agent terminate process.

## 9. Danh gia tong quan

| Tieu chi | Danh gia hien tai |
|---|---|
| Thu thap telemetry tu file/process/event | Dat |
| Phan tich dac trung G2.96 | Dat |
| Rule-based detection baseline | Dat |
| ML inference runtime | Dat o muc test tich hop |
| Atomic Red Team validation | Dat voi tap 12 test da chon |
| Response that | Dat o muc lab/proof-of-concept |
| AMSI Bridge E2E response | Dat voi Named Pipe test va registered AMSI Provider test |
| Bang chung thuc nghiem | Day du report JSON/Markdown |

## 10. Gioi han can neu trong bao cao

- Cac test duoc thuc hien trong moi truong lab, chua thay the benchmark production.
- Atomic Red Team la tap test co chon loc, chua bao phu toan bo MITRE ATT&CK.
- ML model moi duoc test bang case tich hop, can them danh gia dataset neu viet sau ve machine learning.
- Response Engine phu hop lab: chua co self-defense, service hardening, tamper protection.
- Event Log 4104 khong response kill truc tiep vi thieu PID runtime dang tin cay.
- AMSI Bridge E2E hien da dat qua Named Pipe test va registered AMSI Provider test. Van can neu ro day la moi truong lab, co can thiep registry bang `regsvr32`.

## 11. Ket luan

Voi cac ket qua hien tai, project da co bo bang chung thuc nghiem kha day du cho khoa luan: thu thap telemetry dat 20/20 tren tung sensor chinh, ML inference hoat dong, Atomic Red Team dat 12/12 telemetry, va response dat 15/15. He thong co the chuyen sang giai doan viet chuong thuc nghiem, trinh bay kien truc va tong hop danh gia.
