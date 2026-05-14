# Kien truc PythonAgent: telemetry -> feature extraction -> detection -> response

Tai lieu nay mo ta luong xu ly chinh cua `PythonAgent` trong he thong Mini EDR PowerShell. Pham vi tap trung vao pipeline runtime: thu thap telemetry, trich xuat dac trung, phan loai hanh vi va response.

## 1. Muc tieu thiet ke

`PythonAgent` dong vai tro la trung tam phan tich cua he thong. Agent nhan telemetry tu nhieu nguon, chuan hoa ve mot event format, trich xuat dac trung G2.96, ket hop rule-based detection va ML model, sau do dua ra verdict cuoi cung. Khi response duoc bat bang `EDR_ENABLE_RESPONSE=1`, agent chi thuc hien response voi event co `final_verdict = TERMINATE`.

Muc tieu cua thiet ke hien tai:

- Tap trung vao hanh vi PowerShell va script interpreter tren Windows.
- Ho tro nhieu nguon telemetry: AMSI bridge, process command line, file script, Event Log 4104.
- Giu response o che do opt-in de an toan trong moi truong lab.
- Ghi log day du bang chung de phuc vu chuong thuc nghiem va dieu tra.

## 2. Luong tong the

```text
Telemetry Sources
   |
   |-- C++ AMSI Bridge Agent -> POST /telemetry
   |-- Process Sensor        -> process command line
   |-- File Sensor           -> script file content
   |-- Event Log 4104 Sensor -> PowerShell ScriptBlockText
   |
   v
Normalize Event
   |
   v
Noise Filter + Dedup
   |
   v
Feature Extraction G2.96
   |
   v
Detection
   |-- Data analysis / risk score
   |-- Rule-based baseline
   |-- Optional Random Forest ML model
   |
   v
Verdict Combination
   |
   v
Response Engine
   |-- disabled by default
   |-- only acts on TERMINATE
   |-- source-aware action
   |
   v
Evidence Logs
   |-- PythonAgent/logs/edr_events.jsonl
   |-- PythonAgent/logs/edr_features_g296.csv
   |-- PythonAgent/logs/quarantine_index.jsonl
   |-- PythonAgent/quarantine/
```

## 3. Nguon telemetry

### 3.1. AMSI Bridge telemetry

Nguon `amsi_cpp_bridge` den tu C++ Native Bridge Agent thong qua HTTP endpoint:

```text
POST http://127.0.0.1:9001/telemetry
```

Nguon nay phu hop de bat noi dung script PowerShell o tang AMSI. PythonAgent tra ve verdict cho C++ Agent. Neu verdict la `TERMINATE`, viec kill process duoc giao cho C++ Agent vi C++ Agent nam gan nguon AMSI va co PID runtime ro hon.

### 3.2. Process Sensor

Nguon `process_sensor` dung `psutil` de theo doi tien trinh moi. Sensor tap trung vao cac process co nguy co cao:

- `powershell.exe`, `pwsh.exe`, `powershell_ise.exe`
- `wscript.exe`, `cscript.exe`, `mshta.exe`
- `rundll32.exe`, `regsvr32.exe`, `reg.exe`, `schtasks.exe`

Telemetry chinh gom process name, PID, PPID, parent process, executable path va command line. Sensor nay phu hop de phat hien encoded command, bypass execution policy, hidden window, downloader command va cac chuoi lenh dang nghi tren command line.

### 3.3. File Sensor

Nguon `file_sensor` dung `watchdog` de theo doi script file trong cac thu muc nguoi dung. Mac dinh watch:

- `%USERPROFILE%\Desktop`
- `%USERPROFILE%\Downloads`
- `%USERPROFILE%\Documents`
- `%USERPROFILE%\OneDrive\Documents`
- `%USERPROFILE%\OneDrive\Desktop`

Co the tuy bien bang bien moi truong:

```powershell
$env:EDR_WATCH_PATHS = "C:\Path1;C:\Path2"
```

Sensor doc noi dung cac file script co extension:

```text
.ps1, .psm1, .psd1, .js, .jse, .vbs, .vbe, .wsf, .hta, .bat, .cmd
```

File Sensor co retry/stable read de giam loi doc file khi file vua duoc tao hoac dang duoc ghi. Sensor bo qua file qua lon theo nguong `MAX_FILE_READ_BYTES`.

### 3.4. Event Log 4104 Sensor

Nguon `eventlog_4104_sensor` doc log:

```text
Microsoft-Windows-PowerShell/Operational
Event ID 4104
```

Sensor parse XML event de lay `ScriptBlockText`, `RecordID`, `Path`, `MessageNumber`, `MessageTotal`, thoi gian va computer name. Nguon nay phu hop de bat noi dung script block ma command line khong the hien day du.

Gioi han quan trong: Event Log 4104 khong luon cung cap PID dang tin cay cho hanh dong runtime. Vi vay response doi voi nguon nay la `LOG_ONLY`.

## 4. Chuan hoa event

Moi telemetry duoc chuan hoa ve event co cac truong chinh:

| Truong | Y nghia |
|---|---|
| `source` | Nguon telemetry: `process_sensor`, `file_sensor`, `eventlog_4104_sensor`, `amsi_cpp_bridge` |
| `pid`, `ppid` | Process ID va parent process ID neu co |
| `process` | Ten process lien quan |
| `parent_process` | Ten process cha neu thu thap duoc |
| `path` | Duong dan file/script neu co |
| `script` | Noi dung can phan tich: command line, file content hoac ScriptBlockText |
| `local_verdict` | Verdict tu thanh phan truoc do, vi du C++ Agent |

Truoc khi phan tich, agent thuc hien:

- Bo qua telemetry rong.
- Bo qua noise ro rang nhu lenh health check, module manifest, `clear-host`, `get-history`.
- Tinh `sha256` tren script.
- Dedup theo hash de giam log trung lap.

## 5. Feature Extraction G2.96

Ham `extract_features_g296()` trich xuat dac trung tu noi dung `script`. Nhom dac trung chinh:

| Nhom dac trung | Vi du |
|---|---|
| Raw/statistical | do dai, so dong, entropy, ti le khoang trang, ti le ky tu dac biet |
| Payload | base64, hex string, PE header, URL, IP, domain, exe download |
| Variable | so bien, do dai bien, entropy bien, bien co ve random |
| Benign indicators | comment/help, function, try/catch, pester, module install, whitelisted download |
| Obfuscation | encoded command, frombase64string, replace/join/xor, char cast, hidden window |
| Behavior | IEX, web request, WebClient, registry, schtasks, Defender modification, persistence, LOLBin |
| Chain features | download-execute chain, decode-execute chain |

Ket qua feature duoc ghi vao event va co the append vao:

```text
PythonAgent/logs/edr_features_g296.csv
```

Neu ML model duoc su dung, agent tao DataFrame theo dung thu tu cot trong:

```text
PythonAgent/model/feature_columns.pkl
```

## 6. Detection

Detection hien tai gom ba lop: data analysis, rule-based baseline va ML plugin.

### 6.1. Data analysis / risk score

`analyze_features()` tinh:

- `raw_risk_score`
- `benign_score`
- `risk_score`
- `risk_level`: `LOW`, `MEDIUM`, `HIGH`
- `reasons`: danh sach ly do de giai thich verdict

Risk score khong tu dong kill process. No la mot tin hieu dau vao cho verdict combination.

### 6.2. Rule-based baseline

`rule_analyze()` dua ra:

- `TERMINATE` voi cac chi bao nguy hiem cao nhu credential dumping keyword, `mimikatz`, `sekurlsa`, `logonpasswords`, hoac risk cuc cao kem memory injection/AMSI bypass.
- `ALERT` voi cac hanh vi dang nghi nhu EncodedCommand, IEX, downloader, Base64, ExecutionPolicy bypass, hidden window, persistence, registry write, certutil, BitsTransfer.
- `ALLOW` khi khong co chi bao dang ke.

Rule baseline giup he thong co kha nang phat hien ngay ca khi ML model chua duoc load.

### 6.3. ML plugin

ML la thanh phan tuy chon. Khi co du 2 file:

```text
PythonAgent/model/random_forest_model.pkl
PythonAgent/model/feature_columns.pkl
```

agent load model bang `joblib` va predict tren feature vector. Output gom:

- `ml_enabled`
- `ml_verdict`: `BENIGN`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN`
- `ml_confidence`

Neu model loi version, thieu dependency hoac thieu file cot feature, agent van chay duoc voi rule baseline.

## 7. Verdict combination

`combine_verdict()` tong hop:

```text
cpp_verdict + rule_verdict + ml_verdict + ml_confidence + risk_level
```

Quy tac chinh:

- Neu C++ verdict hoac rule verdict la `TERMINATE` -> final la `TERMINATE`.
- Neu ML la `MALICIOUS` voi confidence cao va co rule/cpp alert hoac risk high -> co the nang len `TERMINATE`.
- Neu C++/rule la `ALERT` -> final la `ALERT`.
- Neu ML la `MALICIOUS`/`SUSPICIOUS` nhung chua du nguong terminate -> `ALERT`.
- Neu risk high -> `ALERT`.
- Con lai -> `ALLOW`.

Ket qua cuoi cung duoc luu trong truong:

```text
final_verdict
```

## 8. Response Engine

Response duoc thiet ke theo huong an toan cho lab:

- Mac dinh tat.
- Chi bat khi co bien moi truong `EDR_ENABLE_RESPONSE=1`.
- Chi xu ly event co `final_verdict = TERMINATE`.
- Phan biet action theo `source`.
- Co protected process/command line de giam nguy co kill nham.
- Co quarantine va index log de truy vet.

### 8.1. Chinh sach response theo source

| Source | Action | Ly do |
|---|---|---|
| `process_sensor` | `TERMINATE_PROCESS` | Co PID truc tiep tu process telemetry |
| `file_sensor` | `QUARANTINE_FILE` | Co duong dan file va nam trong watch scope |
| `eventlog_4104_sensor` | `LOG_ONLY` | Event 4104 khong co PID runtime dang tin cay |
| `amsi_cpp_bridge` | `DELEGATED_TO_CPP_AGENT` | C++ Agent gan nguon AMSI va xu ly PID tot hon |
| source khac | `UNSUPPORTED_SOURCE` | Khong du ngu canh de response |

### 8.2. Protected list

Process response co cac lop bao ve:

- Khong terminate PID cua chinh PythonAgent.
- Khong terminate process he thong quan trong nhu `system`, `csrss.exe`, `wininit.exe`, `winlogon.exe`, `services.exe`, `lsass.exe`, `svchost.exe`, `explorer.exe`.
- Khong terminate command line chua cac script quan ly agent nhu `PythonAgent.py`, `start_python_agent.ps1`, `stop_python_agent.ps1`, `status_python_agent.ps1`, `run_response_tests.ps1`.

Neu gap protected case, agent ghi response failure co ly do ro rang thay vi im lang bo qua.

### 8.3. Quarantine

File quarantine chi ap dung cho file:

- Co `path` hop le.
- Ton tai tren disk.
- Nam trong watch scope cua File Sensor.

File duoc move vao:

```text
PythonAgent/quarantine/
```

Index bang chung duoc ghi vao:

```text
PythonAgent/logs/quarantine_index.jsonl
```

Truong bang chung gom original path, quarantine path, hash, source, final verdict, response action, timestamp. Neu cung mot path da duoc quarantine truoc do, agent tra ve `already_quarantined` de dam bao tinh idempotent.

## 9. Log bang chung

Log chinh cua agent:

```text
PythonAgent/logs/edr_events.jsonl
```

Moi event sau khi xu ly co cac nhom truong:

| Nhom | Truong tieu bieu |
|---|---|
| Telemetry | `source`, `pid`, `process`, `path`, `script`, `sha256` |
| Feature | `features` |
| Detection | `data_analysis`, `rule_verdict`, `ml_verdict`, `ml_confidence`, `final_verdict` |
| Response | `response_enabled`, `response_action`, `response_success`, `response_reason`, `quarantine_path` |

CSV feature:

```text
PythonAgent/logs/edr_features_g296.csv
```

Quarantine index:

```text
PythonAgent/logs/quarantine_index.jsonl
```

## 10. Trang thai kiem thu hien tai

Cac nhom kiem thu da duoc xay dung de danh gia tung phan:

| Hang muc | Report |
|---|---|
| File Sensor | `tests/file_sensor/file_sensor_report.json` |
| Process Sensor | `tests/process_sensor/process_sensor_report.json` |
| Event Log 4104 Sensor | `tests/event_sensor/event_sensor_report.json` |
| ML model | `tests/ml_model/ml_model_report.json` |
| Atomic Red Team | `tests/atomic_red_team/atomic_experiment_summary.md` |
| Response Engine | `tests/response/response_report.json` |

Ket qua response gan nhat:

```text
Total: 15
Passed: 15
Failed: 0
Success rate: 100%
```

Bo response test bao gom terminate process, quarantine file, khong can thiep voi `ALERT`/`ALLOW`, log-only cho Event Log 4104, delegate cho AMSI bridge, protected command line, self PID, missing PID/path, outside watch path, idempotent quarantine va health check sau response.

## 11. Cach chay agent va kiem tra nhanh

Chay agent khong response:

```powershell
cd PythonAgent
python PythonAgent.py
```

Chay agent co response:

```powershell
cd PythonAgent
$env:EDR_ENABLE_RESPONSE = "1"
python PythonAgent.py
```

Kiem tra health:

```powershell
Invoke-RestMethod http://127.0.0.1:9001/health
```

Chay response test:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\response\run_response_tests.ps1
```

## 12. Gioi han can neu trong khoa luan

He thong hien tai phu hop voi muc tieu proof-of-concept cho khoa luan, nhung can neu ro cac gioi han:

- Response chua phai production-grade.
- Event Log 4104 chi log-only vi khong co PID runtime dang tin cay.
- Quarantine chi ap dung voi file nam trong watch scope.
- Protected list moi o muc co ban.
- Chua co self-defense, tamper protection, service hardening.
- Chua co benchmark hieu nang dai han tren moi truong production.
- ML model phu thuoc chat luong dataset, feature columns va version moi truong train/runtime.

## 13. Ket luan kien truc

Pipeline hien tai da di dung huong voi de tai Mini EDR PowerShell: co telemetry da nguon, feature extraction co cau truc, detection ket hop rule va ML, verdict co giai thich, response that o muc lab va log bang chung ro rang. Kien truc nay du de lam nen tang cho chuong thiet ke he thong va chuong thuc nghiem cua khoa luan tot nghiep.
