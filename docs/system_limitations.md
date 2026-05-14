# Gioi han cua he thong

He thong Mini EDR PowerShell hien tai da dat muc proof-of-concept phu hop cho pham vi khoa luan tot nghiep. Tuy nhien, he thong van co mot so gioi han quan trong can neu ro khi danh gia ket qua thuc nghiem.

## 1. Response chua phai production-grade

Co che response hien tai duoc thiet ke theo huong an toan cho moi truong lab:

- Mac dinh response bi tat, chi bat khi cau hinh `EDR_ENABLE_RESPONSE=1`.
- Agent chi thuc hien response voi event co `final_verdict = TERMINATE`.
- Response moi bao gom cac hanh dong co ban: terminate process, quarantine file, log-only va delegate cho C++ Agent.
- Protected list moi o muc can thiet de tranh kill nham mot so process/script quan trong.

Do do, response hien tai phu hop de chung minh kha nang phat hien va ngan chan trong moi truong thuc nghiem, nhung chua the xem la production-grade. Mot he thong production can bo sung them:

- Self-defense va tamper protection.
- Service hardening de agent chay on dinh nhu Windows Service.
- Co che rollback/restore quarantine an toan.
- Policy response chi tiet theo user, process, path va muc do rui ro.
- Audit log chong sua doi.
- Benchmark hieu nang va do on dinh dai han.

## 2. Event Log 4104 khong kill truc tiep vi thieu PID tin cay

`eventlog_4104_sensor` doc PowerShell Script Block Logging tu:

```text
Microsoft-Windows-PowerShell/Operational
Event ID 4104
```

Nguon telemetry nay rat huu ich vi no ghi nhan noi dung script block sau khi PowerShell xu ly, dac biet voi cac hanh vi nhu obfuscation, encoded command, downloader hoac discovery. Tuy nhien, Event ID 4104 khong phai luc nao cung cung cap PID runtime dang tin cay de terminate dung process.

Vi ly do an toan, PythonAgent khong kill process truc tiep doi voi event tu `eventlog_4104_sensor`. Khi eventlog co `final_verdict = TERMINATE`, response engine chi ghi nhan:

```text
response_action = LOG_ONLY
response_reason = eventlog_4104_has_no_reliable_pid
```

Day la lua chon co chu dich: uu tien tranh kill nham process hon la ep response khi ngu canh chua du tin cay. Neu muon nang cap trong tuong lai, can co them co che correlation giua Event Log 4104 voi process sensor theo thoi gian, command line, user/session va process tree.

## 3. Quarantine chi ap dung cho file trong watch path

File quarantine hien tai chi thuc hien khi telemetry den tu `file_sensor`, event co `final_verdict = TERMINATE`, va file nam trong watch scope cua agent.

Mac dinh watch path gom:

```text
%USERPROFILE%\Desktop
%USERPROFILE%\Downloads
%USERPROFILE%\Documents
%USERPROFILE%\OneDrive\Documents
%USERPROFILE%\OneDrive\Desktop
```

Neu file nam ngoai watch path, agent khong quarantine va se ghi log:

```text
response_action = QUARANTINE_FILE
response_success = false
response_reason = path_outside_watch_scope
```

Gioi han nay giup response an toan hon trong moi truong lab, vi agent chi di chuyen cac file nam trong pham vi da duoc theo doi. Tuy nhien, trong moi truong production, malware co the nam o nhieu vi tri khac nhu `%TEMP%`, `%APPDATA%`, thu muc startup, network share hoac duong dan he thong. De nang cap, can mo rong policy watch path va bo sung co che allowlist/denylist ro rang.

## 4. Tong ket

Ba gioi han tren khong lam mat gia tri cua ket qua thuc nghiem, vi muc tieu hien tai la xay dung va chung minh mot Mini EDR hoat dong trong moi truong lab. He thong da co telemetry da nguon, feature extraction, rule/ML detection, response co kiem soat va bang chung test. Tuy nhien, khi trinh bay trong khoa luan, can neu ro rang rang response hien tai la proof-of-concept, chua thay the cho mot san pham EDR production.
