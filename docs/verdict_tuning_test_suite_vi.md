# Bo Test Chuan De Tuning Verdict Va Rule Logic

Tai lieu nay mo ta bo test `tests/verdict_tuning` dung de dieu chinh logic ket hop verdict cua PythonAgent. Muc tieu khong phai thay the Atomic Red Team, ma tao mot tap test co kiem soat de tra loi cau hoi:

- Hanh vi benign co bi canh bao qua muc khong?
- Discovery-only co bi nang len `TERMINATE` sai khong?
- Obfuscation/EncodedCommand co duoc canh bao nhung khong chan qua tay khong?
- Hanh vi high-confidence malicious co dat `TERMINATE` khong?

## 1. File trong bo test

```text
tests/verdict_tuning/verdict_tuning_cases.json
tests/verdict_tuning/run_verdict_tuning_tests.ps1
```

`verdict_tuning_cases.json` chua danh sach test case, script mo phong, verdict ky vong va ghi chu tuning.

`run_verdict_tuning_tests.ps1` gui tung case vao API `/telemetry` cua PythonAgent va xuat report JSON/CSV.

## 2. Cach chay

Khoi dong PythonAgent truoc, sau do chay:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\verdict_tuning\run_verdict_tuning_tests.ps1
```

Ket qua mac dinh:

```text
tests/verdict_tuning/verdict_tuning_report.json
tests/verdict_tuning/verdict_tuning_report.csv
```

Neu muon chi dinh file report rieng:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\verdict_tuning\run_verdict_tuning_tests.ps1 `
  -ReportPath tests\verdict_tuning\verdict_tuning_report_before_tuning.json
```

Sau khi tuning logic, chay lai:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\verdict_tuning\run_verdict_tuning_tests.ps1 `
  -ReportPath tests\verdict_tuning\verdict_tuning_report_after_tuning.json
```

## 3. Nhom test va verdict ky vong

### Benign admin

Ky vong: `ALLOW`.

Nhom nay gom cac lenh quan tri thong thuong:

| ID | Hanh vi | Expected |
|---|---|---|
| VT-BEN-001 | Doc locale/regional settings | ALLOW |
| VT-BEN-002 | `Get-Process` don le | ALLOW |
| VT-BEN-003 | Liet ke thu muc temp | ALLOW |
| VT-BEN-004 | Liet ke service | ALLOW |
| VT-BEN-005 | Doc registry regional settings | ALLOW |
| VT-BEN-006 | Lay thong tin he dieu hanh | ALLOW |
| VT-BEN-007 | Tao va xoa file test trong temp | ALLOW |

Neu cac case nay bi `ALERT` hoac `TERMINATE`, logic hien tai dang qua nhay voi hanh vi quan tri lanh tinh. Can giam trong so discovery-only, registry-read-only va temp-file automation.

### Suspicious

Ky vong: `ALERT`.

Nhom nay co dau hieu dang nghi nhung chua du manh de terminate:

| ID | Hanh vi | Expected |
|---|---|---|
| VT-SUS-101 | EncodedCommand voi payload benign | ALERT |
| VT-SUS-102 | Base64 decode nhung khong execute | ALERT |
| VT-SUS-103 | Ghep chuoi bang char array | ALERT |
| VT-SUS-104 | Nhieu lenh discovery trong mot script | ALERT |
| VT-SUS-105 | PowerShell hidden window | ALERT |
| VT-SUS-106 | Download tu nguon whitelist, khong execute | ALERT |

Neu cac case nay thanh `ALLOW`, agent co the bo sot hanh vi dang nghi. Neu thanh `TERMINATE`, policy dang qua manh va de gay false positive.

### Malicious / high-confidence

Ky vong: `TERMINATE`.

Nhom nay co tin hieu nguy hiem ro:

| ID | Hanh vi | Expected |
|---|---|---|
| VT-MAL-201 | Credential dumping keywords | TERMINATE |
| VT-MAL-202 | Download + execute chain | TERMINATE |
| VT-MAL-203 | AMSI bypass indicators | TERMINATE |
| VT-MAL-204 | Defender tampering | TERMINATE |
| VT-MAL-205 | Persistence + hidden encoded PowerShell | TERMINATE |
| VT-MAL-206 | Memory injection API cluster | TERMINATE |

Neu cac case nay khong dat `TERMINATE`, can tang trong so rule cho credential dumping, downloader-execute, AMSI bypass, Defender tampering, persistence va memory injection.

### Borderline benign

Ky vong: `ALLOW`.

| ID | Hanh vi | Expected |
|---|---|---|
| VT-BRD-301 | Tao SecureString/PSCredential | ALLOW |
| VT-BRD-302 | Doc Windows Event Log | ALLOW |

Day la cac case de kiem tra false positive trong cong viec IT support/System admin. `ConvertTo-SecureString`, `PSCredential` va `Get-WinEvent` khong nen bi xem la doc hai neu khong di kem credential dumping, exfiltration hoac event log clearing.

## 4. Cach dien giai ket qua

Report CSV co cac cot quan trong:

| Cot | Y nghia |
|---|---|
| `expected_final_verdict` | Verdict muc tieu theo policy thuc te |
| `actual_final_verdict` | Verdict PythonAgent tra ve |
| `rule_verdict` | Ket qua rule baseline |
| `ml_verdict` | Ket qua ML |
| `risk_level` | Muc risk tu feature analysis |
| `tuning_note` | Huong sua neu case bi fail |

Neu case fail, khong nen sua model ngay lap tuc. Nen xem fail thuoc nhom nao:

- Benign bi `ALERT/TERMINATE`: can giam false positive bang rule cap, benign context hoac ML threshold.
- Suspicious bi `ALLOW`: can tang detection cho obfuscation/encoded/discovery chain.
- Suspicious bi `TERMINATE`: can giam severity, chi terminate khi co tin hieu manh hon.
- Malicious khong `TERMINATE`: can tang high-confidence rule.

## 5. Policy tuning de xuat

Logic nen huong toi cac quy tac sau:

1. Discovery-only khong duoc vuot qua `ALERT`.
2. Discovery don le co tinh quan tri nen `ALLOW`.
3. `TERMINATE` chi ap dung cho high-confidence behavior:
   - credential dumping,
   - AMSI bypass,
   - Defender tampering,
   - download + execute,
   - persistence ket hop obfuscation/hidden execution,
   - memory injection API cluster.
4. ML `MALICIOUS` khong nen tu dong nang discovery-only len `TERMINATE`.
5. Neu ML `MALICIOUS` nhung rule/risk chi la benign discovery, cap ve `ALERT` hoac `ALLOW` tuy ngu canh.
6. Cac lenh IT support pho bien can co benign context de giam false positive.

## 6. Quy trinh dung trong khoa luan

Quy trinh nen trinh bay:

1. Chay `verdict_tuning_report_before_tuning.json`.
2. Ghi lai cac case false positive va false negative.
3. Dieu chinh rule/combine verdict.
4. Chay `verdict_tuning_report_after_tuning.json`.
5. So sanh ty le pass truoc/sau.
6. Chay lai Atomic Red Team de dam bao tuning khong lam mat kha nang phat hien hanh vi nguy hiem.

Bo test nay giup chung minh qua trinh tuning co co so khoa hoc: khong chi toi uu theo 12 Atomic tests, ma con co tap benign/suspicious/malicious rieng de kiem soat false positive.

