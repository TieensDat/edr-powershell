# Ket Qua Chay Bo Test Verdict Tuning

Run ID: `VTUNE_20260609_230507`

File ket qua:

```text
tests/verdict_tuning/verdict_tuning_report_20260609_230505.json
tests/verdict_tuning/verdict_tuning_report_20260609_230505.csv
```

Luu y: file `verdict_tuning_report_20260609_230403` la lan chay loi do runner doc mang JSON khong dung tren Windows PowerShell. Runner da duoc sua sau lan do. Ket qua hop le de danh gia la `verdict_tuning_report_20260609_230505`.

## 1. Tong quan

| Chi so | Ket qua |
|---|---:|
| Tong so test | 21 |
| Pass | 11 |
| Fail | 10 |
| Pass rate | 52.38% |

Ket qua cho thay logic verdict hien tai da bat duoc mot so nhom hanh vi quan trong, nhung van can tuning de giam false positive va tang severity cho mot so tin hieu nguy hiem.

## 2. Ket qua theo nhom

| Nhom | Ket qua | Nhan xet |
|---|---:|---|
| Benign admin | 5/7 pass | Da nhan dien dung nhieu lenh quan tri co ban, nhung con FP voi registry read va temp file cleanup. |
| Suspicious | 3/6 pass | Co case bi nang qua muc len TERMINATE, co case obfuscation lai bi ALLOW. |
| Malicious high-confidence | 3/6 pass | Credential dumping, download-execute va persistence dat TERMINATE; AMSI bypass, Defender tampering va memory injection chua du manh. |
| Borderline benign | 0/2 pass | Secure credential object va read event log bi ML keo len ALERT. |

## 3. Cac case fail quan trong

### False positive / can giam nhay

| ID | Expected | Actual | Nguyen nhan quan sat |
|---|---|---|---|
| VT-BEN-005 | ALLOW | ALERT | Rule ALLOW, risk LOW, nhung ML MALICIOUS confidence 0.57. |
| VT-BEN-007 | ALLOW | ALERT | Rule ALLOW, ML MALICIOUS 0.77; temp file write/remove bi xem hoi nang. |
| VT-BRD-301 | ALLOW | ALERT | SecureString/PSCredential bi ML MALICIOUS 0.66. |
| VT-BRD-302 | ALLOW | ALERT | Get-WinEvent bi ML MALICIOUS 0.60 du rule ALLOW/risk LOW. |

Nhan xet: nhom false positive chu yeu den tu ML `MALICIOUS` trong khi rule dang `ALLOW` va risk thap. Day la dau hieu model con nhay voi cac pattern quan tri hop le.

### Over-escalation / can ha tu TERMINATE xuong ALERT

| ID | Expected | Actual | Nguyen nhan quan sat |
|---|---|---|---|
| VT-SUS-101 | ALERT | TERMINATE | EncodedCommand benign payload bi nang len TERMINATE vi rule ALERT + ML MALICIOUS 0.92 + risk HIGH. |
| VT-SUS-105 | ALERT | TERMINATE | Hidden PowerShell window voi payload benign bi nang len TERMINATE. |

Nhan xet: `EncodedCommand` va `Hidden Window` la tin hieu dang nghi, nhung neu payload chi benign/demo thi chi nen ALERT. TERMINATE nen yeu cau them tin hieu manh nhu downloader, credential dumping, AMSI bypass, persistence, memory injection hoac download-execute chain.

### Under-detection / can tang severity

| ID | Expected | Actual | Nguyen nhan quan sat |
|---|---|---|---|
| VT-SUS-103 | ALERT | ALLOW | Character array reconstruction chua duoc bat. |
| VT-MAL-203 | TERMINATE | ALERT | AMSI bypass indicators chi len ALERT. |
| VT-MAL-204 | TERMINATE | ALERT | Defender tampering `Set-MpPreference -DisableRealtimeMonitoring` chi len ALERT. |
| VT-MAL-206 | TERMINATE | ALERT | Memory injection API cluster bi ML bat nhung rule ALLOW, final chi ALERT. |

Nhan xet: cac hanh vi high-confidence nhu AMSI bypass, Defender tampering va memory injection API cluster nen dat TERMINATE o muc policy, khong nen phu thuoc qua nhieu vao ML.

## 4. De xuat tuning

Chua thuc hien tuning trong lan nay. Cac de xuat duoi day chi la huong sua.

### Uu tien 1: Giam false positive tu ML khi rule/risk thap

De xuat:

- Neu `rule_verdict = ALLOW`, `risk_level = LOW`, va script thuoc benign admin context thi khong nen de ML mot minh nang len ALERT.
- Tang nguong chap nhan ML MALICIOUS khi khong co rule/risk ho tro, vi cac FP hien tai co confidence tu 0.57 den 0.77.
- Them benign context cho:
  - registry read benign,
  - temp file write/remove trong `$env:TEMP`,
  - `ConvertTo-SecureString`/`PSCredential`,
  - `Get-WinEvent` chi doc log.

### Uu tien 2: Cap severity cho suspicious-only

De xuat:

- `EncodedCommand` don le: toi da ALERT neu khong co download/execute/credential/persistence/AMSI bypass.
- `Hidden Window` don le: toi da ALERT neu payload benign va khong co chain nguy hiem.
- Discovery-only chain: toi da ALERT, khong TERMINATE.

### Uu tien 3: Tang high-confidence TERMINATE rule

De xuat:

- AMSI bypass indicator nen TERMINATE khi xuat hien ro cac token nhu `AmsiUtils`, `amsiInitFailed`, `amsi fail`.
- Defender tampering nhu `Set-MpPreference -DisableRealtimeMonitoring` nen TERMINATE.
- Memory injection cluster nen TERMINATE khi co tu 3 tin hieu tro len trong nhom `VirtualAlloc`, `CreateThread`, `GetProcAddress`, `Marshal.Copy`, `0x40`.

### Uu tien 4: Bat char-array reconstruction o muc ALERT

De xuat:

- Sua pattern de bat chuoi `([char]73)+([char]69)+([char]88)` va cac bien the tuong tu.
- Khong TERMINATE neu chi reconstruct string; chi terminate khi di kem `IEX`, downloader hoac payload.

## 5. Thu tu thuc hien de giam rui ro

Nen tuning theo thu tu:

1. Them cap rule de discovery/admin benign khong bi ML nang len qua muc.
2. Cap `EncodedCommand`/hidden-window-only o muc ALERT.
3. Tang rule TERMINATE cho AMSI bypass, Defender tampering, memory injection cluster.
4. Chay lai bo `verdict_tuning`.
5. Chay lai Atomic Red Team de dam bao khong lam mat detection o cac test nguy hiem.
6. Neu false positive van cao, luc do moi tinh den retrain model voi benign dataset lon hon.

## 6. Ket luan

Bo test cho thay he thong hien tai co kha nang phat hien hanh vi PowerShell dang nghi, nhung logic ket hop verdict con can tuning. Van de lon nhat la ML co the keo mot so lenh quan tri benign len ALERT, trong khi mot so tin hieu high-confidence nhu AMSI bypass, Defender tampering va memory injection chua duoc nang len TERMINATE. Ket qua nay phu hop de lam co so khoa hoc truoc khi tien hanh tuning logic.

