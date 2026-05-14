# Ghi chu dieu tra Event Log 4104 Sensor

## Ket qua ban dau

Lan chay truoc do cua `tests\event_sensor\event_sensor_report.json` dat 18/20. Hai case fail la:

- `EV011`: PowerShell `-File` voi script mot dong.
- `EV012`: PowerShell `-File` voi script nhieu dong.

Ca hai case deu khong co event moi tu `eventlog_4104_sensor`.

## Nguyen nhan

Kiem tra lai Windows Event Log goc cho thay marker cua `EV011` va `EV012` khong xuat hien trong Event ID 4104. Dieu nay cho thay PythonAgent khong bo sot record; ban than PowerShell khong tao 4104 cho hai lan chay do.

Nguyen nhan thuc te nam o test harness: hai case `EV011` va `EV012` tao file `.ps1` roi chay bang:

```powershell
powershell.exe -NoProfile -File <script.ps1>
```

Lenh nay phu thuoc vao Execution Policy hien tai cua may. Neu script file bi policy chan hoac khong duoc thuc thi day du, PowerShell se khong sinh Script Block Logging 4104 nhu ky vong. Cac case inline `-Command` van pass vi khong phu thuoc vao cung dieu kien thuc thi file script.

## Dieu chinh

Da cap nhat `EV011` va `EV012` de chay script file voi:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File <script.ps1>
```

Ngoai ra, da sua helper `Start-TestProcess` de khong truyen `ArgumentList` rong cho negative test `EV020`, vi Windows PowerShell 5.1 bao loi khi `ArgumentList` la mang rong.

## Ket qua sau dieu chinh

Report moi:

```text
tests\event_sensor\event_sensor_report.json
```

Ket qua:

| Chi so | Gia tri |
|---|---:|
| Tong test | 20 |
| Passed | 20 |
| Failed | 0 |
| Success rate | 100% |

Hai case `-File` da co Event ID 4104:

| Test | Observed events | Record ID |
|---|---:|---|
| EV011 | 1 | 10810 |
| EV012 | 1 | 10816 |

## Ket luan

Event Log 4104 Sensor hien tai dat 20/20 trong bo test. Hai loi ban dau khong phai do sensor bo sot telemetry, ma do test `-File` chua dam bao script file duoc thuc thi trong moi truong co Execution Policy khac nhau.

Khi trinh bay trong khoa luan, can neu ro dieu kien de thu duoc 4104 cho script file:

- PowerShell Script Block Logging phai duoc bat.
- Script file phai duoc thuc thi that su.
- Trong moi truong test, nen dung `-ExecutionPolicy Bypass` de loai bo bien nhieu do policy cuc bo.
