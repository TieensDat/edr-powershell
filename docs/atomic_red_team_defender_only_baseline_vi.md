# Hướng Dẫn Chạy 12 Atomic Red Team Với Windows Defender Only

Tài liệu này dùng để chạy lại 12 test Atomic Red Team trong điều kiện chỉ bật Windows Defender, không chạy PythonAgent và không chạy C++ AMSI Bridge Agent. Mục tiêu là tạo baseline so sánh: Windows Defender xử lý được những test nào khi không có hệ thống EDR của đề tài.

Checkpoint khuyến nghị: `CP01_Runtime_Install_Agent_stopped`.

## 1. Khôi phục checkpoint

Trên Hyper-V Manager, chọn máy ảo Windows 10 test, vào mục `Checkpoints`, chọn `CP01_Runtime_Install_Agent_stopped`, sau đó chọn `Apply`.

Nếu dùng PowerShell trên máy host:

```powershell
Restore-VMCheckpoint -VMName "<TEN_MAY_AO>" -Name "CP01_Runtime_Install_Agent_stopped" -Confirm:$false
```

Sau khi máy ảo khởi động lại, đăng nhập vào Windows và mở PowerShell bằng quyền Administrator.

## 2. Đảm bảo agent của đề tài không chạy

Nếu thư mục runtime nằm tại `C:\KLTN\mini-edr-powershell-runtime`, chạy:

```powershell
cd C:\KLTN\mini-edr-powershell-runtime
Get-Process python,AgentConsole -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process python,AgentConsole -ErrorAction SilentlyContinue
```

Lệnh cuối cùng không nên trả về tiến trình nào. Nếu vẫn thấy `python.exe` hoặc `AgentConsole.exe`, cần dừng lại trước khi chạy Atomic test. Không chạy `start_python_agent.ps1`, `AgentConsole.exe`, hoặc script test của project trong kịch bản này.

## 3. Kiểm tra Windows Defender

Chạy các lệnh sau để kiểm tra trạng thái Defender:

```powershell
Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled
Set-MpPreference -DisableRealtimeMonitoring $false
```

Nếu Windows chặn thay đổi do Tamper Protection, mở `Windows Security` -> `Virus & threat protection` -> `Manage settings`, sau đó kiểm tra `Real-time protection` đang bật.

Lưu ý: không thêm Defender exclusion cho thư mục Atomic Red Team trong phép đo này, vì mục tiêu là quan sát hành vi mặc định của Defender.

## 4. Cài Atomic Red Team nếu máy chưa có

Nếu máy test chưa có `C:\AtomicRedTeam`, chạy:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-Module -Name powershell-yaml -Scope CurrentUser -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
```

Kiểm tra cài đặt:

```powershell
Test-Path C:\AtomicRedTeam\atomics
Test-Path C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1
```

Cả hai lệnh nên trả về `True`.

## 5. Chạy 12 test Atomic Red Team với Defender only

Chạy toàn bộ block dưới đây trong PowerShell Administrator:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
Import-Module powershell-yaml -Force
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 -Force

$AtomicsPath = "C:\AtomicRedTeam\atomics"
$RunId = "DEFENDER_ONLY_" + (Get-Date -Format "yyyyMMdd_HHmmss")
$StartTime = Get-Date
$OutDir = Join-Path (Get-Location) "defender_only_results_$RunId"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$Tests = @(
    [pscustomobject]@{ Technique="T1059.001"; TestNumber="13"; Name="PowerShell command-line parameter variations" },
    [pscustomobject]@{ Technique="T1059.001"; TestNumber="15"; Name="PowerShell suspicious execution pattern" },
    [pscustomobject]@{ Technique="T1059.001"; TestNumber="17"; Name="PowerShell encoded command" },
    [pscustomobject]@{ Technique="T1059.001"; TestNumber="18"; Name="PowerShell session policy manipulation" },
    [pscustomobject]@{ Technique="T1027"; TestNumber="2"; Name="Obfuscated command / encoded payload" },
    [pscustomobject]@{ Technique="T1027"; TestNumber="7"; Name="Obfuscated script content" },
    [pscustomobject]@{ Technique="T1027"; TestNumber="11"; Name="Obfuscated PowerShell behavior" },
    [pscustomobject]@{ Technique="T1105"; TestNumber="10"; Name="PowerShell download behavior" },
    [pscustomobject]@{ Technique="T1105"; TestNumber="15"; Name="Ingress tool transfer over PowerShell" },
    [pscustomobject]@{ Technique="T1082"; TestNumber="37"; Name="System locale discovery" },
    [pscustomobject]@{ Technique="T1057"; TestNumber="3"; Name="Process discovery" },
    [pscustomobject]@{ Technique="T1083"; TestNumber="2"; Name="File and directory discovery" }
)

$Results = foreach ($t in $Tests) {
    Write-Host "[ATOMIC] Running $($t.Technique)-$($t.TestNumber): $($t.Name)"

    $status = "UNKNOWN"
    $errorText = ""
    $prereqTail = ""
    $executionTail = ""

    try {
        $pre = Invoke-AtomicTest $t.Technique `
            -TestNumbers $t.TestNumber `
            -PathToAtomicsFolder $AtomicsPath `
            -CheckPrereqs *>&1 | Out-String

        $prereqTail = (($pre -split "`r?`n") | Select-Object -Last 8) -join "`n"

        if ($pre -match "Prerequisites met") {
            $status = "EXECUTED"
            $out = Invoke-AtomicTest $t.Technique `
                -TestNumbers $t.TestNumber `
                -PathToAtomicsFolder $AtomicsPath `
                -TimeoutSeconds 60 `
                -NoExecutionLog *>&1 | Out-String

            $executionTail = (($out -split "`r?`n") | Select-Object -Last 12) -join "`n"
        }
        else {
            $status = "SKIPPED_PREREQ"
        }
    }
    catch {
        $status = "ERROR"
        $errorText = $_.Exception.Message
    }

    Start-Sleep -Seconds 5

    [pscustomobject]@{
        RunId = $RunId
        Technique = $t.Technique
        TestNumber = $t.TestNumber
        AtomicId = "$($t.Technique)-$($t.TestNumber)"
        Name = $t.Name
        Status = $status
        Error = $errorText
        PrereqTail = $prereqTail
        ExecutionTail = $executionTail
    }
}

$Results | Export-Csv (Join-Path $OutDir "atomic_execution.csv") -NoTypeInformation -Encoding UTF8

Get-MpThreatDetection |
    Where-Object { $_.InitialDetectionTime -ge $StartTime } |
    Export-Csv (Join-Path $OutDir "defender_threat_detection.csv") -NoTypeInformation -Encoding UTF8

Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Windows Defender/Operational"
    StartTime = $StartTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, ProviderName, Message |
    Export-Csv (Join-Path $OutDir "defender_operational_events.csv") -NoTypeInformation -Encoding UTF8

$Results | Format-Table AtomicId,Status,Name -AutoSize
Write-Host ""
Write-Host "Output folder: $OutDir"
```

## 6. Bằng chứng cần chụp và lưu

Sau khi chạy xong, cần lưu các bằng chứng sau:

- Ảnh màn hình PowerShell hiển thị bảng `AtomicId`, `Status`, `Name`.
- Ảnh thư mục kết quả `defender_only_results_<RunId>`.
- File `atomic_execution.csv`.
- File `defender_threat_detection.csv`.
- File `defender_operational_events.csv`.
- Ảnh `Windows Security` -> `Virus & threat protection` -> `Protection history`, nếu Defender có cảnh báo hoặc quarantine.

## 7. Cách đọc kết quả

`atomic_execution.csv` cho biết 12 Atomic test đã chạy được hay bị bỏ qua do thiếu prerequisite. `defender_threat_detection.csv` và `defender_operational_events.csv` cho biết Windows Defender có ghi nhận, cảnh báo, chặn hoặc quarantine hành vi nào hay không.

Kết quả này không dùng để chứng minh PythonAgent tốt hơn Defender. Nó dùng để trả lời câu hỏi baseline: nếu chỉ bật Windows Defender thì 12 kịch bản Atomic Red Team được xử lý như thế nào. Sau đó so sánh với kết quả khi bật PythonAgent và C++ AMSI Bridge để làm rõ đóng góp của hệ thống đề tài: thu thập telemetry, giải thích lý do verdict, ghi log bằng chứng, response/quarantine và khả năng tùy chỉnh rule/model trong môi trường lab.

## 8. Chạy đủ 12 test và lặp lại để kiểm tra tính ổn định

Nếu lần chạy đầu có test `SKIPPED_PREREQ`, không nên dùng kết quả đó để kết luận Defender detect hay không detect. Trước khi chạy lại, cần cài đủ prerequisite cho các test bị thiếu. Với hai test `T1059.001-13` và `T1059.001-15`, prerequisite thường gặp là module `AtomicTestHarnesses`.

Chạy trong PowerShell Administrator:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
Import-Module powershell-yaml -Force
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 -Force

Invoke-AtomicTest T1059.001 `
    -TestNumbers 13,15 `
    -PathToAtomicsFolder C:\AtomicRedTeam\atomics `
    -GetPrereqs

Invoke-AtomicTest T1059.001 `
    -TestNumbers 13,15 `
    -PathToAtomicsFolder C:\AtomicRedTeam\atomics `
    -CheckPrereqs
```

Khi cả 12 test đều không còn `SKIPPED_PREREQ`, nên tạo một checkpoint mới, ví dụ:

```text
CP02_DefenderOnly_AtomicReady
```

Checkpoint này nên được tạo sau khi:

- Atomic Red Team đã cài xong.
- Prerequisite của 12 test đã đủ.
- PythonAgent và AgentConsole không chạy.
- Windows Defender đang bật.

Quy trình chạy lặp lại khuyến nghị:

1. Apply checkpoint `CP02_DefenderOnly_AtomicReady`.
2. Đợi Windows ổn định khoảng 2-3 phút sau khi đăng nhập.
3. Kiểm tra lại agent không chạy:

```powershell
Get-Process python,AgentConsole -ErrorAction SilentlyContinue
```

4. Kiểm tra Defender đang bật:

```powershell
Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled
```

5. Chạy block test ở mục 5 và lưu thư mục kết quả với tên run rõ ràng, ví dụ:

```text
defender_only_results_run1
defender_only_results_run2
defender_only_results_run3
```

6. Sau mỗi lần chạy, copy thư mục kết quả ra ngoài hoặc lưu vào thư mục báo cáo.
7. Trước lần chạy tiếp theo, apply lại checkpoint `CP02_DefenderOnly_AtomicReady`.

Không nên chạy liên tiếp nhiều lần trên cùng một trạng thái máy nếu mục tiêu là so sánh khoa học. Sau khi Defender đã detect/quarantine/remediate một hành vi, trạng thái hệ thống, cache cloud protection và threat history có thể thay đổi, làm kết quả lần sau không còn tương đương lần đầu.

Nên chạy ít nhất 3 lần. Nếu thời gian cho phép, chạy 5 lần sẽ tốt hơn. Bảng tổng hợp nên có các cột:

| Atomic ID | Run 1 | Run 2 | Run 3 | Defender event 1116/1117 | Kết luận |
|---|---|---|---|---|---|
| T1059.001-18 | ERROR/blocked | ERROR/blocked | ERROR/blocked | Có | Defender chặn ổn định |
| T1105-10 | ERROR/blocked | ERROR/blocked | ERROR/blocked | Có | Defender chặn ổn định |
| T1082-37 | EXECUTED | EXECUTED | EXECUTED | Không | Defender không cảnh báo |

Tiêu chí kết luận một test bị Windows Defender chặn:

- `atomic_execution.csv` có `Status = ERROR` hoặc output thể hiện command không chạy được.
- `Error` có nội dung như `Access is denied`.
- Trong cùng khoảng thời gian chạy test, `defender_operational_events.csv` có event ID `1116` hoặc `1117`.
- Message của Defender có threat name, severity, action và command/path liên quan đến test đang chạy.
- `defender_threat_detection.csv` có bản ghi threat detection tương ứng.

Nếu test bị `ERROR` nhưng không có event Defender tương ứng, không nên kết luận là Defender chặn. Khi đó cần xem lại lỗi môi trường như thiếu quyền Administrator, lỗi mạng, thiếu file, thiếu module, hoặc command của Atomic test không tương thích với máy test.
