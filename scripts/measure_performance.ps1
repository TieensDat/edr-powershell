param(
    [string]$Label = "measurement",
    [int]$DurationSeconds = 60,
    [int]$SampleIntervalSeconds = 1,
    [string]$OutputCsvPath = ""
)

$ErrorActionPreference = "Stop"

if ($DurationSeconds -lt 5) {
    throw "DurationSeconds must be at least 5."
}

if ($SampleIntervalSeconds -lt 1) {
    throw "SampleIntervalSeconds must be at least 1."
}

function New-Stats {
    return [pscustomobject]@{
        Values = @()
    }
}

function Add-StatValue {
    param(
        [Parameter(Mandatory=$true)]$Stats,
        [double]$Value
    )
    $Stats.Values += $Value
}

function Get-Avg {
    param([array]$Values)
    if (-not $Values -or $Values.Count -eq 0) {
        return 0.0
    }
    return [math]::Round((($Values | Measure-Object -Average).Average), 2)
}

function Get-SumProperty {
    param(
        [array]$Processes,
        [string]$PropertyName
    )

    $sum = 0.0
    foreach ($proc in $Processes) {
        $prop = $proc.PSObject.Properties[$PropertyName]
        if ($null -ne $prop -and $null -ne $prop.Value) {
            $sum += [double]$prop.Value
        }
    }
    return $sum
}

function Get-ProcessTotals {
    param([string]$Name)

    $processes = @(Get-Process -Name $Name -ErrorAction SilentlyContinue)
    $cpuSeconds = Get-SumProperty -Processes $processes -PropertyName "CPU"
    $workingSet = Get-SumProperty -Processes $processes -PropertyName "WorkingSet64"
    $privateMemory = Get-SumProperty -Processes $processes -PropertyName "PrivateMemorySize64"
    $ioRead = Get-SumProperty -Processes $processes -PropertyName "IOReadBytes"
    $ioWrite = Get-SumProperty -Processes $processes -PropertyName "IOWriteBytes"

    return [pscustomobject]@{
        Count = $processes.Count
        CpuSeconds = $cpuSeconds
        WorkingSetMB = $workingSet / 1MB
        PrivateMemoryMB = $privateMemory / 1MB
        IOReadBytes = $ioRead
        IOWriteBytes = $ioWrite
    }
}

function Get-SystemCounterValues {
    try {
        $samples = Get-Counter `
            "\Processor(_Total)\% Processor Time", `
            "\Memory\Available MBytes", `
            "\PhysicalDisk(_Total)\Disk Bytes/sec" `
            -ErrorAction Stop

        $values = @{
            SystemCpuPercent = 0.0
            AvailableMemoryMB = 0.0
            DiskBytesPerSec = 0.0
        }

        foreach ($sample in $samples.CounterSamples) {
            if ($sample.Path -like "*\processor(_total)\% processor time") {
                $values.SystemCpuPercent = [double]$sample.CookedValue
            }
            elseif ($sample.Path -like "*\memory\available mbytes") {
                $values.AvailableMemoryMB = [double]$sample.CookedValue
            }
            elseif ($sample.Path -like "*\physicaldisk(_total)\disk bytes/sec") {
                $values.DiskBytesPerSec = [double]$sample.CookedValue
            }
        }

        return $values
    }
    catch {
        return @{
            SystemCpuPercent = 0.0
            AvailableMemoryMB = 0.0
            DiskBytesPerSec = 0.0
        }
    }
}

$logicalCores = [Environment]::ProcessorCount
$sampleCount = [math]::Ceiling($DurationSeconds / $SampleIntervalSeconds)

$stats = @{
    SystemCpuPercent = New-Stats
    AvailableMemoryMB = New-Stats
    DiskBytesPerSec = New-Stats
    PythonCpuPercent = New-Stats
    PythonWorkingSetMB = New-Stats
    PythonPrivateMemoryMB = New-Stats
    PythonIOReadBytesPerSec = New-Stats
    PythonIOWriteBytesPerSec = New-Stats
    AgentConsoleCpuPercent = New-Stats
    AgentConsoleWorkingSetMB = New-Stats
    AgentConsolePrivateMemoryMB = New-Stats
    AgentConsoleIOReadBytesPerSec = New-Stats
    AgentConsoleIOWriteBytesPerSec = New-Stats
}

$previous = @{
    python = Get-ProcessTotals -Name "python"
    AgentConsole = Get-ProcessTotals -Name "AgentConsole"
}

Write-Host "[MEASURE] Label: $Label"
Write-Host "[MEASURE] Duration: $DurationSeconds seconds"
Write-Host "[MEASURE] Sample interval: $SampleIntervalSeconds second(s)"
Write-Host "[MEASURE] Logical cores: $logicalCores"
Write-Host "[MEASURE] Measuring..."

$startTime = Get-Date

for ($i = 1; $i -le $sampleCount; $i++) {
    Start-Sleep -Seconds $SampleIntervalSeconds

    $system = Get-SystemCounterValues
    Add-StatValue -Stats $stats.SystemCpuPercent -Value $system.SystemCpuPercent
    Add-StatValue -Stats $stats.AvailableMemoryMB -Value $system.AvailableMemoryMB
    Add-StatValue -Stats $stats.DiskBytesPerSec -Value $system.DiskBytesPerSec

    $currentPython = Get-ProcessTotals -Name "python"
    $currentAgentConsole = Get-ProcessTotals -Name "AgentConsole"

    $pythonCpu = (($currentPython.CpuSeconds - $previous.python.CpuSeconds) / $SampleIntervalSeconds / $logicalCores) * 100
    $agentCpu = (($currentAgentConsole.CpuSeconds - $previous.AgentConsole.CpuSeconds) / $SampleIntervalSeconds / $logicalCores) * 100

    $pythonRead = ($currentPython.IOReadBytes - $previous.python.IOReadBytes) / $SampleIntervalSeconds
    $pythonWrite = ($currentPython.IOWriteBytes - $previous.python.IOWriteBytes) / $SampleIntervalSeconds
    $agentRead = ($currentAgentConsole.IOReadBytes - $previous.AgentConsole.IOReadBytes) / $SampleIntervalSeconds
    $agentWrite = ($currentAgentConsole.IOWriteBytes - $previous.AgentConsole.IOWriteBytes) / $SampleIntervalSeconds

    Add-StatValue -Stats $stats.PythonCpuPercent -Value ([math]::Max(0, $pythonCpu))
    Add-StatValue -Stats $stats.PythonWorkingSetMB -Value $currentPython.WorkingSetMB
    Add-StatValue -Stats $stats.PythonPrivateMemoryMB -Value $currentPython.PrivateMemoryMB
    Add-StatValue -Stats $stats.PythonIOReadBytesPerSec -Value ([math]::Max(0, $pythonRead))
    Add-StatValue -Stats $stats.PythonIOWriteBytesPerSec -Value ([math]::Max(0, $pythonWrite))

    Add-StatValue -Stats $stats.AgentConsoleCpuPercent -Value ([math]::Max(0, $agentCpu))
    Add-StatValue -Stats $stats.AgentConsoleWorkingSetMB -Value $currentAgentConsole.WorkingSetMB
    Add-StatValue -Stats $stats.AgentConsolePrivateMemoryMB -Value $currentAgentConsole.PrivateMemoryMB
    Add-StatValue -Stats $stats.AgentConsoleIOReadBytesPerSec -Value ([math]::Max(0, $agentRead))
    Add-StatValue -Stats $stats.AgentConsoleIOWriteBytesPerSec -Value ([math]::Max(0, $agentWrite))

    $previous.python = $currentPython
    $previous.AgentConsole = $currentAgentConsole
}

$finishedAt = Get-Date

$result = [pscustomobject]@{
    Label = $Label
    StartedAt = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
    FinishedAt = $finishedAt.ToString("yyyy-MM-dd HH:mm:ss")
    DurationSeconds = $DurationSeconds
    SampleIntervalSeconds = $SampleIntervalSeconds
    SystemCpuAvgPercent = Get-Avg $stats.SystemCpuPercent.Values
    AvailableMemoryAvgMB = Get-Avg $stats.AvailableMemoryMB.Values
    DiskBytesPerSecAvg = Get-Avg $stats.DiskBytesPerSec.Values
    PythonCpuAvgPercent = Get-Avg $stats.PythonCpuPercent.Values
    PythonWorkingSetAvgMB = Get-Avg $stats.PythonWorkingSetMB.Values
    PythonPrivateMemoryAvgMB = Get-Avg $stats.PythonPrivateMemoryMB.Values
    PythonIOReadBytesPerSecAvg = Get-Avg $stats.PythonIOReadBytesPerSec.Values
    PythonIOWriteBytesPerSecAvg = Get-Avg $stats.PythonIOWriteBytesPerSec.Values
    AgentConsoleCpuAvgPercent = Get-Avg $stats.AgentConsoleCpuPercent.Values
    AgentConsoleWorkingSetAvgMB = Get-Avg $stats.AgentConsoleWorkingSetMB.Values
    AgentConsolePrivateMemoryAvgMB = Get-Avg $stats.AgentConsolePrivateMemoryMB.Values
    AgentConsoleIOReadBytesPerSecAvg = Get-Avg $stats.AgentConsoleIOReadBytesPerSec.Values
    AgentConsoleIOWriteBytesPerSecAvg = Get-Avg $stats.AgentConsoleIOWriteBytesPerSec.Values
}

Write-Host ""
Write-Host "[MEASURE] Summary"
$result | Format-List

if ($OutputCsvPath) {
    $fileExists = Test-Path $OutputCsvPath
    $result | Export-Csv -Path $OutputCsvPath -NoTypeInformation -Append:$fileExists -Encoding UTF8
    Write-Host "[MEASURE] Saved CSV: $OutputCsvPath"
}
