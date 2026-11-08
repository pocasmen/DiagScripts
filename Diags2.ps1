<#
.SYNOPSIS
    ECO-UniversalDiagnostic.ps1 - Ecocardiograma Completo em 2 Fases (ASCII Puro)
.DESCRIPTION
    Compatibilidade universal sem dependencias de codificacao ou idioma.
#>

[CmdletBinding()]
param (
    [string]$OutputDir = "."
)

# 1. Hardware e Clock Base do Kernel
$LogicalCores = [Environment]::ProcessorCount
$CpuInfo = Get-CimInstance Win32_Processor | Select-Object -First 1
$CpuModel = $CpuInfo.Name.Trim()

$KernelBaseClock = try {
    (Get-ItemProperty -Path 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0' -ErrorAction Stop).'~MHz'
} catch {
    [int]$CpuInfo.MaxClockSpeed
}

Clear-Host
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "     ECOCARDIOGRAMA DE BANCADA (UNIVERSAL / INTERATIVO)   " -ForegroundColor Cyan
Write-Host "   Processador     : $CpuModel" -ForegroundColor Gray
Write-Host "   Threads Logicas : $LogicalCores" -ForegroundColor Gray
Write-Host "   Clock Base      : $KernelBaseClock MHz ($([math]::Round($KernelBaseClock/1000, 2)) GHz)" -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Cyan

# 2. Funcoes Interativas (ASCII Puro)
function Ask-YesNo {
    param([string]$Prompt, [bool]$Default = $true)
    $defStr = if ($Default) { "S/n" } else { "s/N" }
    while ($true) {
        $ans = (Read-Host "$Prompt ($defStr)").Trim().ToLower()
        if ([string]::IsNullOrWhiteSpace($ans)) { return $Default }
        if ($ans -in @('s', 'sim', 'y', 'yes')) { return $true }
        if ($ans -in @('n', 'nao', 'no')) { return $false }
        Write-Host "Opcao invalida. Digite 'S' para Sim ou 'N' para Nao." -ForegroundColor Red
    }
}

function Ask-Duration {
    param([string]$Prompt, [int]$Default = 60, [int]$Min = 30, [int]$Max = 600)
    while ($true) {
        $val = (Read-Host "$Prompt [$Min-$Max s] (Predefinicao: $Default)").Trim()
        if ([string]::IsNullOrWhiteSpace($val)) { return $Default }
        if ($val -as [int] -and [int]$val -ge $Min -and [int]$val -le $Max) {
            return [int]$val
        }
        Write-Host "Valor invalido. Insira um numero inteiro entre $Min e $Max segundos." -ForegroundColor Red
    }
}

Write-Host "`n[CONFIGURACAO DA PROVA DE ESFORCO]" -ForegroundColor Yellow

$RunCpuTest = Ask-YesNo "Deseja executar a Fase 1: Prova de CPU e Memoria?" $true
$CpuDuration = 0
if ($RunCpuTest) {
    $CpuDuration = Ask-Duration "Duracao do teste de CPU" 60 30 600
}

$RunDiskTest = Ask-YesNo "Deseja executar a Fase 2: Prova de Disco (I/O Intensivo)?" $true
$DiskDuration = 0
if ($RunDiskTest) {
    $DiskDuration = Ask-Duration "Duracao do teste de Disco" 60 30 600
}

if (-not $RunCpuTest -and -not $RunDiskTest) {
    Write-Warning "`nNenhum teste foi selecionado. Operacao cancelada."
    exit
}

# 3. Estrutura de Telemetria
$EcoData = [ordered]@{
    Metadata = [ordered]@{
        ComputerName       = $env:COMPUTERNAME
        Timestamp          = (Get-Date).ToString("o")
        CPUModel           = $CpuModel
        LogicalCores       = $LogicalCores
        BaseClockMHz       = $KernelBaseClock
        CpuTestExecuted    = $RunCpuTest
        CpuDurationSec     = $CpuDuration
        DiskTestExecuted   = $RunDiskTest
        DiskDurationSec    = $DiskDuration
    }
    Baseline               = [ordered]@{}
    CpuStressMetrics       = @()
    DiskStressMetrics      = @()
    Recovery               = [ordered]@{}
    HardwareEvents         = [ordered]@{}
    DiagnosticVerdict      = [ordered]@{}
}

# 4. Telemetria Dinamica
function Get-VitalsRealTime {
    param([int]$BaseClock)
    try {
        $CpuMetric = Get-CimInstance -ClassName Win32_PerfFormattedData_Counters_ProcessorInformation -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*_Total" } | Select-Object -First 1

        $OSMetric = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        $DiskMetric = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" -ErrorAction SilentlyContinue

        $PerfPct = if ($CpuMetric.PercentProcessorPerformance) {
            [double]$CpuMetric.PercentProcessorPerformance
        } elseif ($CpuMetric.PercentofMaximumFrequency) {
            [double]$CpuMetric.PercentofMaximumFrequency
        } else { 100 }

        $RealClockMHz = [int][math]::Round(($BaseClock * ($PerfPct / 100)), 0)

        $CpuUsage = if ($CpuMetric.PercentProcessorUtility) {
            [math]::Min(100, [int][math]::Round($CpuMetric.PercentProcessorUtility, 0))
        } else {
            [int](Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'").PercentProcessorTime
        }

        $FreeRAM_MB = [int][math]::Round($OSMetric.FreePhysicalMemory / 1024, 0)
        $DiskTimePct = if ($DiskMetric) { [math]::Min(100, [int]$DiskMetric.PercentDiskTime) } else { 0 }
        $DiskMBs = if ($DiskMetric) { [math]::Round($DiskMetric.DiskBytesPerSec / 1MB, 1) } else { 0 }
        $DiskQueue = if ($DiskMetric) { [int]$DiskMetric.CurrentDiskQueueLength } else { 0 }

        return [PSCustomObject]@{
            CPU_UsagePct       = $CpuUsage
            CPU_ClockMHz       = $RealClockMHz
            Mem_AvailMB        = $FreeRAM_MB
            Disk_UsagePct      = $DiskTimePct
            Disk_ThroughputMBs = $DiskMBs
            Disk_Queue         = $DiskQueue
        }
    } catch {
        return $null
    }
}

# 5. Medicao em Repouso (Baseline: 6 segundos)
Write-Host "`n>>> [FASE 0/4] A medir sinais vitais em repouso (Baseline de 6s)..." -ForegroundColor Yellow
$BaselineSamples = @()
for ($i = 0; $i -lt 3; $i++) {
    $Sample = Get-VitalsRealTime -BaseClock $KernelBaseClock
    if ($Sample) { $BaselineSamples += $Sample }
    Start-Sleep -Seconds 2
}

$EcoData.Baseline = [ordered]@{
    CPU_IdleUsagePct  = [math]::Round(($BaselineSamples.CPU_UsagePct | Measure-Object -Average).Average, 1)
    CPU_IdleClockMHz  = [int]($BaselineSamples.CPU_ClockMHz | Measure-Object -Average).Average
    FreeRAM_MB        = [int]($BaselineSamples.Mem_AvailMB | Measure-Object -Average).Average
    Disk_IdleUsagePct = [int]($BaselineSamples.Disk_UsagePct | Measure-Object -Average).Average
}

Write-Host "    Baseline OK -> CPU: $($EcoData.Baseline.CPU_IdleUsagePct)% | Clock: $($EcoData.Baseline.CPU_IdleClockMHz) MHz | RAM Livre: $($EcoData.Baseline.FreeRAM_MB) MB | Disco: $($EcoData.Baseline.Disk_IdleUsagePct)%" -ForegroundColor Gray

$OverallStartTime = Get-Date

# 6. Fase 1: Stress de CPU e RAM
if ($RunCpuTest) {
    Write-Host "`n>>> [FASE 1/4] A INICIAR STRESS DE PROCESSADOR ($CpuDuration segundos)..." -ForegroundColor Yellow
    Write-Host ("{0,6} | {1,8} | {2,11} | {3,12} | {4,10} | {5,10}" -f "Tempo", "CPU Uso", "Clock Real", "RAM Livre", "Uso Disco", "Fila Disco") -ForegroundColor DarkCyan

    $CpuPool = [runspacefactory]::CreateRunspacePool(1, $LogicalCores)
    $CpuPool.Open()

    $CpuWorker = {
        param($Duration)
        $Watch = [System.Diagnostics.Stopwatch]::StartNew()
        $Sha = [System.Security.Cryptography.SHA256]::Create()
        $Buffer = [byte[]]::new(16384)
        (New-Object Random).NextBytes($Buffer)
        while ($Watch.Elapsed.TotalSeconds -lt $Duration) {
            for ($i = 0; $i -lt 150; $i++) { $null = $Sha.ComputeHash($Buffer) }
        }
        $Sha.Dispose()
    }

    try {
        for ($c = 0; $c -lt $LogicalCores; $c++) {
            $Instance = [powershell]::Create().AddScript($CpuWorker).AddArgument($CpuDuration)
            $Instance.RunspacePool = $CpuPool
            $null = $Instance.BeginInvoke()
        }

        $CpuWatch = [System.Diagnostics.Stopwatch]::StartNew()
        while ($CpuWatch.Elapsed.TotalSeconds -lt $CpuDuration) {
            Start-Sleep -Seconds 2
            $V = Get-VitalsRealTime -BaseClock $KernelBaseClock
            if ($V) {
                $Elapsed = [math]::Round($CpuWatch.Elapsed.TotalSeconds, 0)
                $EcoData.CpuStressMetrics += [PSCustomObject]@{
                    Second       = $Elapsed
                    CPU_UsagePct = $V.CPU_UsagePct
                    CPU_ClockMHz = $V.CPU_ClockMHz
                    Mem_AvailMB  = $V.Mem_AvailMB
                }
                Write-Host ("{0,5}s | {1,7}% | {2,7} MHz | {3,9} MB | {4,9}% | {5,10}" -f `
                    $Elapsed, $V.CPU_UsagePct, $V.CPU_ClockMHz, $V.Mem_AvailMB, $V.Disk_UsagePct, $V.Disk_Queue) -ForegroundColor White
            }
        }
    } finally {
        $CpuPool.Close()
        $CpuPool.Dispose()
    }

    Write-Host "    Fase 1 terminada. Intervalo de arrefecimento de 5 segundos..." -ForegroundColor Gray
    Start-Sleep -Seconds 5
}

# 7. Fase 2: Stress de Disco Multi-Thread
if ($RunDiskTest) {
    Write-Host "`n>>> [FASE 2/4] A INICIAR PROVA DE DISCO MULTI-THREAD ($DiskDuration segundos)..." -ForegroundColor Yellow
    Write-Host ("{0,6} | {1,8} | {2,11} | {3,12} | {4,10} | {5,12} | {6,10}" -f "Tempo", "CPU Uso", "Clock Real", "RAM Livre", "Uso Disco", "Transf. Disco", "Fila Disco") -ForegroundColor DarkCyan

    $DiskThreads = 4
    $DiskPool = [runspacefactory]::CreateRunspacePool(1, $DiskThreads)
    $DiskPool.Open()

    $DiskWorker = {
        param($Duration, $WorkerId)
        $Watch = [System.Diagnostics.Stopwatch]::StartNew()
        $Guid = [System.Guid]::NewGuid().ToString("N")
        $Path = Join-Path $env:TEMP "bancada_io_${WorkerId}_$Guid.tmp"
        $BlockSize = 64KB
        $Buffer = [byte[]]::new($BlockSize)
        (New-Object Random).NextBytes($Buffer)
        $Stream = $null

        try {
            $Stream = New-Object System.IO.FileStream(
                $Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None, $BlockSize, [System.IO.FileOptions]::WriteThrough
            )

            while ($Watch.Elapsed.TotalSeconds -lt $Duration) {
                $Stream.Position = 0
                for ($i = 0; $i -lt 150; $i++) {
                    if ($Watch.Elapsed.TotalSeconds -ge $Duration) { break }
                    $Stream.Write($Buffer, 0, $Buffer.Length)
                }
                $Stream.Position = 0
                for ($i = 0; $i -lt 150; $i++) {
                    if ($Watch.Elapsed.TotalSeconds -ge $Duration) { break }
                    $null = $Stream.Read($Buffer, 0, $Buffer.Length)
                }
            }
        } finally {
            if ($Stream) { $Stream.Close(); $Stream.Dispose() }
            if (Test-Path $Path) { Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue }
        }
    }

    try {
        for ($d = 0; $d -lt $DiskThreads; $d++) {
            $Instance = [powershell]::Create().AddScript($DiskWorker).AddArgument($DiskDuration).AddArgument($d)
            $Instance.RunspacePool = $DiskPool
            $null = $Instance.BeginInvoke()
        }

        $DiskWatch = [System.Diagnostics.Stopwatch]::StartNew()
        while ($DiskWatch.Elapsed.TotalSeconds -lt $DiskDuration) {
            Start-Sleep -Seconds 2
            $V = Get-VitalsRealTime -BaseClock $KernelBaseClock
            if ($V) {
                $Elapsed = [math]::Round($DiskWatch.Elapsed.TotalSeconds, 0)
                $EcoData.DiskStressMetrics += [PSCustomObject]@{
                    Second             = $Elapsed
                    Disk_UsagePct      = $V.Disk_UsagePct
                    Disk_ThroughputMBs = $V.Disk_ThroughputMBs
                    Disk_Queue         = $V.Disk_Queue
                }
                Write-Host ("{0,5}s | {1,7}% | {2,7} MHz | {3,9} MB | {4,9}% | {5,7} MB/s | {6,10}" -f `
                    $Elapsed, $V.CPU_UsagePct, $V.CPU_ClockMHz, $V.Mem_AvailMB, $V.Disk_UsagePct, $V.Disk_ThroughputMBs, $V.Disk_Queue) -ForegroundColor Yellow
            }
        }
    } finally {
        $DiskPool.Close()
        $DiskPool.Dispose()
        Get-ChildItem -Path $env:TEMP -Filter "bancada_io_*.tmp" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

# 8. Recuperacao (10 segundos)
Write-Host "`n>>> [FASE 3/4] A medir recuperacao hemodinamica pos-esforco (10s)..." -ForegroundColor Yellow
Start-Sleep -Seconds 10
$Recov = Get-VitalsRealTime -BaseClock $KernelBaseClock
if ($Recov) {
    $EcoData.Recovery = [ordered]@{
        CPU_UsagePct   = $Recov.CPU_UsagePct
        CPU_ClockMHz   = $Recov.CPU_ClockMHz
        Mem_AvailMB    = $Recov.Mem_AvailMB
        Disk_UsagePct  = $Recov.Disk_UsagePct
    }
}

# 9. Deteccao de Eventos WHEA e Throttling
try {
    $ThrottleEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Id=37; StartTime=$OverallStartTime} -ErrorAction SilentlyContinue
    $WheaEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'; StartTime=$OverallStartTime} -ErrorAction SilentlyContinue

    $EcoData.HardwareEvents = [ordered]@{
        ThrottlingEventsCount = ($ThrottleEvents | Measure-Object).Count
        WHEAErrorsCount       = ($WheaEvents | Measure-Object).Count
    }
} catch {
    $EcoData.HardwareEvents = @{ Error = $_.Message }
}

# 10. Veredito Clinico Offline (ASCII Puro)
Write-Host "`n=================== RESULTADO DO ECOCARDIOGRAMA ===================" -ForegroundColor Green

$Defects = @()
$Passed = @()

if ($RunCpuTest -and $EcoData.CpuStressMetrics.Count -gt 0) {
    $Clocks = $EcoData.CpuStressMetrics.CPU_ClockMHz
    $MaxClock = ($Clocks | Measure-Object -Maximum).Maximum
    $MinClock = ($Clocks | Measure-Object -Minimum).Minimum
    $AvgClock = [int]($Clocks | Measure-Object -Average).Average

    if ($EcoData.HardwareEvents.ThrottlingEventsCount -gt 0) {
        $Defects += "[CRITICO] Throttling Termico Ativo: O firmware interveio para limitar o CPU por excesso termico."
    }
    if ($KernelBaseClock -gt 0 -and $MinClock -lt ($KernelBaseClock * 0.75)) {
        $Defects += "[ALERTA] Queda Severa de Clock: CPU caiu para $MinClock MHz (mais de 25% abaixo da base de $KernelBaseClock MHz)."
    } else {
        $Passed += "[OK] Frequencia Sustentada: Manteve curva termica saudavel (Min: $MinClock MHz | Max: $MaxClock MHz | Media: $AvgClock MHz)."
    }
}

if ($RunDiskTest -and $EcoData.DiskStressMetrics.Count -gt 0) {
    $DiskUsages = $EcoData.DiskStressMetrics.Disk_UsagePct
    $DiskMBs = $EcoData.DiskStressMetrics.Disk_ThroughputMBs
    $MaxUsage = ($DiskUsages | Measure-Object -Maximum).Maximum
    $AvgUsage = [int]($DiskUsages | Measure-Object -Average).Average
    $MaxThroughput = ($DiskMBs | Measure-Object -Maximum).Maximum
    $AvgThroughput = [math]::Round(($DiskMBs | Measure-Object -Average).Average, 1)

    if ($MaxUsage -lt 40) {
        $Defects += "[ALERTA] O disco nao atingiu niveis de saturacao esperados (Pico: $MaxUsage%)."
    } else {
        $Passed += "[OK] Saturacao de Disco Eficaz: Controladora sustentou carga pesada (Media: $AvgUsage% | Pico: $MaxUsage% | Debito Medio: $AvgThroughput MB/s)."
    }
}

if ($EcoData.HardwareEvents.WHEAErrorsCount -gt 0) {
    $Defects += "[FATAL] Erros Fisicos WHEA: Instabilidade de silicio detetada (CPU, RAM ou barramento PCIe)."
} else {
    $Passed += "[OK] Integridade de Silicio: Zero erros fisicos WHEA detetados sob esforco maximo."
}

if ($Defects.Count -gt 0) {
    Write-Host "ANOMALIAS IDENTIFICADAS:" -ForegroundColor Red
    $Defects | ForEach-Object { Write-Host "  * $_" -ForegroundColor Yellow }
    $EcoData.DiagnosticVerdict.Status = "ANORMAL"
    $EcoData.DiagnosticVerdict.Issues = $Defects
} else {
    Write-Host "SISTEMA APROVADO NA PROVA DE ESFORCO:" -ForegroundColor Green
    $Passed | ForEach-Object { Write-Host "  * $_" -ForegroundColor Gray }
    $EcoData.DiagnosticVerdict.Status = "NORMAL"
    $EcoData.DiagnosticVerdict.PassedChecks = $Passed
}
Write-Host "==================================================================" -ForegroundColor Green

# 11. Exportacao de Relatorios
$BaseName = "ECO_Report_$($env:COMPUTERNAME)_$((Get-Date).ToString('yyyyMMdd_HHmmss'))"
$JsonPath = Join-Path $OutputDir "$BaseName.json"
$TxtPath = Join-Path $OutputDir "$BaseName.txt"

$EcoData | ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonPath -Encoding ascii

$SummaryText = @"
==================================================================
RELATORIO DO ECOCARDIOGRAMA DE SISTEMA (PROVA DE ESFORCO)
Computador        : $($env:COMPUTERNAME)
Data/Hora         : $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
Processador       : $CpuModel ($LogicalCores Threads)
Clock Base        : $KernelBaseClock MHz
Status Final      : $($EcoData.DiagnosticVerdict.Status)
==================================================================

1. SINAIS VITAIS EM REPOUSO (BASELINE):
- Clock em Repouso : $($EcoData.Baseline.CPU_IdleClockMHz) MHz
- CPU Uso Repouso  : $($EcoData.Baseline.CPU_IdleUsagePct)%
- RAM Livre        : $($EcoData.Baseline.FreeRAM_MB) MB
- Disco Uso Repouso: $($EcoData.Baseline.Disk_IdleUsagePct)%

2. PROVA DE ESFORCO DE CPU (Fase 1: $(if($RunCpuTest){"$CpuDuration s"}else{"IGNORADA"})):
- Clock Minimo em Carga : $(if($RunCpuTest){"$MinClock MHz"}else{"N/A"})
- Clock Medio em Carga  : $(if($RunCpuTest){"$AvgClock MHz"}else{"N/A"})
- Clock Maximo em Carga : $(if($RunCpuTest){"$MaxClock MHz"}else{"N/A"})
- Eventos Throttling    : $($EcoData.HardwareEvents.ThrottlingEventsCount)
- Eventos WHEA          : $($EcoData.HardwareEvents.WHEAErrorsCount)

3. PROVA DE ESFORCO DE DISCO (Fase 2: $(if($RunDiskTest){"$DiskDuration s"}else{"IGNORADA"})):
- Uso Medio de Disco    : $(if($RunDiskTest){"$AvgUsage%"}else{"N/A"})
- Pico de Uso de Disco  : $(if($RunDiskTest){"$MaxUsage%"}else{"N/A"})
- Debito Medio de Disco : $(if($RunDiskTest){"$AvgThroughput MB/s"}else{"N/A"})
- Pico de Debito Disco  : $(if($RunDiskTest){"$MaxThroughput MB/s"}else{"N/A"})

4. RECUPERACAO HEMODINAMICA (Pos-teste):
- Clock Recuperado : $($EcoData.Recovery.CPU_ClockMHz) MHz
- CPU Utilizacao   : $($EcoData.Recovery.CPU_UsagePct)%
- RAM Disponivel   : $($EcoData.Recovery.Mem_AvailMB) MB

5. PARECER CLINICO OFFLINE:
$((($Defects + $Passed) | ForEach-Object { "- $_" }) -join "`n")
==================================================================
"@

$SummaryText | Out-File -FilePath $TxtPath -Encoding ascii

Write-Host "`n>>> Relatorio de texto guardado em : $TxtPath" -ForegroundColor Cyan
Write-Host ">>> Telemetria JSON guardada em    : $JsonPath`n" -ForegroundColor Cyan