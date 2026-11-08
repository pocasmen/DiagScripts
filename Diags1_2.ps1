<#
.SYNOPSIS
    ECG-Diagnostic-v2.1.ps1 - Agente de Triagem e Diagnostico Clinico Windows
.DESCRIPTION
    Versao 2.1 com analise completa e agnostica (testa sempre todos os componentes),
    suporte a Schema 2.1, separacao de falhas fisicas vs logicas de storage, auditoria
    de Kernel-Power 41 (BugCheck vs Corte Eletrico), Minidumps, indice de fiabilidade,
    amostragem delta real de CPU e calculo ponderado de HealthScore.
    Formato: ASCII puro (sem caracteres latinos) compativel com qualquer SO.
#>

[CmdletBinding()]
param (
    [string]$Issue = "",
    [switch]$DeepIntegrity,
    [string]$OutputDir = "."
)

# 0. Configuracao de Consola e Permissoes
[Console]::OutputEncoding = [System.Text.Encoding]::ASCII
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ([string]::IsNullOrWhiteSpace($Issue)) {
    Clear-Host
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "     ECG DIAGNOSTIC v2.1 - TRIAGEM CLINICA UNIVERSAL      " -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    $Issue = Read-Host "`nQueixa do cliente / Sintoma reportado"
    if ([string]::IsNullOrWhiteSpace($Issue)) { $Issue = "Revisao preventiva geral" }
}

$Watch = [System.Diagnostics.Stopwatch]::StartNew()
Write-Host "`n>>> [1/8] A iniciar amostragem delta de processos (T0)..." -ForegroundColor Yellow

# Estrutura Central com Schema Version
$Report = [ordered]@{
    SchemaVersion           = "2.1"
    DiagnosticEngine        = "ECG-Universal"
    DiagnosticEngineVersion = "2.1.0"
    Metadata = [ordered]@{
        ComputerName   = $env:COMPUTERNAME
        Timestamp      = (Get-Date).ToString("o")
        IssueReported  = $Issue
        RanAsAdmin     = $IsAdmin
        DeepIntegrity  = [bool]$DeepIntegrity
    }
    HealthScore = [ordered]@{
        Overall  = 100
        Hardware = 100
        Storage  = 100
        Memory   = 100
        Windows  = 100
        Network  = 100
    }
    Facts = [ordered]@{}
    Findings = @()
    RecommendedActions = @()
}

# Funcao de Registo de Diagnostico e Calculo Ponderado de Score
function Add-Finding {
    param(
        [string]$Category,
        [ValidateSet("Critical", "Warning", "Info")][string]$Severity,
        [double]$Confidence,
        [string]$Finding,
        [string]$Evidence,
        [string]$Action,
        [int]$ImpactWeight = 1
    )
    $script:Report.Findings += [PSCustomObject]@{
        Category          = $Category
        Severity          = $Severity
        Confidence        = $Confidence
        Finding           = $Finding
        Evidence          = $Evidence
        RecommendedAction = $Action
    }
    if ($Action -and ($script:Report.RecommendedActions -notcontains $Action)) {
        $script:Report.RecommendedActions += $Action
    }

    # Calculo ponderado do score para evitar quebras em cascata
    $BasePenalty = switch ($Severity) { "Critical" { 20 } "Warning" { 10 } default { 0 } }
    $CalculatedPenalty = [math]::Round($BasePenalty * $Confidence * ($ImpactWeight / 2.0), 0)

    if ($script:Report.HealthScore.Contains($Category)) {
        $script:Report.HealthScore[$Category] = [math]::Max(0, $script:Report.HealthScore[$Category] - $CalculatedPenalty)
    }
    $OverallPenalty = [math]::Round($CalculatedPenalty * 0.6, 0)
    $script:Report.HealthScore.Overall = [math]::Max(0, $script:Report.HealthScore.Overall - $OverallPenalty)
}

# 1. Ponto de Amostragem T0 de Processos
$LogicalCores = [Environment]::ProcessorCount
$ProcSampleT0 = Get-Process | Select-Object Id, ProcessName, CPU
$TimeT0 = [System.Diagnostics.Stopwatch]::GetTimestamp()

# 2. Hardware Base, Processador e Sensores Termicos
Write-Host " [2/8] A recolher sinais vitais de processador, bios e termicos..." -ForegroundColor Gray
$CpuCim = Get-CimInstance Win32_Processor | Select-Object -First 1
$OS = Get-CimInstance Win32_OperatingSystem
$CS = Get-CimInstance Win32_ComputerSystem
$BIOS = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue

$KernelBaseClock = try {
    (Get-ItemProperty -Path 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0' -ErrorAction Stop).'~MHz'
} catch { [int]$CpuCim.MaxClockSpeed }

$CpuMetric = Get-CimInstance -ClassName Win32_PerfFormattedData_Counters_ProcessorInformation -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "*_Total" } | Select-Object -First 1

$PerformancePct = if ($CpuMetric.PercentProcessorPerformance) { [double]$CpuMetric.PercentProcessorPerformance } else { $null }
$CpuTotalUsage = if ($CpuMetric.PercentProcessorUtility) { [math]::Min(100, [int]$CpuMetric.PercentProcessorUtility) } else { [int]$CpuCim.LoadPercentage }

# Deteccao Honesta de Zona Termica ACPI
$ThermalZoneC = $null
try {
    $Thermal = Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($Thermal -and $Thermal.CurrentTemperature -gt 2732) {
        $ThermalZoneC = [math]::Round(($Thermal.CurrentTemperature - 2732) / 10, 1)
    }
} catch { }

# Bateria (se presente)
$Battery = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
$BatteryStatus = if ($Battery) {
    @{ Present = $true; ChargePercent = $Battery.EstimatedChargeRemaining; Status = $Battery.BatteryStatus }
} else { @{ Present = $false } }

# Reinicios Pendentes
$RebootPending = $false
$RebootReasons = @()
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
    $RebootPending = $true; $RebootReasons += "CBS_RebootPending"
}
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
    $RebootPending = $true; $RebootReasons += "WindowsUpdate_RebootRequired"
}
$FileRename = try { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ErrorAction SilentlyContinue).PendingFileRenameOperations } catch { $null }
if ($FileRename) { $RebootPending = $true; $RebootReasons += "PendingFileRenameOperations" }

$Report.Facts.System = [ordered]@{
    ComputerName          = $env:COMPUTERNAME
    Manufacturer          = $CS.Manufacturer.Trim()
    Model                 = $CS.Model.Trim()
    OSCaption             = $OS.Caption.Trim()
    OSBuild               = $OS.BuildNumber
    UptimeDays            = [math]::Round(((Get-Date) - $OS.LastBootUpTime).TotalDays, 2)
    RebootPending         = $RebootPending
    RebootReasons         = ($RebootReasons -join ", ")
    CPUModel              = $CpuCim.Name.Trim()
    LogicalCores          = $LogicalCores
    BaseClockMHz          = $KernelBaseClock
    PerformancePct        = $PerformancePct
    CPUUsagePct           = $CpuTotalUsage
    ThermalZone_ACPI_C    = $ThermalZoneC
    BIOSVersion           = if ($BIOS) { $BIOS.SMBIOSBIOSVersion } else { "N/A" }
    Battery               = $BatteryStatus
}

# 3. Memoria RAM (Disponibilidade Real, Commit e Pools)
Write-Host " [3/8] A recolher metricas de memoria, commit e pools de kernel..." -ForegroundColor Gray
$PerfMem = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory -ErrorAction SilentlyContinue
$TotalRamMB = [int][math]::Round($OS.TotalVisibleMemorySize / 1024, 0)
$AvailRamMB = [int][math]::Round($OS.FreePhysicalMemory / 1024, 0)
$UsedRamMB = $TotalRamMB - $AvailRamMB
$CommitTotalMB = if ($PerfMem) { [int][math]::Round($PerfMem.CommittedBytes / 1MB, 0) } else { 0 }
$CommitLimitMB = if ($PerfMem) { [int][math]::Round($PerfMem.CommitLimit / 1MB, 0) } else { 0 }
$PoolPagedMB   = if ($PerfMem) { [int][math]::Round($PerfMem.PoolPagedBytes / 1MB, 0) } else { 0 }
$PoolNonPagedMB= if ($PerfMem) { [int][math]::Round($PerfMem.PoolNonpagedBytes / 1MB, 0) } else { 0 }

$Report.Facts.Memory = [ordered]@{
    TotalRAM_MB       = $TotalRamMB
    AvailableRAM_MB   = $AvailRamMB
    UsedRAM_Pct       = [math]::Round(($UsedRamMB / $TotalRamMB) * 100, 1)
    Committed_MB      = $CommitTotalMB
    CommitLimit_MB    = $CommitLimitMB
    CommitUtilization = if ($CommitLimitMB -gt 0) { [math]::Round(($CommitTotalMB / $CommitLimitMB) * 100, 1) } else { 0 }
    PoolPaged_MB      = $PoolPagedMB
    PoolNonPaged_MB   = $PoolNonPagedMB
    PageFileActive    = [bool](Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue)
}

# 4. Armazenamento: Discos Fisicos e Volumes
Write-Host " [4/8] A mapear topologia de discos, controladores e espaco livre..." -ForegroundColor Gray
$Disks = Get-PhysicalDisk -ErrorAction SilentlyContinue
$DiskList = @()
foreach ($d in $Disks) {
    $Reliability = if ($IsAdmin) { Get-StorageReliabilityCounter -PhysicalDisk $d -ErrorAction SilentlyContinue } else { $null }
    $DiskList += [ordered]@{
        DeviceId           = $d.DeviceId
        FriendlyName       = $d.FriendlyName.Trim()
        MediaType          = $d.MediaType
        BusType            = $d.BusType
        HealthStatus       = $d.HealthStatus
        OperationalStatus  = ($d.OperationalStatus -join ", ")
        SizeGB             = [math]::Round($d.Size / 1GB, 1)
        TemperatureC       = if ($Reliability) { $Reliability.Temperature } else { "N/A" }
        WearPercentage     = if ($Reliability -and $null -ne $Reliability.Wear) { $Reliability.Wear } else { "N/A" }
        ReadErrorsTotal    = if ($Reliability) { $Reliability.ReadErrorsTotal } else { $null }
        WriteErrorsTotal   = if ($Reliability) { $Reliability.WriteErrorsTotal } else { $null }
    }
}
$Report.Facts.PhysicalDisks = $DiskList

$Report.Facts.Volumes = Get-Volume -ErrorAction SilentlyContinue |
    Where-Object { $_.DriveLetter -and $_.Size -gt 0 } |
    Select-Object DriveLetter, FileSystemLabel, FileSystem,
        @{N="SizeGB"; E={[math]::Round($_.Size / 1GB, 1)}},
        @{N="FreeGB"; E={[math]::Round($_.SizeRemaining / 1GB, 1)}},
        @{N="FreePct"; E={[math]::Round(($_.SizeRemaining / $_.Size) * 100, 1)}}

# 5. Auditoria de Minidumps e Estabilidade
Write-Host " [5/8] A verificar minidumps de BSOD e indice de fiabilidade do sistema..." -ForegroundColor Gray
$MinidumpFolder = "$env:SystemRoot\Minidump"
$DumpFiles = if (Test-Path $MinidumpFolder) { Get-ChildItem -Path $MinidumpFolder -Filter "*.dmp" -ErrorAction SilentlyContinue } else { @() }
$DumpCount = @($DumpFiles).Count
$LatestDumpDate = if ($DumpCount -gt 0) {
    ($DumpFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
} else { "Nenhum" }

$RelMetric = Get-CimInstance Win32_ReliabilityStabilityMetrics -ErrorAction SilentlyContinue | Sort-Object TimeGenerated -Descending | Select-Object -First 1
$StabilityIndex = if ($RelMetric) { [math]::Round($RelMetric.SystemStabilityIndex, 1) } else { "N/A" }

$Report.Facts.CrashDumps = [ordered]@{
    MinidumpCount         = $DumpCount
    LatestMinidumpDate    = $LatestDumpDate
    SystemStabilityIndex  = $StabilityIndex
}

# 6. Diagnostico Escalonado de Rede e Wi-Fi
Write-Host " [6/8] A auditar conectividade de rede (Gateway, DNS e Porta 443)..." -ForegroundColor Gray
$ActiveAdapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
$NetFacts = [ordered]@{
    AdapterActive  = if ($ActiveAdapter) { $ActiveAdapter.InterfaceAlias } else { "Nenhum" }
    LinkSpeed      = if ($ActiveAdapter) { $ActiveAdapter.LinkSpeed } else { "N/A" }
    GatewayPing    = $false
    DNSResolution  = $false
    InternetHttp   = $false
    WiFiDetails    = $null
}

if ($ActiveAdapter) {
    $GatewayIP = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $ActiveAdapter.InterfaceIndex -ErrorAction SilentlyContinue).NextHop
    if ($GatewayIP) {
        $NetFacts.GatewayPing = Test-Connection -ComputerName $GatewayIP -Count 1 -Quiet -ErrorAction SilentlyContinue
    }
    try {
        $dnsTest = [System.Net.Dns]::GetHostAddresses("www.microsoft.com")
        if ($dnsTest) { $NetFacts.DNSResolution = $true }
    } catch { }
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $iar = $tcpClient.BeginConnect("1.1.1.1", 443, $null, $null)
        $success = $iar.AsyncWaitHandle.WaitOne(2000, $false)
        if ($success -and $tcpClient.Connected) {
            $NetFacts.InternetHttp = $true
            $tcpClient.EndConnect($iar)
        }
        $tcpClient.Close()
        $tcpClient.Dispose()
    } catch { }
}

$WlanRaw = netsh wlan show interfaces 2>$null
if ($WlanRaw) {
    $SSID = ($WlanRaw | Select-String "SSID\s+:" | Select-Object -First 1) -replace ".*:\s*", ""
    $Signal = ($WlanRaw | Select-String "Sinal\s+:|Signal\s+:" | Select-Object -First 1) -replace ".*:\s*", ""
    $Radio = ($WlanRaw | Select-String "Tipo de r.*dio\s+:|Radio type\s+:" | Select-Object -First 1) -replace ".*:\s*", ""
    if ($SSID) {
        $NetFacts.WiFiDetails = @{ SSID = $SSID.Trim(); Signal = $Signal.Trim(); RadioType = $Radio.Trim() }
    }
}
$Report.Facts.Network = $NetFacts

# 7. Servicos, Atualizacoes e Integridade Windows
Write-Host " [7/8] A inspecionar servicos de arranque automatico e DISM..." -ForegroundColor Gray
$Report.Facts.FaultedServices = Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' } |
    Select-Object -First 6 Name, DisplayName, Status, StartType

$RecentUpdates = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 3
$Report.Facts.RecentHotfixes = $RecentUpdates | Select-Object HotFixID, Description, InstalledOn

$DismHealth = "Nao verificado"
try {
    $dismOut = DISM.exe /Online /Cleanup-Image /CheckHealth 2>$null | Out-String
    if ($dismOut -match "No component store corruption detected|Nenhuma corrup") {
        $DismHealth = "Saudavel"
    } elseif ($dismOut -match "repairable|repar") {
        $DismHealth = "Corrompido (Reparavel)"
    }
} catch { }
$Report.Facts.ComponentStoreHealth = $DismHealth

if ($DeepIntegrity) {
    Write-Host "    [DeepIntegrity] A executar SFC /verifyonly (pode demorar 1-3 min)..." -ForegroundColor Yellow
    $sfcOut = sfc.exe /verifyonly 2>$null | Out-String
    $Report.Facts.SFC_Status = if ($sfcOut -match "did not find any integrity violations") { "Integro" } else { "Violacoes Encontradas" }
}

$Report.Facts.StartupItems = Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue |
    Select-Object Name, Command, Location, User

# 8. Amostragem Delta T1 e Calculo de CPU Instantaneo
Write-Host " [8/8] A finalizar delta de CPU (T1) e a correlacionar eventos de kernel..." -ForegroundColor Gray
$ProcSampleT1 = Get-Process | Select-Object Id, ProcessName, CPU, Path, Company, Description
$TimeT1 = [System.Diagnostics.Stopwatch]::GetTimestamp()
$TimeDeltaSeconds = ($TimeT1 - $TimeT0) / [System.Diagnostics.Stopwatch]::Frequency

$RealCpuHogs = @()
foreach ($p1 in $ProcSampleT1) {
    if ($null -eq $p1.CPU) { continue }
    $p0 = $ProcSampleT0 | Where-Object { $_.Id -eq $p1.Id }
    if ($p0 -and $null -ne $p0.CPU) {
        $CpuTimeDelta = $p1.CPU - $p0.CPU
        if ($CpuTimeDelta -gt 0) {
            $InstantUsage = ($CpuTimeDelta / ($TimeDeltaSeconds * $LogicalCores)) * 100
            if ($InstantUsage -ge 1.0) {
                $RealCpuHogs += [PSCustomObject]@{
                    Id           = $p1.Id
                    ProcessName  = $p1.ProcessName
                    InstantCPU   = [math]::Round($InstantUsage, 1)
                    Company      = if ($p1.Company) { $p1.Company.Trim() } else { "N/A" }
                    Description  = if ($p1.Description) { $p1.Description.Trim() } else { "N/A" }
                    Path         = if ($p1.Path) { $p1.Path } else { "N/A" }
                }
            }
        }
    }
}
$Report.Facts.TopRealTimeCPU = $RealCpuHogs | Sort-Object InstantCPU -Descending | Select-Object -First 5

# 9. Analise Aprofundada e Normalizada do Event Log (Ultimas 72h)
$ThreeDaysAgo = (Get-Date).AddDays(-3)
$Report.Facts.AggregatedEvents = [ordered]@{}

try {
    # 9.1 Falhas Fisicas de Controlador/Storage (disk, stornvme, storahci, iaStor)
    $PhysicalStorageProviders = @('disk', 'stornvme', 'storahci', 'iaStorA', 'iaStorAVC')
    $RawPhysEvents = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = $PhysicalStorageProviders
        Level        = 1, 2, 3
        StartTime    = $ThreeDaysAgo
    } -ErrorAction SilentlyContinue

    $PhysGrouped = @($RawPhysEvents | Group-Object ProviderName, Id | Select-Object Count, Name)
    $Report.Facts.AggregatedEvents.PhysicalStorageErrors = $PhysGrouped

    # 9.2 Falhas Logicas de Sistema de Ficheiros (Ntfs, volmgr)
    $LogicalStorageProviders = @('Ntfs', 'volmgr')
    $RawLogEvents = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = $LogicalStorageProviders
        Level        = 1, 2, 3
        StartTime    = $ThreeDaysAgo
    } -ErrorAction SilentlyContinue

    $LogGrouped = @($RawLogEvents | Group-Object ProviderName, Id | Select-Object Count, Name)
    $Report.Facts.AggregatedEvents.LogicalFilesystemErrors = $LogGrouped

    # 9.3 Erros WHEA (Hardware/Silicio)
    $WheaEvents = @(Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = 'Microsoft-Windows-WHEA-Logger'
        StartTime    = $ThreeDaysAgo
    } -ErrorAction SilentlyContinue | Group-Object Id | Select-Object Count, Name)
    $Report.Facts.AggregatedEvents.WHEA = $WheaEvents

    # 9.4 Kernel-Power 41 Pormenorizado (BSOD vs Corte Eletrico)
    $KP41Raw = @(Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Id        = 41
        StartTime = $ThreeDaysAgo
    } -ErrorAction SilentlyContinue)

    $KP41Total = $KP41Raw.Count
    $KP41WithBugcheck = 0
    $KP41DirtyPower = 0

    foreach ($evt in $KP41Raw) {
        $xml = [xml]$evt.ToXml()
        $bc = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'BugcheckCode' } | Select-Object -ExpandProperty '#text'
        if ($bc -and [int64]$bc -ne 0) { $KP41WithBugcheck++ } else { $KP41DirtyPower++ }
    }

    $Report.Facts.AggregatedEvents.KernelPower41 = [ordered]@{
        TotalCount        = $KP41Total
        CrashesWithBugcheck = $KP41WithBugcheck
        DirtyPowerLosses  = $KP41DirtyPower
    }

    # 9.5 Resource-Exhaustion 2004
    $ResExCount = @(Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Id        = 2004
        StartTime = $ThreeDaysAgo
    } -ErrorAction SilentlyContinue).Count
    $Report.Facts.AggregatedEvents.ResourceExhaustion_Count = $ResExCount

} catch { }

# =========================================================================
# MOTOR HEURISTICO LOCAL (AVALIACAO ROBUSTA DE EVIDENCIAS)
# =========================================================================

# CPU e Temperatura
if ($CpuTotalUsage -ge 85) {
    $hog = $Report.Facts.TopRealTimeCPU | Select-Object -First 1
    Add-Finding "Hardware" "Critical" 0.95 "Saturacao de CPU em Tempo Real" `
        "Utilizacao em $($CpuTotalUsage)%. Processo topo: $($hog.ProcessName) ($($hog.InstantCPU)% real)." `
        "Investigar/terminar o processo $($hog.ProcessName) ($($hog.Path))." 2
}
if ($ThermalZoneC -and $ThermalZoneC -ge 88) {
    Add-Finding "Hardware" "Warning" 0.85 "Temperatura Termica ACPI Elevada" `
        "Sonda ACPI reportou $($ThermalZoneC) C em repouso/carga de exame." `
        "Inspecionar saidas de ar, ventoinhas e considerar manutencao termica." 1
}

# Armazenamento: Volumes
foreach ($vol in $Report.Facts.Volumes) {
    if ($vol.FreePct -lt 10) {
        Add-Finding "Storage" "Critical" 0.98 "Volume $($vol.DriveLetter) em Esgotamento Critico" `
            "Apenas $($vol.FreeGB) GB disponiveis ($($vol.FreePct)% livres)." `
            "Libertar espaco no volume $($vol.DriveLetter) de imediato." 2
    } elseif ($vol.FreePct -lt 15) {
        Add-Finding "Storage" "Warning" 0.85 "Volume $($vol.DriveLetter) com Espaco Reduzido" `
            "Volume com $($vol.FreePct)% de espaco livre." `
            "Executar limpeza de disco (cleanmgr) e descarregar ficheiros temporarios." 1
    }
}

# Armazenamento: Falhas Fisicas vs Logicas (Sem bugs de contagem)
if (@($Report.Facts.AggregatedEvents.PhysicalStorageErrors).Count -gt 0) {
    $names = ($Report.Facts.AggregatedEvents.PhysicalStorageErrors | ForEach-Object { "$($_.Name) (x$($_.Count))" }) -join ", "
    Add-Finding "Storage" "Critical" 0.92 "Erros no Barramento ou Controlador de Armazenamento" `
        "Detetadas falhas fisicas nas ultimas 72h: $names." `
        "Executar exame Ecocardiograma de disco e inspecionar integridade/cabo do SSD/HDD." 2
}
if (@($Report.Facts.AggregatedEvents.LogicalFilesystemErrors).Count -gt 0) {
    $names = ($Report.Facts.AggregatedEvents.LogicalFilesystemErrors | ForEach-Object { "$($_.Name) (x$($_.Count))" }) -join ", "
    Add-Finding "Storage" "Warning" 0.80 "Erros Lógicos no Sistema de Ficheiros (NTFS/volmgr)" `
        "Detetados eventos de sistema de ficheiros: $names." `
        "Agendar chkdsk no volume correspondente para verificar metadados NTFS." 1
}

# Memoria RAM
if ($AvailRamMB -lt 1024) {
    Add-Finding "Memory" "Critical" 0.95 "Memoria Fisica Quase Esgotada" `
        "Apenas $AvailRamMB MB de RAM disponivel ($($Report.Facts.Memory.UsedRAM_Pct)% em uso)." `
        "Verificar processos em fuga de memoria ou considerar expansao de RAM." 2
}
if ($Report.Facts.Memory.CommitUtilization -gt 85) {
    Add-Finding "Memory" "Warning" 0.85 "Commit Limit Sob Pressao" `
        "Memoria comprometida em $($Report.Facts.Memory.CommitUtilization)% do limite." `
        "Garantir Pagefile adequado gerido pelo sistema." 1
}
if ($Report.Facts.AggregatedEvents.ResourceExhaustion_Count -gt 0) {
    Add-Finding "Memory" "Critical" 0.90 "Historico Recente de Esgotamento de Recursos (Event 2004)" `
        "$($Report.Facts.AggregatedEvents.ResourceExhaustion_Count) eventos de Resource-Exhaustion registados." `
        "Verificar configuracao de memoria virtual." 2
}

# Kernel-Power 41 Nuancado
if ($Report.Facts.AggregatedEvents.KernelPower41.TotalCount -ge 2) {
    $kp = $Report.Facts.AggregatedEvents.KernelPower41
    if ($kp.CrashesWithBugcheck -gt 0) {
        Add-Finding "Hardware" "Critical" 0.90 "Reinicios por Ecrã Azul / BugCheck Detetados" `
            "$($kp.CrashesWithBugcheck) falhas com Bugcheck registadas no Kernel-Power." `
            "Analisar ficheiros Minidump em C:\Windows\Minidump para isolar o driver causador." 2
    }
    if ($kp.DirtyPowerLosses -gt 0) {
        Add-Finding "Hardware" "Warning" 0.75 "Desligamentos Abruptos / Perda de Energia" `
            "$($kp.DirtyPowerLosses) cortes sem registo de Bugcheck (possivel corte eletrico ou botao de desligar forçado)." `
            "Testar estabilidade da fonte de alimentacao (PSU), bateria e circuitos de energia." 1
    }
}

# Minidumps Existentes
if ($DumpCount -gt 0) {
    Add-Finding "Windows" "Warning" 0.88 "Historico de Crash Dumps Presente" `
        "Existem $DumpCount ficheiro(s) minidump. O mais recente e de $LatestDumpDate." `
        "Examinar minidumps com WinDbg ou BlueScreenView se houver queixas de instabilidade." 1
}

# Integridade do Sistema Operativo
if ($RebootPending) {
    Add-Finding "Windows" "Warning" 0.95 "Reinicio Pendente por Atualizacoes" `
        "Motivo(s): $($Report.Facts.System.RebootReasons)." `
        "Reiniciar o equipamento para concluir o ciclo de atualizacoes pendentes." 1
}
if ($Report.Facts.ComponentStoreHealth -eq "Corrompido (Reparavel)") {
    Add-Finding "Windows" "Critical" 0.90 "Corrupcao no Component Store do Windows" `
        "DISM CheckHealth reportou pacotes danificados." `
        "Executar: DISM /Online /Cleanup-Image /RestoreHealth." 2
}
if (@($Report.Facts.AggregatedEvents.WHEA).Count -gt 0) {
    Add-Finding "Hardware" "Critical" 0.98 "Erros Fisicos de Arquitetura WHEA" `
        "Registo de eventos WHEA de hardware detetados." `
        "Inspecionar instabilidade em processador, memorias ou barramento PCIe." 2
}

# Rede
if ($Report.Facts.Network.AdapterActive -eq "Nenhum") {
    Add-Finding "Network" "Critical" 1.0 "Sem Adaptadores de Rede com Link Ativo" `
        "Nao existem placas Ethernet ou Wi-Fi ativas." `
        "Verificar ligacao fisica de rede ou comutador de radio Wi-Fi." 2
} elseif (-not $Report.Facts.Network.DNSResolution -and $Report.Facts.Network.GatewayPing) {
    Add-Finding "Network" "Critical" 0.95 "Falha na Resolucao de Nomes DNS" `
        "Gateway local responde a ping, mas a resolucao externa de nomes falhou." `
        "Limpar cache DNS (ipconfig /flushdns) ou redefinir servidores para 1.1.1.1 / 8.8.8.8." 2
} elseif (-not $Report.Facts.Network.InternetHttp -and $Report.Facts.Network.GatewayPing) {
    Add-Finding "Network" "Warning" 0.85 "Acesso a Porta Web Externa Bloqueado" `
        "Rede local OK, mas ligacao TCP 443 falhou." `
        "Verificar definicoes de firewall, proxy ou bloqueio no router." 1
}

$Watch.Stop()
$Report.Metadata.DurationSeconds = [math]::Round($Watch.Elapsed.TotalSeconds, 2)

# =========================================================================
# APRESENTACAO NO TERMINAL E EXPORTACAO
# =========================================================================
Clear-Host
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         PARECER CLINICO DO ECG (TRIAGEM LOCAL)           " -ForegroundColor Cyan
Write-Host "   Schema: v$($Report.SchemaVersion) | Tempo: $($Report.Metadata.DurationSeconds)s | Queixa: $Issue" -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Cyan

Write-Host "`nPONTUACAO DE SAUDE PONDERADA (0-100):" -ForegroundColor White
$ScoreColor = if ($Report.HealthScore.Overall -ge 80) { "Green" } elseif ($Report.HealthScore.Overall -ge 50) { "Yellow" } else { "Red" }
Write-Host "  GLOBAL   : $($Report.HealthScore.Overall)/100" -ForegroundColor $ScoreColor
Write-Host "  Hardware : $($Report.HealthScore.Hardware) | Storage : $($Report.HealthScore.Storage) | RAM : $($Report.HealthScore.Memory)" -ForegroundColor Gray
Write-Host "  Windows  : $($Report.HealthScore.Windows)  | Rede    : $($Report.HealthScore.Network)" -ForegroundColor Gray

Write-Host "`nDIAGNOSTICOS E EVIDENCIAS ($($Report.Findings.Count)):" -ForegroundColor White
if ($Report.Findings.Count -eq 0) {
    Write-Host "  [OK] Nenhuma anomalia critica identificada nos sinais vitais." -ForegroundColor Green
} else {
    foreach ($f in $Report.Findings) {
        $color = if ($f.Severity -eq "Critical") { "Red" } elseif ($f.Severity -eq "Warning") { "Yellow" } else { "Cyan" }
        Write-Host "  [$($f.Severity)] $($f.Category): $($f.Finding)" -ForegroundColor $color
        Write-Host "    Evidencia : $($f.Evidence)" -ForegroundColor Gray
        Write-Host "    Acao      : $($f.RecommendedAction)" -ForegroundColor DarkCyan
    }
}

if ($Report.RecommendedActions.Count -gt 0) {
    Write-Host "`nPLANO DE INTERVENCAO PROPOSTO:" -ForegroundColor Yellow
    foreach ($act in $Report.RecommendedActions) {
        Write-Host "  [ ] $act" -ForegroundColor White
    }
}
Write-Host "==========================================================" -ForegroundColor Cyan

# Gravacao dos Ficheiros
$TimeStampStr = (Get-Date).ToString('yyyyMMdd_HHmmss')
$BaseName = "ECG_v21_$($env:COMPUTERNAME)_$TimeStampStr"
$JsonPath = Join-Path $OutputDir "$BaseName.json"
$TxtPath = Join-Path $OutputDir "$BaseName.txt"

$Report | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonPath -Encoding ascii

$ReportText = @"
==================================================================
RELATORIO CLINICO DE TRIAGEM (ECG v2.1)
Computador : $($env:COMPUTERNAME)
Data/Hora  : $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
Queixa     : $Issue
Duracao    : $($Report.Metadata.DurationSeconds) segundos
Schema     : v$($Report.SchemaVersion)
==================================================================

SCORES DE SAUDE PONDERADOS:
- Global   : $($Report.HealthScore.Overall)/100
- Hardware : $($Report.HealthScore.Hardware)/100
- Storage  : $($Report.HealthScore.Storage)/100
- Memoria  : $($Report.HealthScore.Memory)/100
- Windows  : $($Report.HealthScore.Windows)/100
- Rede     : $($Report.HealthScore.Network)/100

FINDINGS ($($Report.Findings.Count)):
$((($Report.Findings) | ForEach-Object { "[$($_.Severity)] ($($_.Category)) $($_.Finding)`n  Evidencia: $($_.Evidence)`n  Acao     : $($_.RecommendedAction)" }) -join "`n`n")

PLANO DE ACAO RECOMENDADO:
$((($Report.RecommendedActions) | ForEach-Object { "- $_" }) -join "`n")
==================================================================
"@
$ReportText | Out-File -FilePath $TxtPath -Encoding ascii

Write-Host "`nRelatorio de texto gravado em : $TxtPath" -ForegroundColor Cyan
Write-Host "Payload JSON para o Agente    : $JsonPath`n" -ForegroundColor Cyan