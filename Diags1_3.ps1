<#
.SYNOPSIS
    ECG-Diagnostic-v2.2.ps1 - Agente de Triagem e Diagnostico Clinico Windows
.DESCRIPTION
    Versao 2.2. Evolucao da v2.1 com correcoes de falsos positivos e novas regras:
      - RAM: usa memoria DISPONIVEL (AvailableMBytes) em vez de FreePhysicalMemory
      - CPU: janela de amostragem curta e dedicada, media de varias leituras, exclui o proprio processo
      - Eventos: Kernel-Power 41 e Resource-Exhaustion 2004 filtrados por provider;
        erros de leitura do Event Log ficam registados em Facts.CollectionErrors
      - WHEA: separa erros fatais (Level 1/2) de erros corrigidos; IDs na evidencia
      - Discos: avalia HealthStatus, OperationalStatus, Wear, temperatura e erros nao corrigidos
      - DISM: Repair-WindowsImage (sem depender do idioma). SFC: estado "Indeterminado" quando nao e fiavel
      - Rede: adaptador escolhido pela rota por defeito; DNS e TCP 443 testados sempre
      - Sem admin: finding Info a avisar que os resultados sao parciais
      - Volumes: apenas discos fixos; limiares combinam percentagem e GB livres
    Codigo-fonte em ASCII puro. Os relatorios (JSON e TXT) sao gravados em UTF-8.
    Os valores de Confidence sao constantes heuristicas atribuidas manualmente, nao medicoes.
.PARAMETER Issue
    Sintoma reportado pelo cliente. Se omitido, e pedido interativamente.
.PARAMETER DeepIntegrity
    Executa tambem SFC /verifyonly (requer admin, pode demorar 1-3 min).
.PARAMETER OutputDir
    Pasta de saida. Por defeito: pasta do script; se nao existir, o Ambiente de Trabalho.
.PARAMETER EventDays
    Janela de analise do Event Log em dias (1-30). Por defeito 3.
#>

[CmdletBinding()]
param (
    [string]$Issue = "",
    [switch]$DeepIntegrity,
    [string]$OutputDir = "",
    [ValidateRange(1, 30)][int]$EventDays = 3
)

$ScriptVersion = "2.2"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$DiagErrors = New-Object System.Collections.Generic.List[string]

# --------------------------------------------------------------------------
# Funcoes auxiliares
# --------------------------------------------------------------------------

# Registo de Diagnostico e Calculo Ponderado de Score
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

    $BasePenalty = switch ($Severity) { "Critical" { 20 } "Warning" { 10 } default { 0 } }
    $CalculatedPenalty = [math]::Round($BasePenalty * $Confidence * ($ImpactWeight / 2.0), 0)

    if ($script:Report.HealthScore.Contains($Category)) {
        $script:Report.HealthScore[$Category] = [math]::Max(0, $script:Report.HealthScore[$Category] - $CalculatedPenalty)
    }
    $OverallPenalty = [math]::Round($CalculatedPenalty * 0.6, 0)
    $script:Report.HealthScore.Overall = [math]::Max(0, $script:Report.HealthScore.Overall - $OverallPenalty)
}

# Leitura segura do Event Log: "sem eventos" devolve lista vazia; erros reais ficam registados
function Get-EventsSafe {
    param([hashtable]$Filter, [string]$Label)
    try {
        Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            $script:DiagErrors.Add("EventLog[$Label]: $($_.Exception.Message)")
        }
        @()
    }
}

# Extrai um campo de uma saida de texto (ex.: netsh) por regex com 1 grupo de captura
function Get-TextField {
    param($Lines, [string]$Pattern)
    foreach ($l in @($Lines)) {
        if ("$l" -match $Pattern) { return $Matches[1].Trim() }
    }
    return $null
}

# --------------------------------------------------------------------------
# 0. Entrada e pasta de saida
# --------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($Issue)) {
    try {
        Clear-Host
        Write-Host "==========================================================" -ForegroundColor Cyan
        Write-Host "     ECG DIAGNOSTIC v$ScriptVersion - TRIAGEM CLINICA UNIVERSAL     " -ForegroundColor Cyan
        Write-Host "==========================================================" -ForegroundColor Cyan
        $Issue = Read-Host "`nQueixa do cliente / Sintoma reportado"
    } catch { $Issue = "" }
    if ([string]::IsNullOrWhiteSpace($Issue)) { $Issue = "Revisao preventiva geral" }
}

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = if ($PSScriptRoot) { $PSScriptRoot } else { [Environment]::GetFolderPath('Desktop') }
}
if (-not (Test-Path -LiteralPath $OutputDir)) {
    try { New-Item -ItemType Directory -Path $OutputDir -Force -ErrorAction Stop | Out-Null }
    catch { $OutputDir = [Environment]::GetFolderPath('Desktop') }
}

$Watch = [System.Diagnostics.Stopwatch]::StartNew()

$Report = [ordered]@{
    SchemaVersion           = "2.2"
    DiagnosticEngine        = "ECG-Universal"
    DiagnosticEngineVersion = "2.2.0"
    Metadata = [ordered]@{
        ComputerName   = $env:COMPUTERNAME
        Timestamp      = (Get-Date).ToString("o")
        IssueReported  = $Issue
        RanAsAdmin     = $IsAdmin
        DeepIntegrity  = [bool]$DeepIntegrity
        EventWindowDays = $EventDays
        ConfidenceNote = "Confidence = constante heuristica atribuida manualmente, nao uma medicao."
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

# --------------------------------------------------------------------------
# 1. Amostragem de CPU (janela curta e dedicada)
# --------------------------------------------------------------------------
$SampleSeconds = 4
Write-Host "`n>>> [1/8] A amostrar CPU e processos (janela de $SampleSeconds s)..." -ForegroundColor Yellow

$LogicalCores = [Environment]::ProcessorCount
$SelfPid = $PID

$T0 = @{}
foreach ($p in (Get-Process)) {
    if ($null -ne $p.CPU) { $T0["$($p.Id)|$($p.ProcessName)"] = [double]$p.CPU }
}
$TimeT0 = [System.Diagnostics.Stopwatch]::GetTimestamp()

$CpuSamples = New-Object System.Collections.Generic.List[double]
$PerformancePct = $null
for ($i = 0; $i -lt $SampleSeconds; $i++) {
    Start-Sleep -Seconds 1
    $m = Get-CimInstance -ClassName Win32_PerfFormattedData_Counters_ProcessorInformation -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq '_Total' } | Select-Object -First 1
    if ($m -and $null -ne $m.PercentProcessorUtility) {
        # A primeira leitura de classes "Formatted" pode vir por aquecer: e descartada
        if ($i -gt 0) { $CpuSamples.Add([double]$m.PercentProcessorUtility) }
        if ($null -ne $m.PercentProcessorPerformance) { $PerformancePct = [double]$m.PercentProcessorPerformance }
    }
}

$TimeT1 = [System.Diagnostics.Stopwatch]::GetTimestamp()
$TimeDeltaSeconds = ($TimeT1 - $TimeT0) / [System.Diagnostics.Stopwatch]::Frequency

$RealCpuHogs = @()
$CpuProcSumPct = 0.0
foreach ($p1 in (Get-Process)) {
    if ($null -eq $p1.CPU -or $p1.Id -eq $SelfPid) { continue }
    $key = "$($p1.Id)|$($p1.ProcessName)"
    if ($T0.ContainsKey($key)) {
        $delta = [double]$p1.CPU - $T0[$key]
        if ($delta -gt 0) {
            $usage = ($delta / ($TimeDeltaSeconds * $LogicalCores)) * 100
            $CpuProcSumPct += $usage
            if ($usage -ge 1.0) {
                $RealCpuHogs += [PSCustomObject]@{ Id = $p1.Id; ProcessName = $p1.ProcessName; InstantCPU = $usage }
            }
        }
    }
}

$TopHogs = @($RealCpuHogs | Sort-Object InstantCPU -Descending | Select-Object -First 5 | ForEach-Object {
    $pp = Get-Process -Id $_.Id -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Id          = $_.Id
        ProcessName = $_.ProcessName
        InstantCPU  = [math]::Round($_.InstantCPU, 1)
        Company     = if ($pp -and $pp.Company) { "$($pp.Company)".Trim() } else { "N/A" }
        Description = if ($pp -and $pp.Description) { "$($pp.Description)".Trim() } else { "N/A" }
        Path        = if ($pp -and $pp.Path) { $pp.Path } else { "N/A" }
    }
})

# --------------------------------------------------------------------------
# 2. Hardware base, processador e sensores termicos
# --------------------------------------------------------------------------
Write-Host " [2/8] A recolher sinais vitais de processador, bios e termicos..." -ForegroundColor Gray
$CpuCim = Get-CimInstance Win32_Processor | Select-Object -First 1
$OS = Get-CimInstance Win32_OperatingSystem
$CS = Get-CimInstance Win32_ComputerSystem
$BIOS = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue

$KernelBaseClock = try {
    (Get-ItemProperty -Path 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0' -ErrorAction Stop).'~MHz'
} catch { [int]$CpuCim.MaxClockSpeed }

$CpuTotalUsage = if ($CpuSamples.Count -gt 0) {
    [int][math]::Min(100, [math]::Round(($CpuSamples | Measure-Object -Average).Average, 0))
} else { [int]$CpuCim.LoadPercentage }

# Zona termica ACPI (indicativa: muitas vezes nao e a temperatura do CPU)
$ThermalZoneC = $null
try {
    $Thermal = Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop | Select-Object -First 1
    if ($Thermal -and $Thermal.CurrentTemperature -gt 2732) {
        $ThermalZoneC = [math]::Round(($Thermal.CurrentTemperature - 2732) / 10, 1)
    }
} catch { }

$Battery = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
$BatteryStatus = if ($Battery) {
    @{ Present = $true; ChargePercent = $Battery.EstimatedChargeRemaining; Status = $Battery.BatteryStatus }
} else { @{ Present = $false } }

# Reinicios pendentes (PendingFileRenameOperations isolado e comum em maquinas saudaveis)
$RebootReasons = @()
$RebootStrong = $false
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
    $RebootStrong = $true; $RebootReasons += "CBS_RebootPending"
}
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
    $RebootStrong = $true; $RebootReasons += "WindowsUpdate_RebootRequired"
}
$FileRename = try { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ErrorAction SilentlyContinue).PendingFileRenameOperations } catch { $null }
if ($FileRename) { $RebootReasons += "PendingFileRenameOperations" }
$RebootPending = ($RebootReasons.Count -gt 0)

$Report.Facts.System = [ordered]@{
    ComputerName          = $env:COMPUTERNAME
    Manufacturer          = "$($CS.Manufacturer)".Trim()
    Model                 = "$($CS.Model)".Trim()
    OSCaption             = "$($OS.Caption)".Trim()
    OSBuild               = $OS.BuildNumber
    UptimeDays            = [math]::Round(((Get-Date) - $OS.LastBootUpTime).TotalDays, 2)
    RebootPending         = $RebootPending
    RebootReasons         = ($RebootReasons -join ", ")
    CPUModel              = "$($CpuCim.Name)".Trim()
    LogicalCores          = $LogicalCores
    BaseClockMHz          = $KernelBaseClock
    PerformancePct        = $PerformancePct
    CPUUsagePct           = $CpuTotalUsage
    CPUSampleSeconds      = $SampleSeconds
    CPUProcessSumPct      = [math]::Round($CpuProcSumPct, 1)
    ThermalZone_ACPI_C    = $ThermalZoneC
    BIOSVersion           = if ($BIOS) { $BIOS.SMBIOSBIOSVersion } else { "N/A" }
    Battery               = $BatteryStatus
}
$Report.Facts.TopRealTimeCPU = $TopHogs

# --------------------------------------------------------------------------
# 3. Memoria RAM (disponibilidade real, commit e pools)
# --------------------------------------------------------------------------
Write-Host " [3/8] A recolher metricas de memoria, commit e pools de kernel..." -ForegroundColor Gray
$PerfMem = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory -ErrorAction SilentlyContinue | Select-Object -First 1
$TotalRamMB = [int][math]::Round($OS.TotalVisibleMemorySize / 1024, 0)
$FreeOnlyMB = [int][math]::Round($OS.FreePhysicalMemory / 1024, 0)
if ($PerfMem -and $null -ne $PerfMem.AvailableMBytes) {
    $AvailRamMB = [int]$PerfMem.AvailableMBytes
    $AvailSource = "PerfOS_Memory.AvailableMBytes"
} else {
    $AvailRamMB = $FreeOnlyMB
    $AvailSource = "Win32_OperatingSystem.FreePhysicalMemory (subestima a memoria disponivel)"
}
$UsedRamMB = $TotalRamMB - $AvailRamMB
$AvailPct = if ($TotalRamMB -gt 0) { [math]::Round(($AvailRamMB / $TotalRamMB) * 100, 1) } else { 0 }
$CommitTotalMB = if ($PerfMem) { [int][math]::Round($PerfMem.CommittedBytes / 1MB, 0) } else { 0 }
$CommitLimitMB = if ($PerfMem) { [int][math]::Round($PerfMem.CommitLimit / 1MB, 0) } else { 0 }
$PoolPagedMB    = if ($PerfMem) { [int][math]::Round($PerfMem.PoolPagedBytes / 1MB, 0) } else { 0 }
$PoolNonPagedMB = if ($PerfMem) { [int][math]::Round($PerfMem.PoolNonpagedBytes / 1MB, 0) } else { 0 }

$Report.Facts.Memory = [ordered]@{
    TotalRAM_MB       = $TotalRamMB
    AvailableRAM_MB   = $AvailRamMB
    AvailableRAM_Pct  = $AvailPct
    AvailableSource   = $AvailSource
    UsedRAM_Pct       = if ($TotalRamMB -gt 0) { [math]::Round(($UsedRamMB / $TotalRamMB) * 100, 1) } else { 0 }
    FreeOnly_MB       = $FreeOnlyMB
    Committed_MB      = $CommitTotalMB
    CommitLimit_MB    = $CommitLimitMB
    CommitUtilization = if ($CommitLimitMB -gt 0) { [math]::Round(($CommitTotalMB / $CommitLimitMB) * 100, 1) } else { 0 }
    PoolPaged_MB      = $PoolPagedMB
    PoolNonPaged_MB   = $PoolNonPagedMB
    PageFileActive    = [bool](Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue)
}

# --------------------------------------------------------------------------
# 4. Armazenamento: discos fisicos e volumes
# --------------------------------------------------------------------------
Write-Host " [4/8] A mapear topologia de discos, controladores e espaco livre..." -ForegroundColor Gray
$Disks = @(Get-PhysicalDisk -ErrorAction SilentlyContinue)
$DiskList = @()
foreach ($d in $Disks) {
    $Reliability = if ($IsAdmin) { Get-StorageReliabilityCounter -PhysicalDisk $d -ErrorAction SilentlyContinue } else { $null }
    $DiskList += [ordered]@{
        DeviceId             = "$($d.DeviceId)"
        FriendlyName         = "$($d.FriendlyName)".Trim()
        MediaType            = "$($d.MediaType)"
        BusType              = "$($d.BusType)"
        HealthStatus         = "$($d.HealthStatus)"
        OperationalStatus    = ($d.OperationalStatus -join ", ")
        SizeGB               = [math]::Round($d.Size / 1GB, 1)
        TemperatureC         = if ($Reliability) { $Reliability.Temperature } else { $null }
        WearPercentage       = if ($Reliability) { $Reliability.Wear } else { $null }
        ReadErrorsTotal      = if ($Reliability) { $Reliability.ReadErrorsTotal } else { $null }
        WriteErrorsTotal     = if ($Reliability) { $Reliability.WriteErrorsTotal } else { $null }
        ReadErrorsUncorrected  = if ($Reliability) { $Reliability.ReadErrorsUncorrected } else { $null }
        WriteErrorsUncorrected = if ($Reliability) { $Reliability.WriteErrorsUncorrected } else { $null }
    }
}
$Report.Facts.PhysicalDisks = $DiskList

$Report.Facts.Volumes = @(Get-Volume -ErrorAction SilentlyContinue |
    Where-Object { $_.DriveLetter -and $_.Size -gt 0 -and "$($_.DriveType)" -eq 'Fixed' } |
    ForEach-Object {
        [ordered]@{
            DriveLetter     = "$($_.DriveLetter)"
            FileSystemLabel = "$($_.FileSystemLabel)"
            FileSystem      = "$($_.FileSystem)"
            SizeGB          = [math]::Round($_.Size / 1GB, 1)
            FreeGB          = [math]::Round($_.SizeRemaining / 1GB, 1)
            FreePct         = [math]::Round(($_.SizeRemaining / $_.Size) * 100, 1)
        }
    })

# --------------------------------------------------------------------------
# 5. Minidumps e estabilidade
# --------------------------------------------------------------------------
Write-Host " [5/8] A verificar minidumps de BSOD e indice de fiabilidade do sistema..." -ForegroundColor Gray
$MinidumpFolder = "$env:SystemRoot\Minidump"
$DumpFiles = @()
if (Test-Path $MinidumpFolder) {
    $DumpFiles = @(Get-ChildItem -Path $MinidumpFolder -Filter "*.dmp" -ErrorAction SilentlyContinue)
}
$DumpCount = $DumpFiles.Count
$LatestDumpDt = $null
if ($DumpCount -gt 0) {
    $LatestDumpDt = ($DumpFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
}
$LatestDumpDate = if ($LatestDumpDt) { $LatestDumpDt.ToString("yyyy-MM-dd HH:mm:ss") } else { "Nenhum" }

$RelMetric = Get-CimInstance Win32_ReliabilityStabilityMetrics -ErrorAction SilentlyContinue |
    Sort-Object TimeGenerated -Descending | Select-Object -First 1
$StabilityIndex = if ($RelMetric) { [math]::Round([double]$RelMetric.SystemStabilityIndex, 1) } else { $null }

$Report.Facts.CrashDumps = [ordered]@{
    MinidumpCount        = $DumpCount
    LatestMinidumpDate   = $LatestDumpDate
    SystemStabilityIndex = $StabilityIndex
}

# --------------------------------------------------------------------------
# 6. Rede (adaptador pela rota por defeito; DNS e TCP sempre testados)
# --------------------------------------------------------------------------
Write-Host " [6/8] A auditar conectividade de rede (Gateway, DNS e Porta 443)..." -ForegroundColor Gray
$NetFacts = [ordered]@{
    AdapterActive    = "Nenhum"
    IsVirtualAdapter = $null
    LinkSpeed        = "N/A"
    GatewayIP        = $null
    GatewayPing      = $false
    DNSResolution    = $false
    InternetTcp443   = $false
    WiFiDetails      = $null
}

$ActiveAdapter = $null
$GatewayIP = $null
try {
    $Routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | ForEach-Object {
        $ifm = (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).InterfaceMetric
        [PSCustomObject]@{ IfIndex = $_.InterfaceIndex; NextHop = $_.NextHop; Metric = ([int]$_.RouteMetric + [int]$ifm) }
    } | Sort-Object Metric)
} catch { $Routes = @() }

$BestRoute = $Routes | Select-Object -First 1
if ($BestRoute) {
    $ActiveAdapter = Get-NetAdapter -InterfaceIndex $BestRoute.IfIndex -ErrorAction SilentlyContinue
    $GatewayIP = $BestRoute.NextHop
}
if (-not $ActiveAdapter) {
    $ActiveAdapter = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'Up' -and -not $_.Virtual } | Select-Object -First 1
}

if ($ActiveAdapter) {
    $NetFacts.AdapterActive    = $ActiveAdapter.InterfaceAlias
    $NetFacts.IsVirtualAdapter = [bool]$ActiveAdapter.Virtual
    $NetFacts.LinkSpeed        = "$($ActiveAdapter.LinkSpeed)"
    $NetFacts.GatewayIP        = $GatewayIP

    if ($GatewayIP -and $GatewayIP -ne '0.0.0.0') {
        $NetFacts.GatewayPing = [bool](Test-Connection -ComputerName $GatewayIP -Count 2 -Quiet -ErrorAction SilentlyContinue)
    }

    try {
        if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
            $dnsTest = Resolve-DnsName -Name "www.microsoft.com" -Type A -DnsOnly -ErrorAction Stop
        } else {
            $dnsTest = [System.Net.Dns]::GetHostAddresses("www.microsoft.com")
        }
        if ($dnsTest) { $NetFacts.DNSResolution = $true }
    } catch { }

    $tcpClient = $null
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $iar = $tcpClient.BeginConnect("1.1.1.1", 443, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne(2000, $false) -and $tcpClient.Connected) {
            $tcpClient.EndConnect($iar)
            $NetFacts.InternetTcp443 = $true
        }
    } catch { }
    finally { if ($tcpClient) { $tcpClient.Close(); $tcpClient.Dispose() } }
}

$WlanRaw = netsh wlan show interfaces 2>$null
if ($WlanRaw) {
    $SSID   = Get-TextField $WlanRaw '^\s*SSID\s*:\s*(.+)$'
    $Signal = Get-TextField $WlanRaw '^\s*(?:Sinal|Signal)\s*:\s*(.+)$'
    $Radio  = Get-TextField $WlanRaw '^\s*(?:Radio type|Tipo de r.{1,2}dio)\s*:\s*(.+)$'
    if ($SSID) { $NetFacts.WiFiDetails = @{ SSID = $SSID; Signal = $Signal; RadioType = $Radio } }
}
$Report.Facts.Network = $NetFacts

# --------------------------------------------------------------------------
# 7. Servicos, atualizacoes e integridade Windows
# --------------------------------------------------------------------------
Write-Host " [7/8] A inspecionar servicos de arranque automatico e integridade..." -ForegroundColor Gray

# Servicos automaticos parados com codigo de saida de erro (1077 = nunca iniciado, normal em trigger-start)
$FaultedSvc = @(Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" -ErrorAction SilentlyContinue |
    Where-Object { $_.ExitCode -ne 0 -and $_.ExitCode -ne 1077 } |
    Sort-Object Name | Select-Object -First 10 Name, DisplayName, State, ExitCode)
$Report.Facts.FaultedServices = $FaultedSvc

$Report.Facts.RecentHotfixes = @(Get-HotFix -ErrorAction SilentlyContinue |
    Sort-Object InstalledOn -Descending | Select-Object -First 3 HotFixID, Description, InstalledOn)

$DismHealth = "Nao verificado"
if (-not $IsAdmin) {
    $DismHealth = "Nao verificado (requer admin)"
} else {
    try {
        $img = Repair-WindowsImage -Online -CheckHealth -ErrorAction Stop
        $DismHealth = switch ("$($img.ImageHealthState)") {
            "Healthy"       { "Saudavel" }
            "Repairable"    { "Corrompido (Reparavel)" }
            "NonRepairable" { "Corrompido (Nao reparavel)" }
            default         { "Indeterminado" }
        }
    } catch {
        $DiagErrors.Add("DISM[CheckHealth]: $($_.Exception.Message)")
    }
}
$Report.Facts.ComponentStoreHealth = $DismHealth

if ($DeepIntegrity) {
    if (-not $IsAdmin) {
        $Report.Facts.SFC_Status = "Nao verificado (requer admin)"
    } else {
        Write-Host "    [DeepIntegrity] A executar SFC /verifyonly (pode demorar 1-3 min)..." -ForegroundColor Yellow
        # O sfc escreve em UTF-16: remover NULs antes de comparar
        $sfcOut = (& sfc.exe /verifyonly 2>$null | Out-String) -replace "`0", ""
        $Report.Facts.SFC_Status = if ($sfcOut -match 'did not find any integrity violations|n.{1,2}o encontrou nenhuma viola') {
            "Integro"
        } elseif ($sfcOut -match 'found integrity violations|encontrou viola') {
            "Violacoes Encontradas"
        } else {
            "Indeterminado"
        }
    }
}

$Report.Facts.StartupItems = @(Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue |
    Select-Object Name, Command, Location, User)

# --------------------------------------------------------------------------
# 8. Event Log normalizado
# --------------------------------------------------------------------------
Write-Host " [8/8] A correlacionar eventos de sistema (ultimos $EventDays dias)..." -ForegroundColor Gray
$Since = (Get-Date).AddDays(-$EventDays)
$Ev = [ordered]@{}

# 8.1 Storage fisico: erros (Level 1/2) separados de avisos (Level 3)
$PhysProviders = @('disk', 'stornvme', 'storahci', 'iaStorA', 'iaStorAVC')
$RawPhys = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = $PhysProviders; Level = 1, 2, 3; StartTime = $Since } 'PhysicalStorage')
$Ev.PhysicalStorageErrors   = @($RawPhys | Where-Object { $_.Level -le 2 } | Group-Object ProviderName, Id | Select-Object Count, Name)
$Ev.PhysicalStorageWarnings = @($RawPhys | Where-Object { $_.Level -eq 3 } | Group-Object ProviderName, Id | Select-Object Count, Name)

# 8.2 Sistema de ficheiros logico
$RawLog = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = @('Ntfs', 'volmgr'); Level = 1, 2, 3; StartTime = $Since } 'LogicalFilesystem')
$Ev.LogicalFilesystemErrors = @($RawLog | Group-Object ProviderName, Id | Select-Object Count, Name)

# 8.3 WHEA: fatais vs corrigidos
$RawWhea = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = $Since } 'WHEA')
$Ev.WHEA_Fatal     = @($RawWhea | Where-Object { $_.Level -le 2 } | Group-Object Id | Select-Object Count, Name)
$Ev.WHEA_Corrected = @($RawWhea | Where-Object { $_.Level -gt 2 } | Group-Object Id | Select-Object Count, Name)

# 8.4 Kernel-Power 41 (apenas o provider correto)
$KP41Raw = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $Since } 'KernelPower41')
$KP41WithBugcheck = 0
$KP41DirtyPower = 0
$BugCodes = New-Object System.Collections.Generic.List[string]
foreach ($evt in $KP41Raw) {
    [int64]$code = 0
    try {
        $xml = [xml]$evt.ToXml()
        $node = @($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'BugcheckCode' })[0]
        if ($node) { [void][int64]::TryParse([string]$node.'#text', [ref]$code) }
    } catch { }
    if ($code -ne 0) {
        $KP41WithBugcheck++
        $hex = '0x{0:X}' -f $code
        if (-not $BugCodes.Contains($hex)) { $BugCodes.Add($hex) }
    } else { $KP41DirtyPower++ }
}
$Ev.KernelPower41 = [ordered]@{
    TotalCount          = $KP41Raw.Count
    CrashesWithBugcheck = $KP41WithBugcheck
    DirtyPowerLosses    = $KP41DirtyPower
    BugcheckCodes       = @($BugCodes)
}

# 8.5 Resource-Exhaustion 2004 (apenas o provider correto)
$ResEx = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Resource-Exhaustion-Detector'; Id = 2004; StartTime = $Since } 'ResourceExhaustion')
$Ev.ResourceExhaustion_Count = $ResEx.Count

$Report.Facts.AggregatedEvents = $Ev

# =========================================================================
# MOTOR HEURISTICO LOCAL
# =========================================================================

# --- Contexto de execucao
if (-not $IsAdmin) {
    Add-Finding "Windows" "Info" 1.0 "Executado sem privilegios de administrador" `
        "Resultados parciais: sensores ACPI, contadores de fiabilidade de disco, DISM e SFC nao foram avaliados." `
        "Voltar a executar numa consola PowerShell elevada (Executar como administrador)." 1
}

# --- CPU e temperatura
if ($CpuTotalUsage -ge 85) {
    $hog = $TopHogs | Select-Object -First 1
    if ($hog) {
        $cpuEv  = "Utilizacao media de $CpuTotalUsage% em $SampleSeconds s. Processo topo: $($hog.ProcessName) ($($hog.InstantCPU)%)."
        $cpuAct = "Investigar o processo $($hog.ProcessName) (PID $($hog.Id), $($hog.Path)) e confirmar se e legitimo antes de o terminar."
    } else {
        $cpuEv  = "Utilizacao media de $CpuTotalUsage% em $SampleSeconds s, sem processo dominante (possivel atividade de kernel/driver)."
        $cpuAct = "Repetir a medicao e, se persistir, analisar drivers e interrupcoes (ex.: LatencyMon)."
    }
    Add-Finding "Hardware" "Warning" 0.7 "Utilizacao de CPU Elevada" $cpuEv $cpuAct 2
}
if ($ThermalZoneC -and $ThermalZoneC -ge 88) {
    Add-Finding "Hardware" "Warning" 0.5 "Temperatura Termica ACPI Elevada" `
        "Sonda ACPI reportou $($ThermalZoneC) C (indicativo: a sonda ACPI nem sempre corresponde ao CPU)." `
        "Confirmar com ferramenta dedicada (HWiNFO/Core Temp) e inspecionar ventoinhas, saidas de ar e pasta termica." 1
}
if ($Report.Facts.System.UptimeDays -ge 30) {
    Add-Finding "Windows" "Info" 0.6 "Uptime Prolongado" `
        "Sistema ligado ha $($Report.Facts.System.UptimeDays) dias sem reiniciar." `
        "Reiniciar o equipamento para aplicar atualizacoes e limpar estados acumulados." 1
}

# --- Armazenamento: saude dos discos fisicos
foreach ($dk in $DiskList) {
    $dn = "$($dk.FriendlyName) (disco $($dk.DeviceId))"
    switch ($dk.HealthStatus) {
        "Unhealthy" {
            Add-Finding "Storage" "Critical" 0.95 "Disco Reportado como Nao Saudavel" `
                "$dn : HealthStatus=Unhealthy; OperationalStatus=$($dk.OperationalStatus)." `
                "Fazer copia de seguranca imediata e substituir/diagnosticar o disco $dn." 2
        }
        "Warning" {
            Add-Finding "Storage" "Warning" 0.85 "Disco com Aviso de Saude" `
                "$dn : HealthStatus=Warning; OperationalStatus=$($dk.OperationalStatus)." `
                "Verificar SMART do disco $dn e garantir copia de seguranca." 2
        }
    }
    if ($dk.OperationalStatus -and $dk.OperationalStatus -ne "OK" -and $dk.HealthStatus -eq "Healthy") {
        Add-Finding "Storage" "Warning" 0.6 "Estado Operacional Anormal do Disco" `
            "$dn : OperationalStatus=$($dk.OperationalStatus)." `
            "Verificar o disco $dn no Gestor de Discos e nos registos de sistema." 1
    }
    if ($null -ne $dk.WearPercentage) {
        if ($dk.WearPercentage -ge 90) {
            Add-Finding "Storage" "Critical" 0.9 "Desgaste de SSD Muito Elevado" `
                "$dn : desgaste $($dk.WearPercentage)%." "Planear substituicao do SSD $dn." 2
        } elseif ($dk.WearPercentage -ge 80) {
            Add-Finding "Storage" "Warning" 0.8 "Desgaste de SSD Elevado" `
                "$dn : desgaste $($dk.WearPercentage)%." "Monitorizar e planear substituicao do SSD $dn." 1
        }
    }
    $uncorr = 0
    if ($null -ne $dk.ReadErrorsUncorrected)  { $uncorr += [int64]$dk.ReadErrorsUncorrected }
    if ($null -ne $dk.WriteErrorsUncorrected) { $uncorr += [int64]$dk.WriteErrorsUncorrected }
    if ($uncorr -gt 0) {
        Add-Finding "Storage" "Warning" 0.75 "Erros de I/O Nao Corrigidos no Disco" `
            "$dn : $uncorr erros nao corrigidos acumulados (leitura+escrita)." `
            "Verificar SMART e integridade do disco $dn; garantir copia de seguranca." 2
    }
    if ($null -ne $dk.TemperatureC -and $dk.TemperatureC -ge 70) {
        Add-Finding "Storage" "Warning" 0.7 "Temperatura de Disco Elevada" `
            "$dn : $($dk.TemperatureC) C." "Melhorar a ventilacao do equipamento/disco." 1
    }
}

# --- Armazenamento: volumes (percentagem E GB livres)
foreach ($vol in $Report.Facts.Volumes) {
    if (($vol.FreePct -lt 10 -and $vol.FreeGB -lt 50) -or $vol.FreeGB -lt 5) {
        Add-Finding "Storage" "Critical" 0.98 "Volume $($vol.DriveLetter): em Esgotamento Critico" `
            "Apenas $($vol.FreeGB) GB disponiveis ($($vol.FreePct)% livres)." `
            "Libertar espaco no volume $($vol.DriveLetter): de imediato." 2
    } elseif ($vol.FreePct -lt 15 -and $vol.FreeGB -lt 100) {
        Add-Finding "Storage" "Warning" 0.85 "Volume $($vol.DriveLetter): com Espaco Reduzido" `
            "Volume com $($vol.FreePct)% de espaco livre ($($vol.FreeGB) GB)." `
            "Executar limpeza de disco (cleanmgr) e remover ficheiros temporarios." 1
    }
}

# --- Armazenamento: eventos fisicos vs logicos
if (@($Ev.PhysicalStorageErrors).Count -gt 0) {
    $names = ($Ev.PhysicalStorageErrors | ForEach-Object { "$($_.Name) (x$($_.Count))" }) -join ", "
    Add-Finding "Storage" "Critical" 0.9 "Erros no Barramento ou Controlador de Armazenamento" `
        "Erros nas ultimas $EventDays dias: $names." `
        "Verificar SMART, cabos/ligacoes e estado do disco; fazer copia de seguranca." 2
}
if (@($Ev.PhysicalStorageWarnings).Count -gt 0) {
    $names = ($Ev.PhysicalStorageWarnings | ForEach-Object { "$($_.Name) (x$($_.Count))" }) -join ", "
    Add-Finding "Storage" "Warning" 0.55 "Avisos de I/O no Armazenamento" `
        "Avisos nas ultimas $EventDays dias: $names (retries de I/O sao comuns em dispositivos USB/externos)." `
        "Confirmar se os avisos se referem a um disco interno; se sim, verificar SMART e cabos." 1
}
if (@($Ev.LogicalFilesystemErrors).Count -gt 0) {
    $names = ($Ev.LogicalFilesystemErrors | ForEach-Object { "$($_.Name) (x$($_.Count))" }) -join ", "
    Add-Finding "Storage" "Warning" 0.8 "Erros Logicos no Sistema de Ficheiros (NTFS/volmgr)" `
        "Eventos de sistema de ficheiros: $names." `
        "Agendar chkdsk no volume correspondente para verificar metadados NTFS." 1
}

# --- Memoria RAM
if ($AvailRamMB -lt 1024 -and $AvailPct -lt 15) {
    Add-Finding "Memory" "Critical" 0.9 "Memoria Fisica Disponivel Muito Baixa" `
        "Apenas $AvailRamMB MB disponiveis ($AvailPct% de $TotalRamMB MB)." `
        "Verificar processos com fuga de memoria ou considerar expansao de RAM." 2
}
if ($Report.Facts.Memory.CommitUtilization -gt 85) {
    Add-Finding "Memory" "Warning" 0.85 "Commit Limit Sob Pressao" `
        "Memoria comprometida em $($Report.Facts.Memory.CommitUtilization)% do limite." `
        "Garantir pagefile adequado gerido pelo sistema." 1
}
if ($Ev.ResourceExhaustion_Count -gt 0) {
    Add-Finding "Memory" "Critical" 0.9 "Esgotamento de Recursos Recente (Event 2004)" `
        "$($Ev.ResourceExhaustion_Count) eventos de Resource-Exhaustion nos ultimos $EventDays dias." `
        "Verificar configuracao de memoria virtual e processos com consumo excessivo." 2
}

# --- Kernel-Power 41
$kp = $Ev.KernelPower41
if ($kp.CrashesWithBugcheck -gt 0) {
    $codes = if ($kp.BugcheckCodes.Count -gt 0) { " Codigos: $($kp.BugcheckCodes -join ', ')." } else { "" }
    Add-Finding "Hardware" "Critical" 0.9 "Reinicios por Ecra Azul (BugCheck) Detetados" `
        "$($kp.CrashesWithBugcheck) falha(s) com BugCheck registadas no Kernel-Power.$codes" `
        "Analisar minidumps em C:\Windows\Minidump (WinDbg/BlueScreenView) para isolar o driver causador." 2
}
if ($kp.DirtyPowerLosses -ge 2) {
    Add-Finding "Hardware" "Warning" 0.7 "Desligamentos Abruptos / Perda de Energia" `
        "$($kp.DirtyPowerLosses) reinicios sem BugCheck registado (corte eletrico, bloqueio total ou botao de energia; nao distinguivel apenas por este evento)." `
        "Testar PSU, bateria e alimentacao; verificar bloqueios totais e temperaturas." 1
} elseif ($kp.DirtyPowerLosses -eq 1) {
    Add-Finding "Hardware" "Info" 0.5 "Um Desligamento Abrupto Registado" `
        "1 reinicio sem BugCheck registado nos ultimos $EventDays dias." `
        "Monitorizar; investigar se se repetir." 1
}

# --- WHEA
if (@($Ev.WHEA_Fatal).Count -gt 0) {
    $names = ($Ev.WHEA_Fatal | ForEach-Object { "ID $($_.Name) (x$($_.Count))" }) -join ", "
    Add-Finding "Hardware" "Critical" 0.95 "Erros Fatais de Hardware (WHEA)" `
        "Eventos WHEA de nivel Erro/Critico: $names." `
        "Inspecionar estabilidade de CPU, RAM e barramento PCIe (teste de memoria, BIOS, overclock/undervolt)." 2
}
if (@($Ev.WHEA_Corrected).Count -gt 0) {
    $total = ($Ev.WHEA_Corrected | Measure-Object -Property Count -Sum).Sum
    $names = ($Ev.WHEA_Corrected | ForEach-Object { "ID $($_.Name) (x$($_.Count))" }) -join ", "
    $sev = if ($total -ge 20) { "Warning" } else { "Info" }
    Add-Finding "Hardware" $sev 0.6 "Erros de Hardware Corrigidos (WHEA)" `
        "Eventos WHEA corrigidos: $names." `
        "Se frequentes, atualizar BIOS/drivers de chipset e verificar PCIe/RAM." 1
}

# --- Minidumps e estabilidade
if ($DumpCount -gt 0) {
    $recent = $LatestDumpDt -and ($LatestDumpDt -gt (Get-Date).AddDays(-30))
    $sev = if ($recent) { "Warning" } else { "Info" }
    Add-Finding "Windows" $sev 0.85 "Historico de Crash Dumps Presente" `
        "$DumpCount minidump(s). O mais recente: $LatestDumpDate." `
        "Examinar com WinDbg ou BlueScreenView se houver queixas de instabilidade." 1
}
if ($null -ne $StabilityIndex -and $StabilityIndex -lt 5) {
    Add-Finding "Windows" "Warning" 0.7 "Indice de Fiabilidade Baixo" `
        "SystemStabilityIndex = $StabilityIndex (escala 1-10)." `
        "Abrir o Monitor de Fiabilidade (perfmon /rel) e identificar as falhas recorrentes." 1
}

# --- Integridade do Windows
if ($RebootPending) {
    $sev = if ($RebootStrong) { "Warning" } else { "Info" }
    Add-Finding "Windows" $sev 0.9 "Reinicio Pendente" `
        "Motivo(s): $($Report.Facts.System.RebootReasons)." `
        "Reiniciar o equipamento para concluir operacoes pendentes." 1
}
if ($DismHealth -eq "Corrompido (Reparavel)") {
    Add-Finding "Windows" "Critical" 0.9 "Corrupcao no Component Store do Windows" `
        "DISM CheckHealth: imagem reparavel." `
        "Executar: DISM /Online /Cleanup-Image /RestoreHealth e depois sfc /scannow." 2
} elseif ($DismHealth -eq "Corrompido (Nao reparavel)") {
    Add-Finding "Windows" "Critical" 0.95 "Component Store do Windows Nao Reparavel" `
        "DISM CheckHealth: imagem nao reparavel." `
        "Considerar reparacao in-place (setup.exe com a mesma versao) ou reinstalacao." 2
}
if ($Report.Facts.SFC_Status -eq "Violacoes Encontradas") {
    Add-Finding "Windows" "Warning" 0.8 "SFC Reporta Violacoes de Integridade" `
        "sfc /verifyonly encontrou ficheiros de sistema alterados/danificados." `
        "Executar sfc /scannow (apos DISM /RestoreHealth)." 1
}
if ($FaultedSvc.Count -gt 0) {
    $svcNames = ($FaultedSvc | Select-Object -First 5 | ForEach-Object { "$($_.Name) (exit $($_.ExitCode))" }) -join ", "
    Add-Finding "Windows" "Info" 0.5 "Servicos Automaticos Parados com Erro" `
        "$($FaultedSvc.Count) servico(s): $svcNames." `
        "Rever os servicos listados em services.msc e no Event Log." 1
}

# --- Rede
$N = $Report.Facts.Network
if ($N.AdapterActive -eq "Nenhum") {
    Add-Finding "Network" "Critical" 1.0 "Sem Adaptadores de Rede com Link Ativo" `
        "Nao existem placas Ethernet ou Wi-Fi ativas." `
        "Verificar ligacao fisica de rede ou comutador de radio Wi-Fi." 2
} elseif (-not $N.GatewayIP) {
    Add-Finding "Network" "Warning" 0.8 "Adaptador Ativo sem Rota por Defeito" `
        "Adaptador $($N.AdapterActive) esta ativo mas nao ha gateway por defeito." `
        "Verificar DHCP/configuracao IP (ipconfig /all)." 1
} else {
    if (-not $N.DNSResolution -and $N.InternetTcp443) {
        Add-Finding "Network" "Critical" 0.9 "Falha na Resolucao de Nomes DNS" `
            "Ligacao TCP direta por IP funciona, mas a resolucao de nomes falhou." `
            "Limpar cache DNS (ipconfig /flushdns) ou definir servidores DNS (1.1.1.1 / 8.8.8.8)." 2
    } elseif (-not $N.DNSResolution -and -not $N.InternetTcp443) {
        if ($N.GatewayPing) {
            Add-Finding "Network" "Critical" 0.85 "Gateway Responde mas Sem Acesso a Internet" `
                "Gateway $($N.GatewayIP) responde a ping; DNS e TCP 443 falharam." `
                "Verificar router/modem e ligacao do operador." 2
        } else {
            Add-Finding "Network" "Critical" 0.85 "Sem Conectividade Alem do Adaptador" `
                "Gateway $($N.GatewayIP) nao responde a ping; DNS e TCP 443 falharam." `
                "Verificar Wi-Fi/cabo, router e configuracao IP." 2
        }
    } elseif ($N.DNSResolution -and -not $N.InternetTcp443) {
        Add-Finding "Network" "Warning" 0.6 "Acesso TCP 443 Externo Falhou" `
            "DNS OK, mas a ligacao TCP 443 a 1.1.1.1 falhou (pode ser bloqueio especifico)." `
            "Verificar firewall, proxy ou filtragem no router." 1
    } elseif (-not $N.GatewayPing) {
        Add-Finding "Network" "Info" 0.5 "Gateway Nao Responde a ICMP" `
            "Internet funciona; o gateway $($N.GatewayIP) provavelmente bloqueia ping." `
            "Sem acao necessaria." 1
    }
}

$Watch.Stop()
$Report.Metadata.DurationSeconds = [math]::Round($Watch.Elapsed.TotalSeconds, 2)
$Report.Facts.CollectionErrors = @($DiagErrors)

# =========================================================================
# APRESENTACAO NO TERMINAL E EXPORTACAO
# =========================================================================
$SortedFindings = @($Report.Findings | Sort-Object @{ Expression = { switch ($_.Severity) { 'Critical' { 0 } 'Warning' { 1 } default { 2 } } } })

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         PARECER CLINICO DO ECG (TRIAGEM LOCAL)           " -ForegroundColor Cyan
Write-Host "   Schema: v$($Report.SchemaVersion) | Tempo: $($Report.Metadata.DurationSeconds)s | Queixa: $Issue" -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Cyan

Write-Host "`nPONTUACAO DE SAUDE PONDERADA (0-100):" -ForegroundColor White
$ScoreColor = if ($Report.HealthScore.Overall -ge 80) { "Green" } elseif ($Report.HealthScore.Overall -ge 50) { "Yellow" } else { "Red" }
Write-Host "  GLOBAL   : $($Report.HealthScore.Overall)/100" -ForegroundColor $ScoreColor
Write-Host "  Hardware : $($Report.HealthScore.Hardware) | Storage : $($Report.HealthScore.Storage) | RAM : $($Report.HealthScore.Memory)" -ForegroundColor Gray
Write-Host "  Windows  : $($Report.HealthScore.Windows)  | Rede    : $($Report.HealthScore.Network)" -ForegroundColor Gray

Write-Host "`nDIAGNOSTICOS E EVIDENCIAS ($($SortedFindings.Count)):" -ForegroundColor White
if ($SortedFindings.Count -eq 0) {
    Write-Host "  [OK] Nenhuma anomalia identificada nos sinais vitais." -ForegroundColor Green
} else {
    foreach ($f in $SortedFindings) {
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
if ($DiagErrors.Count -gt 0) {
    Write-Host "`nAVISOS DE RECOLHA ($($DiagErrors.Count)) - ver Facts.CollectionErrors no JSON." -ForegroundColor DarkYellow
}
Write-Host "==========================================================" -ForegroundColor Cyan

# Gravacao dos ficheiros (UTF-8)
$TimeStampStr = (Get-Date).ToString('yyyyMMdd_HHmmss')
$BaseName = "ECG_v22_$($env:COMPUTERNAME)_$TimeStampStr"
$JsonPath = Join-Path $OutputDir "$BaseName.json"
$TxtPath  = Join-Path $OutputDir "$BaseName.txt"

$FindingsText = if ($SortedFindings.Count -eq 0) { "Nenhuma anomalia identificada." } else {
    ($SortedFindings | ForEach-Object {
        "[$($_.Severity)] ($($_.Category)) $($_.Finding)`n  Evidencia: $($_.Evidence)`n  Acao     : $($_.RecommendedAction)"
    }) -join "`n`n"
}
$ActionsText = ($Report.RecommendedActions | ForEach-Object { "- $_" }) -join "`n"
$ErrorsText  = if ($DiagErrors.Count -gt 0) { ($DiagErrors | ForEach-Object { "- $_" }) -join "`n" } else { "(nenhum)" }

$ReportText = @"
==================================================================
RELATORIO CLINICO DE TRIAGEM (ECG v$ScriptVersion)
Computador : $($env:COMPUTERNAME)
Data/Hora  : $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
Queixa     : $Issue
Admin      : $IsAdmin
Duracao    : $($Report.Metadata.DurationSeconds) segundos
Schema     : v$($Report.SchemaVersion)
==================================================================

SCORES DE SAUDE PONDERADOS (heuristicos):
- Global   : $($Report.HealthScore.Overall)/100
- Hardware : $($Report.HealthScore.Hardware)/100
- Storage  : $($Report.HealthScore.Storage)/100
- Memoria  : $($Report.HealthScore.Memory)/100
- Windows  : $($Report.HealthScore.Windows)/100
- Rede     : $($Report.HealthScore.Network)/100

FINDINGS ($($SortedFindings.Count)):
$FindingsText

PLANO DE ACAO RECOMENDADO:
$ActionsText

AVISOS DE RECOLHA:
$ErrorsText
==================================================================
"@

try {
    $Report | ConvertTo-Json -Depth 8 | Out-File -FilePath $JsonPath -Encoding UTF8 -ErrorAction Stop
    $ReportText | Out-File -FilePath $TxtPath -Encoding UTF8 -ErrorAction Stop
    Write-Host "`nRelatorio de texto gravado em : $TxtPath" -ForegroundColor Cyan
    Write-Host "Payload JSON para o Agente    : $JsonPath`n" -ForegroundColor Cyan
} catch {
    Write-Host "`nERRO ao gravar relatorios em '$OutputDir': $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Use -OutputDir para indicar uma pasta com permissoes de escrita.`n" -ForegroundColor Red
}
