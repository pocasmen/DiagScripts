<#
.SYNOPSIS
    ECG-Diagnostic.ps1 - Triagem Rápida e Não Invasiva de Sistemas Windows
.DESCRIPTION
    Recolhe telemetria estática e histórico recente de erros de hardware/software,
    exportando um snapshot estruturado em JSON para análise prévia ou LLM.
#>

[CmdletBinding()]
param (
    [string]$OutputPath = ".\ECG_Report_$($env:COMPUTERNAME)_$((Get-Date).ToString('yyyyMMdd_HHmmss')).json"
)

# 0. Verificação de Privilégios
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Warning "[AVISO] O script não está a correr como Administrador. Alguns dados de SMART, eventos e segurança serão omitidos."
}

Write-Host ">>> Iniciando Triagem Rápida (ECG do Sistema)..." -ForegroundColor Cyan
$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$ECG = [ordered]@{}

# 1. Metadados do Exame
$ECG.Metadata = @{
    Timestamp      = (Get-Date).ToString("o")
    ComputerName   = $env:COMPUTERNAME
    RanAsAdmin     = $IsAdmin
    ExecutionTime  = ""
}

# 2. Identificação e Perfil de Hardware Base
Write-Host " [1/9] Mapeando placa-mãe, processador e BIOS..." -ForegroundColor Gray
try {
    $OS = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $CS = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $CPU = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
    $BIOS = Get-CimInstance Win32_BIOS -ErrorAction Stop

    $ECG.SystemProfile = @{
        Manufacturer     = $CS.Manufacturer
        Model            = $CS.Model
        OSName           = $OS.Caption
        OSVersion        = $OS.Version
        OSBuild          = $OS.BuildNumber
        LastBootUpTime   = $OS.LastBootUpTime
        UptimeDays       = [math]::Round(((Get-Date) - $OS.LastBootUpTime).TotalDays, 2)
        CPUName          = $CPU.Name
        CPUCoresLogical  = $CPU.NumberOfLogicalProcessors
        BaseBoard        = (Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Product)
        BIOSVersion      = $BIOS.SMBIOSBIOSVersion
        BIOSReleaseDate  = $BIOS.ReleaseDate
    }
} catch {
    $ECG.SystemProfile = @{ Error = $_.Message }
}

# 3. Saúde do Armazenamento (SMART, NVMe Wear e Espaço)
Write-Host " [2/9] Analisando saúde dos discos físicos e volumes..." -ForegroundColor Gray
try {
    $Disks = Get-PhysicalDisk -ErrorAction SilentlyContinue
    $DiskList = @()

    foreach ($d in $Disks) {
        $Reliability = $null
        if ($IsAdmin) {
            $Reliability = Get-StorageReliabilityCounter -PhysicalDisk $d -ErrorAction SilentlyContinue
        }

        $DiskList += [ordered]@{
            DeviceId           = $d.DeviceId
            FriendlyName       = $d.FriendlyName
            MediaType          = $d.MediaType
            BusType            = $d.BusType
            HealthStatus       = $d.HealthStatus
            OperationalStatus  = ($d.OperationalStatus -join ", ")
            SizeGB             = [math]::Round($d.Size / 1GB, 2)
            TemperatureCelsius = if ($Reliability) { $Reliability.Temperature } else { "N/A" }
            WearPercentage     = if ($Reliability -and $null -ne $Reliability.Wear) { $Reliability.Wear } else { "N/A" }
            ReadErrorsTotal    = if ($Reliability) { $Reliability.ReadErrorsTotal } else { "N/A" }
            WriteErrorsTotal   = if ($Reliability) { $Reliability.WriteErrorsTotal } else { "N/A" }
        }
    }
    $ECG.PhysicalDisks = $DiskList

    $ECG.Volumes = Get-Volume -ErrorAction SilentlyContinue | 
        Where-Object { $_.DriveLetter -and $_.Size -gt 0 } | 
        Select-Object DriveLetter, FileSystemLabel, FileSystem, 
            @{N="SizeGB"; E={[math]::Round($_.Size / 1GB, 2)}}, 
            @{N="FreeSpaceGB"; E={[math]::Round($_.SizeRemaining / 1GB, 2)}},
            @{N="FreePercent"; E={[math]::Round(($_.SizeRemaining / $_.Size) * 100, 1)}}
} catch {
    $ECG.StorageError = $_.Message
}

# 4. Estado da Memória Fisiológica e Paginação
Write-Host " [3/9] Medindo memória física e arquivo de paginação..." -ForegroundColor Gray
try {
    $TotalRAM = $OS.TotalVisibleMemorySize
    $FreeRAM = $OS.FreePhysicalMemory
    $UsedRAM = $TotalRAM - $FreeRAM

    $PageFiles = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue

    $ECG.Memory = @{
        TotalMemoryGB       = [math]::Round($TotalRAM / 1MB, 2)
        FreeMemoryGB        = [math]::Round($FreeRAM / 1MB, 2)
        UsedMemoryPercent   = [math]::Round(($UsedRAM / $TotalRAM) * 100, 1)
        PageFileConfigured  = if ($PageFiles) { $true } else { $false }
        PageFileAllocatedMB = ($PageFiles | Measure-Object -Property AllocatedBaseSize -Sum).Sum
    }
} catch {
    $ECG.Memory = @{ Error = $_.Message }
}

# 5. Eletrocardiograma de Eventos (Falhas Críticas das últimas 72 horas)
Write-Host " [4/9] Inspecionando histórico recente de falhas e BSODs..." -ForegroundColor Gray
$ThreeDaysAgo = (Get-Date).AddDays(-3)
$SevenDaysAgo = (Get-Date).AddDays(-7)

$ECG.EventLogAnomalies = [ordered]@{}

try {
    # BlueScreens / BugChecks
    $ECG.EventLogAnomalies.BugChecks = Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Id        = 1001
        StartTime = $SevenDaysAgo
    } -ErrorAction SilentlyContinue | Select-Object -First 5 TimeCreated, Message

    # Cortes Abruptos de Energia (Kernel-Power Event 41)
    $ECG.EventLogAnomalies.KernelPowerCrashes = Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Id        = 41
        StartTime = $SevenDaysAgo
    } -ErrorAction SilentlyContinue | Select-Object -First 5 TimeCreated, Message

    # Erros de Hardware WHEA (CPU, PCIe, Bus)
    $ECG.EventLogAnomalies.WHEA_HardwareErrors = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = 'Microsoft-Windows-WHEA-Logger'
        StartTime    = $SevenDaysAgo
    } -ErrorAction SilentlyContinue | Select-Object -First 5 TimeCreated, Id, Message

    # Esgotamento de Memória Virtual / Resource-Exhaustion
    $ECG.EventLogAnomalies.ResourceExhaustion = Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Id        = 2004
        StartTime = $SevenDaysAgo
    } -ErrorAction SilentlyContinue | Select-Object -First 5 TimeCreated, Message

    # Erros e Críticos Genéricos nas últimas 48h (Top 10)
    $ECG.EventLogAnomalies.RecentSystemErrors = Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Level     = 1, 2
        StartTime = $ThreeDaysAgo
    } -ErrorAction SilentlyContinue | Select-Object -First 10 TimeCreated, Id, ProviderName, Message

    # Falhas de Aplicações (Crashes / Hangs)
    $ECG.EventLogAnomalies.ApplicationCrashes = Get-WinEvent -FilterHashtable @{
        LogName      = 'Application'
        ProviderName = @('Application Error', 'Application Hang')
        StartTime    = $ThreeDaysAgo
    } -ErrorAction SilentlyContinue | Select-Object -First 5 TimeCreated, Id, Message
} catch {
    $ECG.EventLogAnomalies.Error = $_.Message
}

# 6. Dispositivos em Conflito (Device Manager)
Write-Host " [5/9] Verificando integridade de drivers e periféricos..." -ForegroundColor Gray
try {
    $BadDevices = Get-PnpDevice -ErrorAction SilentlyContinue | 
        Where-Object { $_.Status -in @('Error', 'Degraded') } | 
        Select-Object FriendlyName, InstanceId, Class, Status, Problem

    $ECG.ProblematicDevices = if ($BadDevices) { $BadDevices } else { "Nenhum dispositivo em erro detetado." }
} catch {
    $ECG.ProblematicDevices = @{ Error = $_.Message }
}

# 7. Postura de Segurança e Antivírus
Write-Host " [6/9] Checando estado de segurança e antivírus ativo..." -ForegroundColor Gray
try {
    $DefenderStatus = $null
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        $Mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
        $DefenderStatus = @{
            AMRunningMode          = $Mp.AMRunningMode
            AntivirusEnabled       = $Mp.AntivirusEnabled
            RealTimeProtection     = $Mp.RealTimeProtectionEnabled
            IoavProtectionEnabled  = $Mp.IoavProtectionEnabled
            AntivirusSignatureAge  = $Mp.AntivirusSignatureAge
        }
    }
    
    # Detetar produtos de terceiros registados no SecurityCenter
    $ThirdPartyAV = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
        Select-Object displayName, pathToSignedReportingExe

    $ECG.SecurityPosture = @{
        WindowsDefender = $DefenderStatus
        RegisteredAVs   = $ThirdPartyAV
    }
} catch {
    $ECG.SecurityPosture = @{ Error = $_.Message }
}

# 8. Persistência e Itens de Arranque
Write-Host " [7/9] Mapeando itens de inicialização automática..." -ForegroundColor Gray
try {
    $ECG.StartupPrograms = Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | 
        Select-Object Name, Command, Location, User
} catch {
    $ECG.StartupPrograms = @{ Error = $_.Message }
}

# 9. Fotografia de Consumo de Processos (Top Hogs em repouso)
Write-Host " [8/9] Tirando instantâneo de processos em CPU e RAM..." -ForegroundColor Gray
try {
    $ECG.TopProcessesCPU = Get-Process | Sort-Object CPU -Descending | 
        Select-Object -First 5 ProcessName, Id, 
            @{N="CPUTimeSeconds"; E={[math]::Round($_.CPU, 1)}}, 
            @{N="MemoryMB"; E={[math]::Round($_.WorkingSet / 1MB, 1)}}

    $ECG.TopProcessesRAM = Get-Process | Sort-Object WorkingSet -Descending | 
        Select-Object -First 5 ProcessName, Id, 
            @{N="MemoryMB"; E={[math]::Round($_.WorkingSet / 1MB, 1)}}
} catch {
    $ECG.TopProcesses = @{ Error = $_.Message }
}

# 10. Conectividade de Rede e DNS
Write-Host " [9/9] Verificando interfaces ativas e servidores DNS..." -ForegroundColor Gray
try {
    $ActiveAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
    $DNSList = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
        Where-Object { $_.ServerAddresses.Count -gt 0 }

    $ECG.Network = @{
        ActiveAdapters = $ActiveAdapters | Select-Object Name, InterfaceDescription, LinkSpeed, Status
        DNSServers     = $DNSList | Select-Object InterfaceAlias, ServerAddresses
    }
} catch {
    $ECG.Network = @{ Error = $_.Message }
}

# Finalização e Exportação
$Stopwatch.Stop()
$ECG.Metadata.ExecutionTime = "$([math]::Round($Stopwatch.Elapsed.TotalSeconds, 2)) segundos"

Write-Host "`n>>> Exportando relatório JSON para: $OutputPath" -ForegroundColor Yellow
$ECG | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding utf8

Write-Host ">>> ECG Concluído com sucesso em $($ECG.Metadata.ExecutionTime)!" -ForegroundColor Green