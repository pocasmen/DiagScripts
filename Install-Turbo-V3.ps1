#requires -Version 5.1
#requires -RunAsAdministrator
<#
 ASUS VivoBook E510MA - Windows 11 Turbo V3
 Installs TurboON.ps1, TurboOFF.ps1 and Diagnose.ps1.
 The installer only captures the original state and creates the scripts.
 Run TurboON.ps1 separately after reviewing the backup.
#>

$ErrorActionPreference = 'Stop'
$Root = 'C:\Win11Turbo'
$Backup = Join-Path $Root 'Backup'
$Log = Join-Path $Root 'Install.log'

New-Item -ItemType Directory -Path $Backup -Force | Out-Null
Start-Transcript -Path $Log -Force | Out-Null

try {
    Write-Host "`n=== ASUS VivoBook E510MA - Turbo V3 ===" -ForegroundColor Cyan

    # Capture the active power plan GUID reliably.
    $powerText = (& powercfg.exe /getactivescheme 2>&1 | Out-String)
    $guidMatch = [regex]::Match($powerText, '[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}')
    if (-not $guidMatch.Success) {
        throw "Não foi possível identificar o plano de energia ativo. Nada foi alterado."
    }
    $guidMatch.Value | Set-Content (Join-Path $Backup 'OriginalPowerPlan.txt') -Encoding ASCII

    # Export registry keys only if this is the first installation.
    $registryKeys = [ordered]@{
        'PriorityControl.reg' = 'HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl'
        'VisualEffects.reg'   = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
        'Personalize.reg'     = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
        'Desktop.reg'         = 'HKCU\Control Panel\Desktop'
        'ExplorerAdvanced.reg'= 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
        'GameConfigStore.reg' = 'HKCU\System\GameConfigStore'
        'GameDVR.reg'         = 'HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR'
    }
    foreach ($entry in $registryKeys.GetEnumerator()) {
        $dest = Join-Path $Backup $entry.Key
        if (-not (Test-Path $dest)) {
            & reg.exe export $entry.Value $dest /y | Out-Null
            if ($LASTEXITCODE -ne 0) { Write-Warning "Não foi possível exportar $($entry.Value)." }
        }
    }

    # Save service startup modes and running state. Do not overwrite an existing baseline.
    $serviceFile = Join-Path $Backup 'OriginalServices.json'
    if (-not (Test-Path $serviceFile)) {
        $serviceNames = @(
            'DiagTrack','dmwappushservice','MapsBroker','RetailDemo',
            'XboxGipSvc','XblAuthManager','XblGameSave','XboxNetApiSvc'
        )
        $serviceData = foreach ($name in $serviceNames) {
            $svc = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
            if ($svc) {
                [pscustomobject]@{
                    Name = $name
                    StartMode = $svc.StartMode
                    State = $svc.State
                }
            }
        }
        $serviceData | ConvertTo-Json -Depth 4 | Set-Content $serviceFile -Encoding UTF8
    }

    # Generate TurboON.
    $turboOn = @'
#requires -Version 5.1
#requires -RunAsAdministrator
$ErrorActionPreference = 'Continue'
Write-Host "`nAtivar TURBO..." -ForegroundColor Cyan

# Use the built-in High performance plan while plugged in.
powercfg.exe /setactive SCHEME_MIN

# Prefer interactive foreground responsiveness; do not use Realtime priority.
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' -Name Win32PrioritySeparation -Type DWord -Value 38

# Reduce visual overhead.
$visual = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
New-Item -Path $visual -Force | Out-Null
Set-ItemProperty -Path $visual -Name VisualFXSetting -Type DWord -Value 2

$personalize = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
New-Item -Path $personalize -Force | Out-Null
Set-ItemProperty -Path $personalize -Name EnableTransparency -Type DWord -Value 0

$desktop = 'HKCU:\Control Panel\Desktop'
Set-ItemProperty -Path $desktop -Name MenuShowDelay -Type String -Value '0'

$advanced = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
New-Item -Path $advanced -Force | Out-Null
Set-ItemProperty -Path $advanced -Name TaskbarAnimations -Type DWord -Value 0
Set-ItemProperty -Path $advanced -Name TaskbarDa -Type DWord -Value 0
Set-ItemProperty -Path $advanced -Name TaskbarMn -Type DWord -Value 0

# Disable Game DVR capture only; leave Xbox services alone unless needed.
$gameDvr = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR'
New-Item -Path $gameDvr -Force | Out-Null
Set-ItemProperty -Path $gameDvr -Name AppCaptureEnabled -Type DWord -Value 0
$gameConfig = 'HKCU:\System\GameConfigStore'
New-Item -Path $gameConfig -Force | Out-Null
Set-ItemProperty -Path $gameConfig -Name GameDVR_Enabled -Type DWord -Value 0

# Disable only optional telemetry/maps/retail demo/Xbox services.
$optional = @('DiagTrack','dmwappushservice','MapsBroker','RetailDemo',
              'XboxGipSvc','XblAuthManager','XblGameSave','XboxNetApiSvc')
foreach ($name in $optional) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc) {
        Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
        Set-Service -Name $name -StartupType Disabled -ErrorAction SilentlyContinue
    }
}

# Preserve memory compression and automatically managed pagefile.
try { Enable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue } catch {}
try {
    $cs = Get-CimInstance Win32_ComputerSystem
    if (-not $cs.AutomaticManagedPagefile) {
        $cs.AutomaticManagedPagefile = $true
        Set-CimInstance -InputObject $cs | Out-Null
    }
} catch {}

Write-Host "`nTURBO ativo. Reinicia o Windows para aplicar todas as alterações." -ForegroundColor Green
'@
    Set-Content -Path (Join-Path $Root 'TurboON.ps1') -Value $turboOn -Encoding UTF8

    # Generate TurboOFF: restore exact exported registry keys, service modes, and original power plan.
    $turboOff = @'
#requires -Version 5.1
#requires -RunAsAdministrator
$ErrorActionPreference = 'Continue'
$Root = 'C:\Win11Turbo'
$Backup = Join-Path $Root 'Backup'
Write-Host "`nRestaurar configuração anterior..." -ForegroundColor Cyan

$regFiles = @(
    'PriorityControl.reg','VisualEffects.reg','Personalize.reg','Desktop.reg',
    'ExplorerAdvanced.reg','GameConfigStore.reg','GameDVR.reg'
)
foreach ($file in $regFiles) {
    $path = Join-Path $Backup $file
    if (Test-Path $path) {
        & reg.exe import $path | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Warning "Falhou a reposição de $file" }
    }
}

$serviceFile = Join-Path $Backup 'OriginalServices.json'
if (Test-Path $serviceFile) {
    $states = @(Get-Content $serviceFile -Raw | ConvertFrom-Json)
    foreach ($item in $states) {
        $mode = switch ($item.StartMode) {
            'Auto'     { 'Automatic' }
            'Manual'   { 'Manual' }
            'Disabled' { 'Disabled' }
            default    { $null }
        }
        if ($mode) {
            Set-Service -Name $item.Name -StartupType $mode -ErrorAction SilentlyContinue
        }
        if ($item.State -eq 'Running') {
            Start-Service -Name $item.Name -ErrorAction SilentlyContinue
        } elseif ($item.State -eq 'Stopped') {
            Stop-Service -Name $item.Name -Force -ErrorAction SilentlyContinue
        }
    }
}

$planFile = Join-Path $Backup 'OriginalPowerPlan.txt'
if (Test-Path $planFile) {
    $guid = (Get-Content $planFile -Raw).Trim()
    if ($guid -match '^[0-9a-fA-F-]{36}$') {
        & powercfg.exe /setactive $guid
    }
}

Write-Host "`nReposição concluída. Reinicia o Windows." -ForegroundColor Green
'@
    Set-Content -Path (Join-Path $Root 'TurboOFF.ps1') -Value $turboOff -Encoding UTF8

    # Generate Diagnose.
    $diagnose = @'
#requires -Version 5.1
$ErrorActionPreference = 'SilentlyContinue'
Write-Host "`n=== DIAGNÓSTICO WINDOWS / ASUS VIVOBOOK ===" -ForegroundColor Cyan

$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor
$freeMB = [math]::Round($os.FreePhysicalMemory / 1KB)
$usedGB = [math]::Round(($cs.TotalPhysicalMemory / 1GB) - ($os.FreePhysicalMemory / 1MB / 1024), 2)

[pscustomobject]@{
    CPU = $cpu.Name
    RAM_Total_GB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    RAM_Em_Uso_GB = $usedGB
    RAM_Disponivel_MB = $freeMB
    Windows = $os.Caption
    Build = $os.BuildNumber
} | Format-List

Write-Host "`nDISCOS" -ForegroundColor Yellow
Get-PhysicalDisk | Select-Object FriendlyName,MediaType,BusType,Size,HealthStatus | Format-Table -AutoSize
Get-CimInstance Win32_DiskDrive | Select-Object Model,InterfaceType,MediaType,@{N='GB';E={[math]::Round($_.Size/1GB,1)}} | Format-Table -AutoSize

Write-Host "`nTOP 20 PROCESSOS POR RAM (Working Set)" -ForegroundColor Yellow
Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 20 Name,
    @{N='RAM_MB';E={[math]::Round($_.WorkingSet64/1MB,0)}},
    @{N='CPU_Segundos';E={if ($_.CPU -ne $null) {[math]::Round($_.CPU,1)} else {0}}} | Format-Table -AutoSize

Write-Host "`nARRANQUE" -ForegroundColor Yellow
Get-CimInstance Win32_StartupCommand | Select-Object Name,Location,Command | Format-Table -Wrap -AutoSize

Write-Host "`nPAGEFILE" -ForegroundColor Yellow
Get-CimInstance Win32_PageFileUsage | Select-Object Name,AllocatedBaseSize,CurrentUsage,PeakUsage | Format-Table -AutoSize

Write-Host "`nSERVIÇOS RELEVANTES" -ForegroundColor Yellow
Get-CimInstance Win32_Service -Filter "Name='SysMain' OR Name='WSearch' OR Name='BITS' OR Name='wuauserv' OR Name='WinDefend'" |
    Select-Object Name,State,StartMode | Format-Table -AutoSize

Write-Host "`nPLANO DE ENERGIA" -ForegroundColor Yellow
powercfg.exe /getactivescheme
'@
    Set-Content -Path (Join-Path $Root 'Diagnose.ps1') -Value $diagnose -Encoding UTF8

    $readme = @"
ASUS VivoBook E510MA - Windows 11 Turbo V3

Ficheiros:
  TurboON.ps1  - aplica os ajustes Turbo
  TurboOFF.ps1 - restaura o estado guardado pelo instalador
  Diagnose.ps1 - recolhe informação de hardware, RAM, processos e arranque
  Backup\      - cópias originais usadas pelo TurboOFF
  Install.log  - registo da instalação

Executar em PowerShell como Administrador:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Win11Turbo\TurboON.ps1
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Win11Turbo\TurboOFF.ps1

Diagnóstico (não requer administrador para a maioria dos dados):
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Win11Turbo\Diagnose.ps1

NOTAS:
- O instalador cria os ficheiros e guarda o estado original; não aplica Turbo automaticamente.
- TurboOFF repõe as cópias feitas nesta instalação.
- Não apaga a pasta C:\Win11Turbo enquanto quiseres poder restaurar.
- Pagefile, Defender, Windows Update, SysMain e WSearch não são desativados pelo Turbo.
"@
    Set-Content -Path (Join-Path $Root 'README.txt') -Value $readme -Encoding UTF8

    Write-Host "`nInstalação concluída. Não foram aplicados tweaks ainda." -ForegroundColor Green
    Write-Host "Ficheiros criados em $Root"
    Write-Host "  TurboON.ps1"
    Write-Host "  TurboOFF.ps1"
    Write-Host "  Diagnose.ps1"
    Write-Host "`nPróximo passo: reinicia e executa Diagnose.ps1; depois decide se queres ativar TurboON."
}
finally {
    Stop-Transcript | Out-Null
}
