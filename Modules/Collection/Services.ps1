# Windows services, updates, drivers and security collection module for ECG Diagnostic

function Invoke-CollectionServices {
    param(
        [bool]$DeepIntegrity = $false,
        [int]$BootDays = 14,
        [int]$SampleSeconds = 4,
        [bool]$ExtendedMode = $false
    )

    $Since = (Get-Date).AddDays(-30)

Show-Step "A inspecionar servicos, atualizacoes, integridade, arranque e drivers..."
Invoke-Step "Services" {
    $Report.Facts.FaultedServices = @(Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" -ErrorAction SilentlyContinue |
        Where-Object { $_.ExitCode -ne 0 -and $_.ExitCode -ne 1077 } |
        Sort-Object Name | Select-Object -First 10 Name, DisplayName, State, ExitCode)
    $scm = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7000, 7001, 7009, 7011, 7022, 7023, 7024, 7031, 7034; StartTime = $Since } 'SCM')
    $rows = foreach ($e in $scm) {
        $nm = (@($e.Properties | ForEach-Object { "$($_.Value)" } | Where-Object { $_ -and $_ -notmatch '^\d+$' }) | Select-Object -First 1)
        [pscustomobject]@{ Key = "$($e.Id)|$nm"; Id = $e.Id }
    }
    $Report.Facts.ServiceControlManagerEvents = @($rows | Group-Object Key | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { [ordered]@{ Event = $_.Name; Count = $_.Count } })
}

Invoke-Step "Updates" {
    $wu = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; Id = 20, 25, 31; StartTime = (Get-Date).AddDays(-30) } 'WindowsUpdateFailures')
    $lastOk = $null
    try {
        $s = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install' -ErrorAction Stop).LastSuccessTime
        if ($s) { $lastOk = [datetime]$s }
    } catch { }
    $Report.Facts.Updates = [ordered]@{
        FailureEvents30d = $wu.Count
        FailureIds = @($wu | Group-Object Id | ForEach-Object { [ordered]@{ Id = $_.Name; Count = $_.Count } })
        LastSuccessfulInstall = if ($lastOk) { $lastOk.ToString('yyyy-MM-dd') } else { $null }
        DaysSinceLastInstall = if ($lastOk) { [int]((Get-Date) - $lastOk).TotalDays } else { $null }
    }
}

$hotfix = @(Invoke-TimedStep "Updates.Hotfixes" {
    Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 3 HotFixID, Description, InstalledOn
} -TimeoutSec 30)
$Report.Facts.RecentHotfixes = $hotfix
if ($null -ne $Report.Facts.Updates -and -not $Report.Facts.Updates.LastSuccessfulInstall -and $hotfix.Count -gt 0 -and $hotfix[0].InstalledOn) {
    $Report.Facts.Updates.LastSuccessfulInstall = ([datetime]$hotfix[0].InstalledOn).ToString('yyyy-MM-dd')
    $Report.Facts.Updates.DaysSinceLastInstall = [int]((Get-Date) - [datetime]$hotfix[0].InstalledOn).TotalDays
    $Report.Facts.Updates.LastInstallSource = 'Get-HotFix'
}

Invoke-Step "OsSupport" {
    $info = Get-OsSupportInfo -Build ([int]$script:OS.BuildNumber) -Caption "$($script:OS.Caption)" -Table $OsSupportTable -Now (Get-Date)
    $Report.Facts.OsSupport = if ($info) { $info } else { [pscustomobject]@{ Label = 'N/A'; OutOfSupport = $false } }
}

Invoke-Step "DriverDates" {
    $Report.Facts.OldDrivers = Test-DriverDates -MaxAgeDays 180
}

$DismHealth = "Nao verificado"
if (-not $script:IsAdmin) {
    $DismHealth = "Nao verificado (requer admin)"
    $script:Coverage.Add([pscustomobject]@{ Name = 'DISM'; Status = 'Skipped'; Seconds = 0; Error = 'requer admin' })
} else {
    $img = @(Invoke-TimedStep "DISM" { Repair-WindowsImage -Online -CheckHealth -ErrorAction Stop } -TimeoutSec 120)
    if ($img.Count -gt 0) {
        $DismHealth = switch ("$($img[0].ImageHealthState)") {
            "Healthy"       { "Saudavel" }
            "Repairable"    { "Corrompido (Reparavel)" }
            "NonRepairable" { "Corrompido (Nao reparavel)" }
            default         { "Indeterminado" }
        }
    }
}
$Report.Facts.ComponentStoreHealth = $DismHealth

if ($DeepIntegrity) {
    if (-not $script:IsAdmin) {
        $Report.Facts.SFC_Status = "Nao verificado (requer admin)"
        $script:Coverage.Add([pscustomobject]@{ Name = 'SFC'; Status = 'Skipped'; Seconds = 0; Error = 'requer admin' })
    } else {
        Write-Host "    [DeepIntegrity] A executar SFC /verifyonly (pode demorar 1-3 min)..." -ForegroundColor Yellow
        $sfcSw = [System.Diagnostics.Stopwatch]::StartNew()
        $sfcTmp = Join-Path $env:TEMP ("ecg_sfc_{0}.txt" -f ([guid]::NewGuid().ToString('N')))
        $sfcStatus = 'Indeterminado'; $sfcEntry = [ordered]@{ Name = 'SFC'; Status = 'Ok'; Seconds = 0; Error = $null }
        try {
            $proc = Start-Process -FilePath "$env:SystemRoot\System32\sfc.exe" -ArgumentList '/verifyonly' -NoNewWindow -PassThru -RedirectStandardOutput $sfcTmp
            if ($proc.WaitForExit(300000)) {
                $sfcOut = ""
                if (Test-Path $sfcTmp) { $sfcOut = (Get-Content -Path $sfcTmp -Raw -Encoding Unicode -ErrorAction SilentlyContinue) -replace "`0", "" }
                if ($sfcOut -match 'did not find any integrity violations|n.{1,2}o encontrou nenhuma viola') { $sfcStatus = 'Integro' }
                elseif ($sfcOut -match 'found integrity violations|encontrou viola') { $sfcStatus = 'Violacoes Encontradas' }
            } else {
                try { $proc.Kill() } catch { }
                $sfcEntry.Status = 'Timeout'; $sfcEntry.Error = 'excedeu 300 s'
            }
        } catch { $sfcEntry.Status = 'Failed'; $sfcEntry.Error = $_.Exception.Message }
        finally { Remove-Item -Path $sfcTmp -Force -ErrorAction SilentlyContinue }
        $sfcSw.Stop(); $sfcEntry.Seconds = [math]::Round($sfcSw.Elapsed.TotalSeconds, 2)
        $script:Coverage.Add([pscustomobject]$sfcEntry)
        $Report.Facts.SFC_Status = $sfcStatus
    }
}

$startupRaw = @(Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue)
$startupRes = @(Invoke-TimedStep "StartupSignatures" {
    param($Items)
    foreach ($it in @(@($Items) | Select-Object -First 40)) {
        $c = [Environment]::ExpandEnvironmentVariables(("$($it.Command)").Trim())
        $exe = $null
        if ($c.StartsWith('"')) { $e = $c.IndexOf('"', 1); if ($e -gt 1) { $exe = $c.Substring(1, $e - 1) } }
        if (-not $exe) {
            $m = [regex]::Match($c, '^(.+?\.(?:exe|com|bat|cmd|lnk|msc|scr|vbs|ps1|dll))(?:\s|$)', 'IgnoreCase')
            $exe = if ($m.Success) { $m.Groups[1].Value } else { ($c -split '\s+')[0] }
        }
        $exists = $false; $sig = 'N/A'; $signer = $null
        if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf -ErrorAction SilentlyContinue)) {
            $exists = $true
            $s = Get-AuthenticodeSignature -FilePath $exe -ErrorAction SilentlyContinue
            if ($s) { $sig = "$($s.Status)"; if ($s.SignerCertificate) { $signer = $s.SignerCertificate.Subject } }
        }
        [pscustomobject]@{
            Name = "$($it.Name)"; Executable = $exe; Exists = $exists; Signature = $sig; Signer = $signer
            SuspiciousPath = [bool]($exe -match '\\AppData\\|\\Temp\\|\\Users\\Public\\|\\ProgramData\\')
            Location = "$($it.Location)"; User = "$($it.User)"
        }
    }
} -ArgumentList @(, $startupRaw) -TimeoutSec 60)
$Report.Facts.StartupItems = $startupRes

$drvRaw = @(Invoke-TimedStep "Drivers" {
    Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object { $_.DeviceName } |
        Select-Object DeviceName, DeviceClass, Manufacturer, DriverVersion, DriverDate, IsSigned, InfName
} -TimeoutSec 60)
$oldCut = (Get-Date).AddYears(-4)
$unsignedDrv = @($drvRaw | Where-Object { $_.IsSigned -eq $false })
$oldDrv = @($drvRaw | Where-Object { $_.DriverDate -and $_.DriverDate -lt $oldCut -and $_.DeviceClass -in 'DISPLAY', 'NET', 'HDC', 'SCSIADAPTER', 'BLUETOOTH', 'MEDIA' } | Sort-Object DriverDate | Select-Object -First 8)
$Report.Facts.Drivers = [ordered]@{
    Total = $drvRaw.Count
    UnsignedCount = $unsignedDrv.Count
    Unsigned = @($unsignedDrv | Select-Object -First 8 | ForEach-Object { [ordered]@{ Device = "$($_.DeviceName)"; Class = "$($_.DeviceClass)"; Inf = "$($_.InfName)" } })
    OldCriticalDrivers = @($oldDrv | ForEach-Object { [ordered]@{ Device = "$($_.DeviceName)"; Class = "$($_.DeviceClass)"; Date = $_.DriverDate.ToString('yyyy-MM-dd'); Version = "$($_.DriverVersion)" } })
}

# V3: Chamada lenta para PnPErrors agora dentro de Runspace
$badPnP = @(Invoke-TimedStep "PnPErrors" {
    Get-CimInstance Win32_PnPEntity -Filter "ConfigManagerErrorCode <> 0" | Where-Object { $_.ConfigManagerErrorCode -notin 22, 24, 45 } | Select-Object Name, PNPClass, ConfigManagerErrorCode
} -TimeoutSec 45)
$codes = @{ 1 = 'mal configurado'; 3 = 'driver corrompido/pouca memoria'; 10 = 'nao consegue iniciar'; 12 = 'recursos insuficientes'; 14 = 'requer reinicio'; 18 = 'reinstalar drivers'; 19 = 'registo corrompido'; 28 = 'drivers nao instalados'; 31 = 'nao funciona corretamente'; 39 = 'driver corrompido/em falta'; 43 = 'o Windows parou o dispositivo (reportou problemas)'; 52 = 'assinatura digital nao verificada' }
$Report.Facts.PnPErrors = @($badPnP | Select-Object -First 10 | ForEach-Object {
    [ordered]@{ Name = "$($_.Name)"; Class = "$($_.PNPClass)"; Code = [int]$_.ConfigManagerErrorCode; Meaning = if ($codes.ContainsKey([int]$_.ConfigManagerErrorCode)) { $codes[[int]$_.ConfigManagerErrorCode] } else { 'ver Gestor de Dispositivos' } }
})
$Report.Facts.PnPErrorCount = $badPnP.Count

Invoke-Step "Boot" {
    $b100 = @(Get-EventsSafe @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100; StartTime = (Get-Date).AddDays($BootDays * -1) } 'BootPerf100')
    $secs = @()
    foreach ($e in $b100) {
        $map = Get-EventDataMap $e
        $v = 0.0
        if ($map.ContainsKey('BootTime') -and [double]::TryParse($map['BootTime'], [ref]$v) -and $v -gt 0) { $secs += ($v / 1000.0) }
    }
    $deg = @(Get-EventsSafe @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 101, 102, 103, 106, 109, 110; StartTime = (Get-Date).AddDays($BootDays * -1) } 'BootDegradation')
    $degRows = foreach ($e in $deg) {
        $map = Get-EventDataMap $e
        $nm = if ($map.ContainsKey('Name')) { $map['Name'] } elseif ($map.ContainsKey('FriendlyName')) { $map['FriendlyName'] } else { '?' }
        [pscustomobject]@{ Key = "$($e.Id)|$nm" }
    }
    $Report.Facts.Boot = [ordered]@{
        DaysAnalyzed = $BootDays; BootsAnalyzed = $secs.Count
        AvgBootSeconds = if ($secs.Count -gt 0) { [math]::Round(($secs | Measure-Object -Average).Average, 1) } else { $null }
        LastBootSeconds = if ($secs.Count -gt 0) { [math]::Round($secs[0], 1) } else { $null }
        SlowBoots = @($secs | Where-Object { $_ -ge 120 }).Count
        FastStartupEnabled = $script:FastStartup
        DegradingItems = @($degRows | Group-Object Key | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { [ordered]@{ Item = $_.Name; Count = $_.Count } })
    }
}

# ==========================================================================
# 9. SEGURANCA
# ==========================================================================
Show-Step "A verificar seguranca: antivirus, firewall, agendador de tarefas e auditorias..."
$Report.Facts.Security = [ordered]@{ Defender = $null; ThirdPartyAV = @(); Firewall = @(); BitLocker = @(); Tpm = $null; SecureBoot = $null }

$mp = @(Invoke-TimedStep "Security.Defender" {
    Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled, RealTimeProtectionEnabled, AntivirusEnabled, AntivirusSignatureAge, AntivirusSignatureLastUpdated, QuickScanAge, FullScanAge, IsTamperProtected
} -TimeoutSec 30)
if ($mp.Count -gt 0) {
    $m0 = $mp[0]
    $Report.Facts.Security.Defender = [ordered]@{
        ServiceEnabled = [bool]$m0.AMServiceEnabled; RealTimeProtection = [bool]$m0.RealTimeProtectionEnabled
        SignatureAgeDays = $m0.AntivirusSignatureAge; QuickScanAgeDays = $m0.QuickScanAge; FullScanAgeDays = $m0.FullScanAge
        TamperProtected = $m0.IsTamperProtected
    }
}

Invoke-Step "Security.ThirdPartyAV" {
    $av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object {
        $st = Get-AvState -ProductState ([uint32]$_.productState)
        [ordered]@{ Name = "$($_.displayName)"; Enabled = $st.Enabled; UpToDate = $st.UpToDate; Snoozed = $st.Snoozed }
    })
    $Report.Facts.Security.ThirdPartyAV = $av
}

Invoke-Step "Security.Firewall" {
    $Report.Facts.Security.Firewall = @(Get-NetFirewallProfile -All -ErrorAction Stop | ForEach-Object { [ordered]@{ Profile = "$($_.Name)"; Enabled = "$($_.Enabled)" } })
}

$bl = @(Invoke-TimedStep "Security.BitLocker" -RequiresAdmin {
    Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -ErrorAction Stop | Select-Object DriveLetter, ProtectionStatus
} -TimeoutSec 30)
$Report.Facts.Security.BitLocker = @($bl | ForEach-Object { [ordered]@{ Drive = "$($_.DriveLetter)"; Protected = ([int]$_.ProtectionStatus -eq 1) } })

$tpmRes = @(Invoke-TimedStep "Security.TpmSecureBoot" -RequiresAdmin {
    $t = $null; $sb = 'N/A'
    try { $t = Get-Tpm -ErrorAction Stop | Select-Object TpmPresent, TpmReady } catch { }
    try { $sb = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { }
    [pscustomobject]@{ TpmPresent = if ($t) { [bool]$t.TpmPresent } else { $null }; TpmReady = if ($t) { [bool]$t.TpmReady } else { $null }; SecureBoot = $sb }
} -TimeoutSec 20)
if ($tpmRes.Count -gt 0) {
    $Report.Facts.Security.Tpm = [ordered]@{ Present = $tpmRes[0].TpmPresent; Ready = $tpmRes[0].TpmReady }
    $Report.Facts.Security.SecureBoot = $tpmRes[0].SecureBoot
}

# Auditoria V3: Tarefas Agendadas Suspeitas e Administradores Locais
$suspTasks = @(Invoke-TimedStep "Security.ScheduledTasks" -RequiresAdmin {
    Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
        $act = $_.Actions | Where-Object { $_.Execute -match 'AppData|Temp|Public|powershell|cmd|cscript|wscript' }
        if ($act) { [pscustomobject]@{ Name = $_.TaskName; Path = $_.TaskPath; Action = $act.Execute; Args = $act.Arguments } }
    }
} -TimeoutSec 30)
$Report.Facts.Security.SuspiciousTasks = $suspTasks

$admins = @(Invoke-TimedStep "Security.LocalAdmins" {
    $g = Get-LocalGroup | Where-Object { $_.SID -like "S-1-5-32-544" } | Select-Object -First 1
    if ($g) { Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue | Where-Object PrincipalSource -eq 'Local' | Select-Object -ExpandProperty Name }
} -TimeoutSec 20)
$Report.Facts.Security.LocalAdmins = $admins

if ($ExtendedMode) {
    Write-Host "    [Extended] janela de amostragem 3/3..." -ForegroundColor Gray
    Invoke-Step "PerfWindow3" { $script:PerfWindows.Add((Get-PerfWindow -Seconds $SampleSeconds -Cores $script:LogicalCores -Label 'W3')) }
}

}