# System events and crash analysis data collection module for ECG Diagnostic
# Collects System/Application logs, WHEA, BugChecks, Minidumps and App Crashes

function Invoke-CollectionEvents {
    param(
        [int]$EventDays = 30,
        [int]$CrashDays = 30
    )

    Show-Step "A analisar eventos de sistema (ultimos $EventDays dias)..."
    $Since = (Get-Date).AddDays(-$EventDays)
    $Ev = [ordered]@{}
    $BugCodeSources = @{}

    Invoke-Step "Events.Storage" {
        $phys = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = @('disk', 'stornvme', 'storahci', 'iaStorA', 'iaStorAVC'); Level = 1, 2, 3; StartTime = $Since } 'PhysicalStorage')
        $Ev.PhysicalStorageErrors   = @(Group-EventSummary -Events @($phys | Where-Object { $_.Level -le 2 }) -Map $StorageEventMap)
        $Ev.PhysicalStorageWarnings = @(Group-EventSummary -Events @($phys | Where-Object { $_.Level -eq 3 }) -Map $StorageEventMap)
        $Ev.StorageTrendIncrease    = Get-EventTrendIncrease -Events $phys -TotalDays $EventDays

        $log = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = @('Ntfs', 'volmgr'); Level = 1, 2, 3; StartTime = $Since } 'LogicalFilesystem')
        $Ev.LogicalFilesystemErrors = @(Group-EventSummary -Events $log -Map $StorageEventMap)
    }

    Invoke-Step "Events.Whea" {
        $w = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = $Since } 'WHEA')
        $Ev.WHEA_Fatal     = @($w | Where-Object { $_.Level -le 2 } | Group-Object Id | Select-Object Count, Name)
        $Ev.WHEA_Corrected = @($w | Where-Object { $_.Level -gt 2 } | Group-Object Id | Select-Object Count, Name)
        $Ev.WheaTrendIncrease = Get-EventTrendIncrease -Events $w -TotalDays $EventDays
    }

    Invoke-Step "Events.KernelPower" {
        $kpRaw = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $Since } 'KernelPower41')
        $withBc = 0; $dirtyCnt = 0
        foreach ($e in $kpRaw) {
            [int64]$code = 0
            $map = Get-EventDataMap $e
            if ($map.ContainsKey('BugcheckCode')) { [void][int64]::TryParse($map['BugcheckCode'], [ref]$code) }
            if ($code -ne 0) {
                $withBc++
                $k = '0x{0:X}' -f $code
                if (-not $BugCodeSources.ContainsKey($k)) { $BugCodeSources[$k] = @{} }
                $BugCodeSources[$k]['KernelPower41'] = 1 + [int]$BugCodeSources[$k]['KernelPower41']
            } else { $dirtyCnt++ }
        }
        $Ev.KernelPower41 = [ordered]@{ TotalCount = $kpRaw.Count; CrashesWithBugcheck = $withBc; DirtyPowerLosses = $dirtyCnt }
    }

    Invoke-Step "Events.Misc" {
        $Ev.CpuThrottlingEvents = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Processor-Power'; Id = 37; StartTime = $Since } 'Throttling').Count
        $Ev.DisplayTDR_Count    = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Display'; Id = 4101; StartTime = $Since } 'DisplayTDR').Count
        $Ev.ResourceExhaustion_Count = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Resource-Exhaustion-Detector'; Id = 2004; StartTime = $Since } 'ResourceExhaustion').Count
        $md = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results'; StartTime = (Get-Date).AddDays(-90) } 'MemoryDiagnostics')
        $last = ($md | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
        $Ev.MemoryDiagnostics = [ordered]@{
            Runs90d = @($md | Where-Object { $_.Id -in 1201, 1202 }).Count
            RunsWithErrors = @($md | Where-Object { $_.Id -eq 1202 }).Count
            LastEvent = if ($last) { $last.ToString('yyyy-MM-dd') } else { $null }
        }
    }

    Invoke-Step "Events.Misc2" {
        $Ev.VSS = @(Get-EventsSafe @{ LogName = 'Application'; ProviderName = @('VSS','Microsoft-Windows-Security-SPP'); Level = 1,2; StartTime = $Since } 'VSS').Count
        $Ev.AudioCrash = @(Get-EventsSafe @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000; StartTime = $Since } 'Audio' | Where-Object { $_.Message -match 'audiodg\.exe' }).Count
        $Ev.USB_BTH = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = @('Microsoft-Windows-USB-USBHUB3','BTHUSB'); Level = 1,2; StartTime = $Since } 'USB').Count
    }
    $Report.Facts.AggregatedEvents = $Ev

    Show-Step "A analisar crashes (com deteção do driver em falha)..."
    Invoke-Step "Crashes.Dumps" {
        $folder = "$env:SystemRoot\Minidump"
        $files = @()
        if (Test-Path $folder) { $files = @(Get-ChildItem -Path $folder -Filter "*.dmp" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending) }
        $script:DumpCount = $files.Count
        $script:LatestDumpDt = if ($files.Count -gt 0) { $files[0].LastWriteTime } else { $null }
        $dumpRows = @()
        foreach ($f in ($files | Select-Object -First 10)) {
            $hdr = Read-MinidumpBugCheck -Path $f.FullName
            $code = if ($hdr -and $hdr.Code -ne 0) { '0x{0:X}' -f $hdr.Code } else { $null }
            if ($code) {
                if (-not $BugCodeSources.ContainsKey($code)) { $BugCodeSources[$code] = @{} }
                $BugCodeSources[$code]['Minidump'] = 1 + [int]$BugCodeSources[$code]['Minidump']
            }
            $dumpRows += [ordered]@{ File = $f.Name; Modified = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'); SizeKB = [math]::Round($f.Length / 1KB, 0); BugCheck = $code }
        }
        $Report.Facts.CrashDumps = [ordered]@{
            MinidumpCount      = $files.Count
            LatestMinidumpDate = if ($script:LatestDumpDt) { $script:LatestDumpDt.ToString("yyyy-MM-dd HH:mm:ss") } else { "Nenhum" }
            Dumps              = $dumpRows
        }
    }

    Invoke-Step "Crashes.BugCheckEvents" {
        $ev1001 = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001; StartTime = (Get-Date).AddDays($CrashDays * -1) } 'BugCheck1001')
        foreach ($e in $ev1001) {
            $txt = if ($e.Properties.Count -gt 0) { "$($e.Properties[0].Value)" } else { "" }
            $m = [regex]::Match($txt, '0x[0-9a-fA-F]+')
            if ($m.Success) {
                $k = '0x{0:X}' -f ([Convert]::ToInt64($m.Value.Substring(2), 16))
                if (-not $BugCodeSources.ContainsKey($k)) { $BugCodeSources[$k] = @{} }
                $BugCodeSources[$k]['Event1001'] = 1 + [int]$BugCodeSources[$k]['Event1001']
                
                # Extrair modulo do BugCheck
                if ($txt -match '(?i)(?:cabecalho|ficheiro|driver|modulo|symbol name|file):\s*([a-zA-Z0-9_\-]+\.(?:sys|dll|exe))') {
                    $mod = $Matches[1].ToLower()
                    if (-not $BugCodeSources[$k].ContainsKey("Culpado_$mod")) { $BugCodeSources[$k]["Culpado_$mod"] = 0 }
                    $BugCodeSources[$k]["Culpado_$mod"]++
                }
            }
        }
        $analysis = @()
        foreach ($k in $BugCodeSources.Keys) {
            $info = Get-BugCheckInfo -Code ([Convert]::ToInt64($k.Substring(2), 16)) -Table $BugCheckTable
            $srcs = $BugCodeSources[$k]
            
            $analysis += [ordered]@{
                Code = $info.Code; Name = $info.Name; Category = $info.Category
                Occurrences = ($srcs['Event1001'] + $srcs['Minidump'] + $srcs['KernelPower41'])
                Sources = (($srcs.Keys | Where-Object { $_ -notlike "Culpado_*" } | Sort-Object) -join ", ")
                RootCauseModules = (($srcs.Keys | Where-Object { $_ -like "Culpado_*" }) -join ", ")
            }
        }
        if (-not $Report.Facts.CrashDumps) { $Report.Facts.CrashDumps = [ordered]@{} }
        $Report.Facts.CrashDumps.BugcheckAnalysis = @($analysis | Sort-Object { $_.Occurrences } -Descending)
    }

    Invoke-Step "Crashes.Stability" {
        $rel = Get-CimInstance Win32_ReliabilityStabilityMetrics -ErrorAction SilentlyContinue | Sort-Object TimeGenerated -Descending | Select-Object -First 1
        $Report.Facts.CrashDumps.SystemStabilityIndex = if ($rel) { [math]::Round([double]$rel.SystemStabilityIndex, 1) } else { $null }
        $rc = Get-CimInstance Win32_OSRecoveryConfiguration -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($rc) { $Report.Facts.CrashDumps.DumpSettings = [ordered]@{ DebugInfoType = $rc.DebugInfoType; AutoReboot = $rc.AutoReboot } }
    }

    Invoke-Step "Crashes.Applications" {
        $crash = @(Get-EventsSafe @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000; StartTime = $Since } 'AppError1000')
        $hang  = @(Get-EventsSafe @{ LogName = 'Application'; ProviderName = 'Application Hang'; Id = 1002; StartTime = $Since } 'AppHang1002')
        $rows = @()
        foreach ($e in $crash) {
            if ($e.Properties.Count -ge 4) { $rows += [pscustomobject]@{ App = "$($e.Properties[0].Value)"; Module = "$($e.Properties[3].Value)" } }
        }
        $hangApps = @{}
        foreach ($e in $hang) { if ($e.Properties.Count -ge 1) { $a = "$($e.Properties[0].Value)"; $hangApps[$a] = 1 + [int]$hangApps[$a] } }
        $top = @($rows | Group-Object App | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
            $mod = ($_.Group | Group-Object Module | Sort-Object Count -Descending | Select-Object -First 1).Name
            [ordered]@{ App = $_.Name; Crashes = $_.Count; TopFaultingModule = $mod; Hangs = [int]$hangApps[$_.Name] }
        })
        $Report.Facts.AppCrashes = [ordered]@{
            Crashes1000 = $crash.Count; Hangs1002 = $hang.Count
            TrendIncrease = Get-EventTrendIncrease -Events $crash -TotalDays $EventDays
            DistinctCrashingApps = @($rows | Select-Object -ExpandProperty App -Unique).Count
            TopApps = $top
        }
    }

    $rrRaw = @(Invoke-TimedStep "Crashes.ReliabilityRecords" {
        param($SinceDt)
        $dm = [Management.ManagementDateTimeConverter]::ToDmtfDateTime($SinceDt)
        try { $r = Get-CimInstance Win32_ReliabilityRecords -Filter "TimeGenerated >= '$dm'" -ErrorAction Stop }
        catch { $r = Get-CimInstance Win32_ReliabilityRecords -ErrorAction SilentlyContinue | Where-Object { $_.TimeGenerated -ge $SinceDt } }
        $r | Select-Object SourceName, EventIdentifier, ProductName, TimeGenerated
    } -ArgumentList @($Since) -TimeoutSec 45)
    $relTop = @($rrRaw | Where-Object { $_.SourceName -match 'Application|Windows Error|Hang' -and $_.ProductName } |
        Group-Object ProductName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { [ordered]@{ Product = $_.Name; Failures = $_.Count } })
    if ($Report.Facts.AppCrashes) {
        $Report.Facts.AppCrashes.ReliabilityTop = $relTop
        $Report.Facts.AppCrashes.ReliabilityRecordsTotal = $rrRaw.Count
    }
}
