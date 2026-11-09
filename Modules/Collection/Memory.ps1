# Memory and Sampling data collection module for ECG Diagnostic
# Collects CPU/Disk sampling windows, memory usage, WSL/Docker overhead and physical DIMMs

function Invoke-CollectionMemory {
    param(
        [int]$SampleSeconds = 4,
        [bool]$ExtendedMode = $false
    )

    Show-Step "A amostrar CPU, disco e memoria (janela de $SampleSeconds s$(if ($ExtendedMode) { ', modo Extended: 3 janelas' }))..."
    $script:PerfWindows = New-Object System.Collections.Generic.List[object]
    Invoke-Step "PerfWindow1" { $script:PerfWindows.Add((Get-PerfWindow -Seconds $SampleSeconds -Cores $script:LogicalCores -Label 'W1')) }

    Show-Step "A recolher memoria (disponibilidade, pool, commit, processos, WSL)..."
    Invoke-Step "Memory" {
        $PerfMem = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory -ErrorAction SilentlyContinue | Select-Object -First 1
        $TotalRamMB = [int][math]::Round($script:OS.TotalVisibleMemorySize / 1024, 0)
        $FreeOnlyMB = [int][math]::Round($script:OS.FreePhysicalMemory / 1024, 0)
        if ($PerfMem -and $null -ne $PerfMem.AvailableMBytes) {
            $AvailRamMB = [int]$PerfMem.AvailableMBytes; $AvailSource = "PerfOS_Memory.AvailableMBytes"
        } else {
            $AvailRamMB = $FreeOnlyMB; $AvailSource = "Win32_OperatingSystem.FreePhysicalMemory (subestima a memoria disponivel)"
        }
        $CommitTotalMB = if ($PerfMem) { [int][math]::Round($PerfMem.CommittedBytes / 1MB, 0) } else { 0 }
        $CommitLimitMB = if ($PerfMem) { [int][math]::Round($PerfMem.CommitLimit / 1MB, 0) } else { 0 }
        $pf = @(Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue)
        $pfAlloc = ($pf | Measure-Object -Property AllocatedBaseSize -Sum).Sum
        $pfPeak  = ($pf | Measure-Object -Property PeakUsage -Sum).Sum
        $pfCur   = ($pf | Measure-Object -Property CurrentUsage -Sum).Sum

        $vmmem = Get-Process -Name "vmmem*" -ErrorAction SilentlyContinue
        $vmmemMB = if ($vmmem) { [math]::Round(($vmmem | Measure-Object -Property WorkingSet64 -Sum).Sum / 1MB, 0) } else { 0 }

        $Report.Facts.Memory = [ordered]@{
            TotalRAM_MB       = $TotalRamMB
            AvailableRAM_MB   = $AvailRamMB
            AvailableRAM_Pct  = if ($TotalRamMB -gt 0) { [math]::Round(($AvailRamMB / $TotalRamMB) * 100, 1) } else { 0 }
            AvailableSource   = $AvailSource
            UsedRAM_Pct       = if ($TotalRamMB -gt 0) { [math]::Round((($TotalRamMB - $AvailRamMB) / $TotalRamMB) * 100, 1) } else { 0 }
            Committed_MB      = $CommitTotalMB
            CommitLimit_MB    = $CommitLimitMB
            CommitUtilization = if ($CommitLimitMB -gt 0) { [math]::Round(($CommitTotalMB / $CommitLimitMB) * 100, 1) } else { 0 }
            PoolPaged_MB      = if ($PerfMem) { [int][math]::Round($PerfMem.PoolPagedBytes / 1MB, 0) } else { 0 }
            PoolNonPaged_MB   = if ($PerfMem) { [int][math]::Round($PerfMem.PoolNonpagedBytes / 1MB, 0) } else { 0 }
            PageFileActive    = ($pf.Count -gt 0)
            PageFileAllocated_MB = $pfAlloc
            PageFileCurrent_MB   = $pfCur
            PageFilePeak_MB      = $pfPeak
            PageFilePeakPct      = if ($pfAlloc -gt 0) { [math]::Round(100.0 * $pfPeak / $pfAlloc, 1) } else { $null }
            WSL_Docker_RAM_MB    = $vmmemMB
        }

        $procs = @(Get-Process -ErrorAction SilentlyContinue)
        $Report.Facts.TopProcesses = [ordered]@{
            ByPrivateMemory = @($procs | Sort-Object PrivateMemorySize64 -Descending | Select-Object -First 5 | ForEach-Object {
                [ordered]@{ Id = $_.Id; Name = $_.ProcessName; PrivateMB = [math]::Round($_.PrivateMemorySize64 / 1MB, 0); Handles = $_.HandleCount } })
            ByHandles = @($procs | Sort-Object HandleCount -Descending | Select-Object -First 5 | ForEach-Object {
                [ordered]@{ Id = $_.Id; Name = $_.ProcessName; Handles = $_.HandleCount; PrivateMB = [math]::Round($_.PrivateMemorySize64 / 1MB, 0) } })
        }
    }

    Invoke-Step "PhysicalMemory" {
        $dimms = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue)
        $slots = (Get-CimInstance Win32_PhysicalMemoryArray -ErrorAction SilentlyContinue | Measure-Object -Property MemoryDevices -Sum).Sum
        $mods = @($dimms | ForEach-Object {
            [ordered]@{
                Locator = "$($_.DeviceLocator)"; Bank = "$($_.BankLabel)"
                CapacityGB = [math]::Round($_.Capacity / 1GB, 1)
                SpeedMHz = $_.Speed; ConfiguredMHz = $_.ConfiguredClockSpeed
                Manufacturer = "$($_.Manufacturer)".Trim(); PartNumber = "$($_.PartNumber)".Trim()
            } })
        $caps = @($mods | ForEach-Object { $_.CapacityGB } | Select-Object -Unique)
        $spds = @($mods | ForEach-Object { $_.SpeedMHz } | Where-Object { $_ } | Select-Object -Unique)
        $xmpOff = @($mods | Where-Object { $_.SpeedMHz -and $_.ConfiguredMHz -and ($_.ConfiguredMHz -lt (0.9 * $_.SpeedMHz)) }).Count -gt 0
        $Report.Facts.PhysicalMemory = [ordered]@{
            ModuleCount = $mods.Count; SlotCount = $slots
            MismatchedCapacity = ($caps.Count -gt 1); MismatchedSpeed = ($spds.Count -gt 1)
            SingleChannelPossible = ($mods.Count -eq 1 -and $slots -ge 2)
            XmpPossiblyOff = $xmpOff
            Modules = $mods
        }
    }


}