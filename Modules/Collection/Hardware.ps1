# Context and Hardware Base collection module for ECG Diagnostic
# Collects OS, CPU, BIOS, Battery, GPU and general platform context

function Invoke-CollectionContext {
    Show-Step "A recolher contexto, hardware base, bateria e GPU..."
    
    $script:OS = Get-CimInstance Win32_OperatingSystem
    $script:CS = Get-CimInstance Win32_ComputerSystem
    $script:CpuCim = Get-CimInstance Win32_Processor | Select-Object -First 1
    $script:BIOS = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    $script:LogicalCores = [Environment]::ProcessorCount
    $script:ChassisTypes = @(Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue | ForEach-Object { $_.ChassisTypes } | ForEach-Object { [int]$_ })
    $script:IsVM = [bool]("$($script:CS.Manufacturer) $($script:CS.Model)" -match 'Virtual|VMware|VirtualBox|KVM|QEMU|Xen|Hyper-V|Parallels|Bochs')
    $script:IsLaptop = [bool](@($script:ChassisTypes | Where-Object { @(8, 9, 10, 11, 14, 30, 31, 32) -contains $_ }).Count)
    $script:Battery = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
    $script:FastStartup = $null
    try { $script:FastStartup = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -ErrorAction Stop).HiberbootEnabled -eq 1) } catch { }

    $Report.Facts.Context = [ordered]@{
        IsVirtualMachine   = $script:IsVM
        IsLaptop           = $script:IsLaptop
        ChassisTypes       = $script:ChassisTypes
        BatteryPresent     = [bool]$script:Battery
        FastStartupEnabled = $script:FastStartup
        IssueProfiles      = $IssueProfiles
    }

    Invoke-Step "HardwareBase" {
        $KernelBaseClock = try { (Get-ItemProperty -Path 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0' -ErrorAction Stop).'~MHz' } catch { [int]$script:CpuCim.MaxClockSpeed }

        $ThermalZoneC = $null
        if (-not $script:IsVM) {
            try {
                $Thermal = Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop | Select-Object -First 1
                if ($Thermal -and $Thermal.CurrentTemperature -gt 2732) { $ThermalZoneC = [math]::Round(($Thermal.CurrentTemperature - 2732) / 10, 1) }
            } catch { }
        }

        $RebootReasons = @()
        $script:RebootStrong = $false
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
            $script:RebootStrong = $true; $RebootReasons += "CBS_RebootPending"
        }
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
            $script:RebootStrong = $true; $RebootReasons += "WindowsUpdate_RebootRequired"
        }
        $FileRename = try { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ErrorAction SilentlyContinue).PendingFileRenameOperations } catch { $null }
        if ($FileRename) { $RebootReasons += "PendingFileRenameOperations" }

        # Power Plan Check
        $pwrScheme = try { (powercfg /getactivescheme 2>$null) -replace '^.+:\s*([0-9a-fA-F-]+)\s+\((.+)\)$','$2' } catch { "Desconhecido" }

        $Report.Facts.System = [ordered]@{
            ComputerName       = $env:COMPUTERNAME
            Manufacturer       = "$($script:CS.Manufacturer)".Trim()
            Model              = "$($script:CS.Model)".Trim()
            OSCaption          = "$($script:OS.Caption)".Trim()
            OSBuild            = $script:OS.BuildNumber
            UptimeDays         = [math]::Round(((Get-Date) - $script:OS.LastBootUpTime).TotalDays, 2)
            RebootPending      = ($RebootReasons.Count -gt 0)
            RebootReasons      = ($RebootReasons -join ", ")
            CPUModel           = "$($script:CpuCim.Name)".Trim()
            LogicalCores       = $script:LogicalCores
            BaseClockMHz       = $KernelBaseClock
            ThermalZone_ACPI_C = $ThermalZoneC
            PowerPlan          = $pwrScheme
            BIOSVersion        = if ($script:BIOS) { $script:BIOS.SMBIOSBIOSVersion } else { "N/A" }
            BIOSDate           = if ($script:BIOS -and $script:BIOS.ReleaseDate) { $script:BIOS.ReleaseDate.ToString('yyyy-MM-dd') } else { $null }
        }
    }

    Invoke-Step "Battery" {
        if (-not $script:Battery) { $Report.Facts.Battery = [ordered]@{ Present = $false }; return }
        $b = [ordered]@{
            Present = $true; ChargePercent = $script:Battery.EstimatedChargeRemaining; Status = $script:Battery.BatteryStatus
            DesignCapacityMWh = $null; FullChargeCapacityMWh = $null; WearPct = $null; CycleCount = $null
        }
        
        try {
            $full = $null
            $stat = $null
            try {
                $full = Get-CimInstance -Namespace root/wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop | Select-Object -First 1
                $stat = Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData -ErrorAction Stop | Select-Object -First 1
            } catch {
                try {
                    $full = Get-WmiObject -Namespace root/wmi -Class BatteryFullChargedCapacity -ErrorAction Stop | Select-Object -First 1
                    $stat = Get-WmiObject -Namespace root/wmi -Class BatteryStaticData -ErrorAction Stop | Select-Object -First 1
                } catch { }
            }
            if ($full -and $stat -and $stat.DesignedCapacity -gt 0) {
                $b.FullChargeCapacityMWh = [int]$full.FullChargedCapacity
                $b.DesignCapacityMWh = [int]$stat.DesignedCapacity
                $b.WearPct = [math]::Max(0, [math]::Round((1 - ($b.FullChargeCapacityMWh / $b.DesignCapacityMWh)) * 100, 1))
            }
        } catch { }
        
        if ($b.WearPct -ge 20) {
            $healthPct = 100 - $b.WearPct
            $severity = if ($b.WearPct -ge 40) { "Critical" } elseif ($b.WearPct -ge 30) { "Warning" } else { "Info" }
            $penalty = if ($b.WearPct -ge 40) { 0.9 } elseif ($b.WearPct -ge 30) { 0.75 } else { 0.5 }
            
            Add-Finding "Hardware" $severity $penalty `
                "Desgaste da bateria: $($b.WearPct)%" `
                "Bateria com $($healthPct)% de saude (desgaste de $($b.WearPct)%). Capacidade atual: $($b.FullChargeCapacityMWh)mWh, Original: $($b.DesignCapacityMWh)mWh." `
                "Considerar substituir a bateria. Baterias com mais de 30% de desgaste tem autonomia significativamente reduzida." 2
            
            Add-Suspect "Hardware" $penalty "Bateria com desgaste de $($b.WearPct)%"
        }
        
        try {
            $cyc = $null
            try {
                $cyc = Get-CimInstance -Namespace root/wmi -ClassName BatteryCycleCount -ErrorAction Stop | Select-Object -First 1
            } catch {
                try {
                    $cyc = Get-WmiObject -Namespace root/wmi -ClassName BatteryCycleCount -ErrorAction Stop | Select-Object -First 1
                } catch { }
            }
            if ($cyc) { $b.CycleCount = [int]$cyc.CycleCount }
        } catch { }
        
        $Report.Facts.Battery = $b
    }

    Invoke-Step "GPU" {
        $Report.Facts.Gpu = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | ForEach-Object {
            [ordered]@{
                Name            = "$($_.Name)"
                DriverVersion   = "$($_.DriverVersion)"
                DriverDate      = if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { $null }
                DriverAgeDays   = if ($_.DriverDate) { [int]((Get-Date) - $_.DriverDate).TotalDays } else { $null }
                Status          = "$($_.Status)"
                ConfigErrorCode = $_.ConfigManagerErrorCode
                RefreshRate     = $_.CurrentRefreshRate
            }
        })
    }
}

