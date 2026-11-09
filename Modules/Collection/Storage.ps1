# Storage data collection module for ECG Diagnostic
# Collects physical disks, SMART reliability, volumes, TRIM, and dirty bit details

function Invoke-CollectionStorage {
    param(
        [int]$SampleSeconds = 4,
        [bool]$ExtendedMode = $false
    )
    Show-Step "A mapear discos, SMART, volumes, dirty bit e TRIM..."
    
    Invoke-Step "PhysicalDisks" {
        $DiskList = @()
        foreach ($d in @(Get-PhysicalDisk -ErrorAction SilentlyContinue)) {
            $rel = if ($IsAdmin) { Get-StorageReliabilityCounter -PhysicalDisk $d -ErrorAction SilentlyContinue } else { $null }
            $DiskList += [ordered]@{
                DeviceId               = "$($d.DeviceId)"
                FriendlyName           = "$($d.FriendlyName)".Trim()
                MediaType              = "$($d.MediaType)"
                BusType                = "$($d.BusType)"
                HealthStatus           = "$($d.HealthStatus)"
                OperationalStatus      = ($d.OperationalStatus -join ", ")
                SizeGB                 = [math]::Round($d.Size / 1GB, 1)
                TemperatureC           = if ($rel) { $rel.Temperature } else { $null }
                MaxTemperatureC        = if ($rel) { $rel.MaxTemperature } else { $null }
                WearPercentage         = if ($rel) { $rel.Wear } else { $null }
                PowerOnHours           = if ($rel) { $rel.PowerOnHours } else { $null }
                StartStopCycleCount    = if ($rel) { $rel.StartStopCycleCount } else { $null }
                StartStopCycleCountMax = if ($rel) { $rel.StartStopCycleCountMax } else { $null }
                LoadUnloadCycleCount   = if ($rel) { $rel.LoadUnloadCycleCount } else { $null }
                LoadUnloadCycleCountMax = if ($rel) { $rel.LoadUnloadCycleCountMax } else { $null }
                ReadErrorsTotal        = if ($rel) { $rel.ReadErrorsTotal } else { $null }
                WriteErrorsTotal       = if ($rel) { $rel.WriteErrorsTotal } else { $null }
                ReadErrorsUncorrected  = if ($rel) { $rel.ReadErrorsUncorrected } else { $null }
                WriteErrorsUncorrected = if ($rel) { $rel.WriteErrorsUncorrected } else { $null }
                ReadLatencyMaxMs       = if ($rel) { $rel.ReadLatencyMax } else { $null }
                WriteLatencyMaxMs      = if ($rel) { $rel.WriteLatencyMax } else { $null }
            }
        }
        $Report.Facts.PhysicalDisks = $DiskList
    }

    Invoke-Step "SmartPredict" -RequiresAdmin {
        $fail = @(Get-CimInstance -Namespace root/wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue | Where-Object { $_.PredictFailure })
        $Report.Facts.SmartPredictFailure = [ordered]@{ Count = $fail.Count; Instances = @($fail | ForEach-Object { "$($_.InstanceName)" }) }
    }

    Invoke-Step "Volumes" {
        $dirty = @{}
        foreach ($wv in @(Get-CimInstance Win32_Volume -Filter "DriveType=3" -ErrorAction SilentlyContinue)) {
            if ($wv.DriveLetter) { $dirty["$($wv.DriveLetter)".TrimEnd(':')] = [bool]$wv.DirtyBitSet }
        }
        $Report.Facts.Volumes = @(Get-Volume -ErrorAction SilentlyContinue |
            Where-Object { $_.DriveLetter -and $_.Size -gt 0 -and "$($_.DriveType)" -eq 'Fixed' } |
            ForEach-Object {
                $dl = "$($_.DriveLetter)"
                [ordered]@{
                    DriveLetter = $dl
                    FileSystemLabel = "$($_.FileSystemLabel)"
                    FileSystem = "$($_.FileSystem)"
                    SizeGB = [math]::Round($_.Size / 1GB, 1)
                    FreeGB = [math]::Round($_.SizeRemaining / 1GB, 1)
                    FreePct = [math]::Round(($_.SizeRemaining / $_.Size) * 100, 1)
                    DirtyBit = if ($dirty.ContainsKey($dl)) { $dirty[$dl] } else { $null }
                }
            })
    }

    Invoke-Step "Trim" -RequiresAdmin {
        $raw = & fsutil.exe behavior query DisableDeleteNotify 2>$null
        $Report.Facts.Trim = [ordered]@{ NtfsDisableDeleteNotify = (Get-TextField $raw '(?i)NTFS\s+DisableDeleteNotify\s*=\s*(\d)') }
    }

    if ($ExtendedMode) {
        Write-Host "    [Extended] janela de amostragem 2/3..." -ForegroundColor Gray
        Invoke-Step "PerfWindow2" { $script:PerfWindows.Add((Get-PerfWindow -Seconds $SampleSeconds -Cores $script:LogicalCores -Label 'W2')) }
    }
}