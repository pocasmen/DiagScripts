# Utility functions for ECG Diagnostic
# Common helper functions and lookup tables used across modules

# ==========================================================================
# TABELAS INTERNAS E MAPEAMENTOS GLOBAIS
# ==========================================================================

$BugCheckTable = @{
    '0xA'        = @('IRQL_NOT_LESS_OR_EQUAL', 'Drivers')
    '0x1A'       = @('MEMORY_MANAGEMENT', 'RAM')
    '0x1E'       = @('KMODE_EXCEPTION_NOT_HANDLED', 'Drivers')
    '0x24'       = @('NTFS_FILE_SYSTEM', 'Armazenamento')
    '0x3B'       = @('SYSTEM_SERVICE_EXCEPTION', 'Drivers')
    '0x3D'       = @('INTERRUPT_EXCEPTION_NOT_HANDLED', 'Drivers')
    '0x3F'       = @('NO_MORE_SYSTEM_PTES', 'Drivers')
    '0x4E'       = @('PFN_LIST_CORRUPT', 'RAM')
    '0x50'       = @('PAGE_FAULT_IN_NONPAGED_AREA', 'RAM')
    '0x7A'       = @('KERNEL_DATA_INPAGE_ERROR', 'Armazenamento')
    '0x7B'       = @('INACCESSIBLE_BOOT_DEVICE', 'Armazenamento')
    '0x7E'       = @('SYSTEM_THREAD_EXCEPTION_NOT_HANDLED', 'Drivers')
    '0x7F'       = @('UNEXPECTED_KERNEL_MODE_TRAP', 'CPU/Hardware')
    '0x9C'       = @('MACHINE_CHECK_EXCEPTION', 'CPU/Hardware')
    '0x9F'       = @('DRIVER_POWER_STATE_FAILURE', 'Drivers')
    '0xBE'       = @('ATTEMPTED_WRITE_TO_READONLY_MEMORY', 'Drivers')
    '0xC2'       = @('BAD_POOL_CALLER', 'Drivers')
    '0xC4'       = @('DRIVER_VERIFIER_DETECTED_VIOLATION', 'Drivers')
    '0xC5'       = @('DRIVER_CORRUPTED_EXPOOL', 'Drivers')
    '0xCE'       = @('DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS', 'Drivers')
    '0xD1'       = @('DRIVER_IRQL_NOT_LESS_OR_EQUAL', 'Drivers')
    '0xEA'       = @('THREAD_STUCK_IN_DEVICE_DRIVER', 'GPU')
    '0xEF'       = @('CRITICAL_PROCESS_DIED', 'Software/Sistema')
    '0xF4'       = @('CRITICAL_OBJECT_TERMINATION', 'Armazenamento')
    '0xFC'       = @('ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY', 'Drivers')
    '0x101'      = @('CLOCK_WATCHDOG_TIMEOUT', 'CPU/Hardware')
    '0x109'      = @('CRITICAL_STRUCTURE_CORRUPTION', 'RAM')
    '0x116'      = @('VIDEO_TDR_FAILURE', 'GPU')
    '0x117'      = @('VIDEO_TDR_TIMEOUT_DETECTED', 'GPU')
    '0x119'      = @('VIDEO_SCHEDULER_INTERNAL_ERROR', 'GPU')
    '0x124'      = @('WHEA_UNCORRECTABLE_ERROR', 'CPU/Hardware')
    '0x133'      = @('DPC_WATCHDOG_VIOLATION', 'Drivers')
    '0x139'      = @('KERNEL_SECURITY_CHECK_FAILURE', 'Drivers')
    '0x13A'      = @('KERNEL_MODE_HEAP_CORRUPTION', 'Drivers')
    '0x141'      = @('VIDEO_ENGINE_TIMEOUT_DETECTED', 'GPU')
    '0x154'      = @('UNEXPECTED_STORE_EXCEPTION', 'Armazenamento')
    '0xC000021A' = @('STATUS_SYSTEM_PROCESS_TERMINATED', 'Software/Sistema')
    '0xC0000221' = @('STATUS_IMAGE_CHECKSUM_MISMATCH', 'Armazenamento')
}

$StorageEventMap = @{
    'disk|7'         = 'bloco invalido (bad block)'
    'disk|11'        = 'erro do controlador'
    'disk|15'        = 'dispositivo nao pronto'
    'disk|51'        = 'erro de paginacao no disco'
    'disk|52'        = 'falha prevista pelo disco (SMART)'
    'disk|153'       = 'operacao de I/O repetida (retry)'
    'disk|157'       = 'disco removido inesperadamente'
    'storahci|129'   = 'reset ao dispositivo (timeout)'
    'stornvme|129'   = 'reset ao dispositivo (timeout)'
    'iaStorA|129'    = 'reset ao dispositivo (timeout)'
    'iaStorAVC|129'  = 'reset ao dispositivo (timeout)'
    'Ntfs|50'        = 'delayed write falhou'
    'Ntfs|55'        = 'estrutura NTFS corrompida'
    'Ntfs|98'        = 'volume requer verificacao'
    'Ntfs|140'       = 'write-through falhou'
    'volmgr|46'      = 'falha ao preparar crash dump'
    'volmgr|161'     = 'falha ao criar crash dump'
}

$CriticalStorageIds = @('disk|7', 'disk|11', 'disk|51', 'disk|52', 'storahci|129', 'stornvme|129', 'iaStorA|129', 'iaStorAVC|129', 'Ntfs|55')

$OsSupportTable = @(
    @{ Min = 10240; Max = 19045; Label = 'Windows 10';        Consumer = '2025-10-14'; Enterprise = '2025-10-14' },
    @{ Min = 22000; Max = 22000; Label = 'Windows 11 21H2';   Consumer = '2023-10-10'; Enterprise = '2024-10-08' },
    @{ Min = 22621; Max = 22621; Label = 'Windows 11 22H2';   Consumer = '2024-10-08'; Enterprise = '2025-10-14' },
    @{ Min = 22631; Max = 22631; Label = 'Windows 11 23H2';   Consumer = '2025-11-11'; Enterprise = '2026-11-10' },
    @{ Min = 26100; Max = 26100; Label = 'Windows 11 24H2';   Consumer = '2026-10-13'; Enterprise = '2027-10-12' },
    @{ Min = 26200; Max = 26200; Label = 'Windows 11 25H2';   Consumer = '2027-10-12'; Enterprise = '2028-10-10' }
)

$IssueProfileMap = [ordered]@{
    Performance = 'lent|travar|trava|demor|slow|devagar|pesado|congel'
    Stability   = 'azul|bsod|reinicia|reinicio|desliga|crash|bloque|falha'
    Network     = 'internet|rede|wifi|wi-fi|ligacao|dns|router|ping|sem net'
    Boot        = 'arranque|boot|iniciar|liga devagar|demora a ligar'
    Battery     = 'bateria|carreg|autonomia'
    Display     = 'ecra|video|imagem|grafic|artefact|gpu|monitor|pisca'
    Security    = 'virus|malware|pop-up|popup|publicidade|seguranca|trojan|ransom|infet'
    Storage     = 'disco|ficheiro|espaco|armazen|ssd|hdd|cheio'
}

$IssueFocusMap = @{
    Performance = @('Hardware', 'Memory', 'Storage')
    Stability   = @('Hardware', 'Windows', 'Storage', 'Memory')
    Network     = @('Network')
    Boot        = @('Windows', 'Storage')
    Battery     = @('Hardware')
    Display     = @('Hardware')
    Security    = @('Windows')
    Storage     = @('Storage')
}

# Get average of values
function Get-Avg {
    param($Values)
    $v = @($Values | Where-Object { $null -ne $_ })
    if ($v.Count -eq 0) { return $null }
    return [math]::Round((($v | Measure-Object -Average).Average), 1)
}

# Get maximum of values
function Get-Max {
    param($Values)
    $v = @($Values | Where-Object { $null -ne $_ })
    if ($v.Count -eq 0) { return $null }
    return [math]::Round((($v | Measure-Object -Maximum).Maximum), 1)
}

# Extract text field using regex
function Get-TextField {
    param($Lines, [string]$Pattern)
    foreach ($l in @($Lines)) {
        if ("$l" -match $Pattern) { return $Matches[1].Trim() }
    }
    return $null
}

# Get latency statistics from ping results
function Get-LatencyStats {
    param($Rtts, [int]$Lost, [int]$Sent)
    $r = @($Rtts | ForEach-Object { [double]$_ })
    $recv = $r.Count
    $jit = $null
    if ($recv -ge 2) {
        $s = 0.0
        for ($i = 1; $i -lt $recv; $i++) { $s += [math]::Abs($r[$i] - $r[$i - 1]) }
        $jit = [math]::Round($s / ($recv - 1), 1)
    }
    return [ordered]@{
        Sent      = $Sent
        Received  = $recv
        LossPct   = if ($Sent -gt 0) { [math]::Round(100.0 * ($Sent - $recv) / $Sent, 1) } else { $null }
        MinMs     = if ($recv -gt 0) { ($r | Measure-Object -Minimum).Minimum } else { $null }
        AvgMs     = if ($recv -gt 0) { [math]::Round(($r | Measure-Object -Average).Average, 1) } else { $null }
        MaxMs     = if ($recv -gt 0) { ($r | Measure-Object -Maximum).Maximum } else { $null }
        JitterMs  = $jit
    }
}

# Test ping target
function Test-PingTarget {
    param([string]$Target, [int]$Count = 20, [int]$TimeoutMs = 1000)
    $ping = New-Object System.Net.NetworkInformation.Ping
    $rtts = New-Object System.Collections.Generic.List[double]
    for ($i = 0; $i -lt $Count; $i++) {
        try {
            $r = $ping.Send($Target, $TimeoutMs)
            if ($r.Status -eq 'Success') { $rtts.Add([double]$r.RoundtripTime) }
        } catch { }
        Start-Sleep -Milliseconds 100
    }
    $ping.Dispose()
    return (Get-LatencyStats -Rtts $rtts -Lost ($Count - $rtts.Count) -Sent $Count)
}

# Get AV state from product state
function Get-AvState {
    param([uint32]$ProductState)
    $hex = '{0:X6}' -f $ProductState
    $prod = $hex.Substring(2, 2)
    $sig = $hex.Substring(4, 2)
    return [pscustomobject]@{
        Enabled  = ($prod -eq '10' -or $prod -eq '11')
        Snoozed  = ($prod -eq '01')
        UpToDate = ($sig -eq '00')
    }
}

# Get OS support info
function Get-OsSupportInfo {
    param([int]$Build, [string]$Caption, $Table, [datetime]$Now)
    if ($Caption -match 'Server|LTSC|LTSB|IoT') { return $null }
    $row = $Table | Where-Object { $Build -ge $_.Min -and $Build -le $_.Max } | Select-Object -First 1
    if (-not $row) { return $null }
    $isEnt = ($Caption -match 'Enterprise|Education')
    $eol = [datetime]::ParseExact($(if ($isEnt) { $row.Enterprise } else { $row.Consumer }), 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    $days = [int][math]::Floor(($eol - $Now).TotalDays)
    return [pscustomobject]@{
        Label = $row.Label; Edition = $(if ($isEnt) { 'Enterprise/Education' } else { 'Home/Pro' })
        EndOfSupport = $eol.ToString('yyyy-MM-dd'); DaysToEnd = $days; OutOfSupport = ($days -lt 0)
    }
}

# Get issue profiles from text
function Get-IssueProfiles {
    param([string]$Text, $ProfileMap)
    $t = "$Text".ToLowerInvariant()
    try { $t = [regex]::Replace($t.Normalize([System.Text.NormalizationForm]::FormD), '\p{M}', '') } catch { }
    $found = @()
    foreach ($k in $ProfileMap.Keys) {
        if ($t -match $ProfileMap[$k]) { $found += $k }
    }
    return $found
}

# Get bug check info
function Get-BugCheckInfo {
    param([int64]$Code, $Table)
    $key = '0x{0:X}' -f $Code
    if ($Table.ContainsKey($key)) {
        return [pscustomobject]@{ Code = $key; Name = $Table[$key][0]; Category = $Table[$key][1] }
    }
    return [pscustomobject]@{ Code = $key; Name = 'DESCONHECIDO'; Category = 'Outros' }
}

# Read minidump bug check
function Read-MinidumpBugCheck {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        try {
            $buf = New-Object byte[] 128
            $n = $fs.Read($buf, 0, 128)
        } finally { $fs.Close() }
        if ($n -lt 64) { return $null }
        if ([System.Text.Encoding]::ASCII.GetString($buf, 0, 4) -ne 'PAGE') { return $null }
        $kind = [System.Text.Encoding]::ASCII.GetString($buf, 4, 4)
        if ($kind -eq 'DU64') { return [pscustomobject]@{ Code = [int64][BitConverter]::ToUInt32($buf, 56); Bits = 64 } }
        if ($kind -eq 'DUMP') { return [pscustomobject]@{ Code = [int64][BitConverter]::ToUInt32($buf, 40); Bits = 32 } }
        return $null
    } catch { return $null }
}

# Create trend row
function New-TrendRow {
    param([string]$Key, [string]$Metric, $Prev, $Cur, [string]$Unit, [string]$Direction)
    if ($null -eq $Prev -or $null -eq $Cur) { return $null }
    try { $p = [double]$Prev; $c = [double]$Cur } catch { return $null }
    $d = [math]::Round($c - $p, 2)
    $worse = switch ($Direction) { 'HigherWorse' { $d -gt 0 } 'LowerWorse' { $d -lt 0 } default { $false } }
    return [pscustomobject]@{ Key = $Key; Metric = $Metric; Previous = $p; Current = $c; Delta = $d; Unit = $Unit; Worse = [bool]$worse }
}

# Get trend rows comparing previous and current reports
function Get-TrendRows {
    param($Prev, $Cur)
    $rows = New-Object System.Collections.Generic.List[object]
    $push = { param($r) if ($null -ne $r) { $rows.Add($r) } }

    if ($Prev -and $Cur -and $Prev.Facts -and $Cur.Facts) {
        foreach ($v in @($Cur.Facts.Volumes)) {
            $pv = @($Prev.Facts.Volumes) | Where-Object { $_.DriveLetter -eq $v.DriveLetter } | Select-Object -First 1
            if ($pv) { & $push (New-TrendRow "VolFree:$($v.DriveLetter)" "Volume $($v.DriveLetter): espaco livre" $pv.FreeGB $v.FreeGB 'GB' 'LowerWorse') }
        }
        foreach ($d in @($Cur.Facts.PhysicalDisks)) {
            $pd = @($Prev.Facts.PhysicalDisks) | Where-Object { $_.FriendlyName -eq $d.FriendlyName } | Select-Object -First 1
            if (-not $pd) { continue }
            & $push (New-TrendRow "DiskWear:$($d.FriendlyName)" "Desgaste $($d.FriendlyName)" $pd.WearPercentage $d.WearPercentage '%' 'HigherWorse')
            $pe = [double]$pd.ReadErrorsUncorrected + [double]$pd.WriteErrorsUncorrected
            $ce = [double]$d.ReadErrorsUncorrected + [double]$d.WriteErrorsUncorrected
            & $push (New-TrendRow "DiskErr:$($d.FriendlyName)" "Erros nao corrigidos $($d.FriendlyName)" $pe $ce 'erros' 'HigherWorse')
        }
        $prevCrash = $Prev.Facts.CrashDumps
        $curCrash = $Cur.Facts.CrashDumps
        if ($prevCrash -and $curCrash) {
            & $push (New-TrendRow 'Stability' 'Indice de fiabilidade' $prevCrash.SystemStabilityIndex $curCrash.SystemStabilityIndex '' 'LowerWorse')
            & $push (New-TrendRow 'Minidumps' 'Numero de minidumps' $prevCrash.MinidumpCount $curCrash.MinidumpCount '' 'HigherWorse')
        }
        $prevBat = $Prev.Facts.Battery
        $curBat = $Cur.Facts.Battery
        if ($prevBat -and $curBat) {
            & $push (New-TrendRow 'BatteryWear' 'Desgaste da bateria' $prevBat.WearPct $curBat.WearPct '%' 'HigherWorse')
        }
        $prevBoot = $Prev.Facts.Boot
        $curBoot = $Cur.Facts.Boot
        if ($prevBoot -and $curBoot) {
            & $push (New-TrendRow 'BootSec' 'Tempo medio de arranque' $prevBoot.AvgBootSeconds $curBoot.AvgBootSeconds 's' 'HigherWorse')
        }
        if ($Prev.HealthScore -and $Cur.HealthScore) {
            & $push (New-TrendRow 'Score' 'HealthScore global' $Prev.HealthScore.Overall $Cur.HealthScore.Overall '' 'LowerWorse')
        }
    }
    return $rows.ToArray()
}

# Add finding to report
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
    if (-not $script:Report -or $null -eq $script:Report.Findings) { return }
    $relevant = ($script:FocusCategories -contains $Category)
    $script:Report.Findings += [PSCustomObject]@{
        Category          = $Category
        Severity          = $Severity
        Confidence        = $Confidence
        Finding           = $Finding
        Evidence          = $Evidence
        RecommendedAction = $Action
        RelevantToIssue   = $relevant
    }
    if ($Action -and ($script:Report.RecommendedActions -notcontains $Action)) {
        $script:Report.RecommendedActions += $Action
    }
    $BasePenalty = switch ($Severity) { "Critical" { 20 } "Warning" { 10 } default { 0 } }
    $Mult = if ($relevant) { 1.25 } else { 1.0 }
    $CalculatedPenalty = [math]::Round($BasePenalty * $Confidence * ($ImpactWeight / 2.0) * $Mult, 0)
    if ($script:Report.HealthScore.Contains($Category)) {
        $script:Report.HealthScore[$Category] = [math]::Max(0, $script:Report.HealthScore[$Category] - $CalculatedPenalty)
    }
    $OverallPenalty = [math]::Round($CalculatedPenalty * 0.6, 0)
    $script:Report.HealthScore.Overall = [math]::Max(0, $script:Report.HealthScore.Overall - $OverallPenalty)
}

# Add suspect to report
function Add-Suspect {
    param([string]$Name, [double]$Points, [string]$Reason)
    if (-not $script:Suspects) { return }
    if (-not $script:Suspects.Contains($Name)) {
        $script:Suspects[$Name] = [ordered]@{ Name = $Name; Points = 0.0; Reasons = @() }
    }
    $script:Suspects[$Name].Points += $Points
    $script:Suspects[$Name].Reasons += $Reason
}

# Testar se modulo ou comando esta disponivel
function Test-ModuleAvailable {
    param(
        [string]$ModuleName,
        [string]$FallbackCommand = $null
    )
    
    $available = $false
    
    try {
        if (Get-Module -Name $ModuleName -ListAvailable -ErrorAction SilentlyContinue) {
            $available = $true
        } elseif ($FallbackCommand -and (Get-Command $FallbackCommand -ErrorAction SilentlyContinue)) {
            $available = $true
        }
    } catch {}
    
    if (-not $available) {
        Write-DiagLog -Message "Modulo nao disponivel: $ModuleName" -Level "Warning" -Component "ModuleCheck"
    }
    
    return $available
}

# Verificacao de Drivers Antigos
function Test-DriverDates {
    param(
        [int]$MaxAgeDays = 180
    )

    Write-DiagLog -Message "Verificando drivers antigos (limite: $MaxAgeDays dias)" -Level "Info" -Component "Drivers"

    try {
        $drivers = $null
        try {
            $drivers = Get-CimInstance -ClassName Win32_Driver -ErrorAction Stop
        } catch {
            try {
                $drivers = Get-WmiObject -Class Win32_Driver -ErrorAction Stop
            } catch {
                try {
                    $drivers = Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction Stop
                } catch {
                    try {
                        $drivers = Get-WmiObject -Class Win32_PnPSignedDriver -ErrorAction Stop
                    } catch {
                        throw "Nao foi possivel obter lista de drivers: $_"
                    }
                }
            }
        }
        
        $oldDrivers = @()
        $now = Get-Date
        $minValidYear = 2000  # Ignorar drivers com data antes de 2000 (datas invalidas)

        foreach ($driver in $drivers) {
            if ($driver.DriverDate -and $driver.DriverDate.Year -ge $minValidYear) {
                $age = ($now - $driver.DriverDate).Days
                if ($age -gt $MaxAgeDays) {
                    $oldDrivers += [pscustomobject]@{
                        Name = $driver.Name
                        DisplayName = $driver.DisplayName
                        DriverVersion = $driver.DriverVersion
                        DriverDate = $driver.DriverDate
                        AgeDays = $age
                        AgeYears = [math]::Round($age / 365, 1)
                        Description = $driver.Description
                        InfName = $driver.InfName
                        DriverPath = $driver.Path
                    }
                }
            }
        }

        if ($oldDrivers.Count -gt 0) {
            Write-DiagLog -Message "Encontrados $($oldDrivers.Count) drivers antigos" -Level "Warning" -Component "Drivers"

            # Filtrar drivers do sistema Microsoft (nao precisam ser atualizados manualmente)
            $nonMicrosoftDrivers = $oldDrivers | Where-Object { 
                $_.DisplayName -and $_.DisplayName -notmatch '^Microsoft' -and 
                $_.DisplayName -notmatch 'Windows' -and
                $_.Description -notmatch 'Microsoft' -and
                $_.Description -notmatch 'Windows'
            }
            
            # Limitar a 20 drivers para nao sobrecarregar o relatorio
            $topDrivers = $nonMicrosoftDrivers | Sort-Object AgeDays -Descending | Select-Object -First 20
            
            if ($topDrivers.Count -gt 0) {
                # Criar lista formatada com nome e data
                $driverList = $topDrivers | ForEach-Object { 
                    $name = if ($_.DisplayName -and $_.DisplayName -ne '') { $_.DisplayName } else { $_.Name }
                    $dateStr = if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { 'N/A' }
                    "$name (v$($_.DriverVersion)) - $dateStr"
                }
                $driverListText = ($driverList -join "; ")
                
                # Adicionar nota se houver muitos drivers
                $note = if ($oldDrivers.Count -gt 20) { 
                    " (mostrando top 20 de $($oldDrivers.Count) - $($oldDrivers.Count - $topDrivers.Count) drivers do sistema Microsoft filtrados)"
                } else { "" }
                
                # Gerar apenas UM finding com os drivers
                Add-Finding "Drivers" "Warning" 0.8 `
                    "Drivers desatualizados ($($oldDrivers.Count) encontrados)$note" `
                    "Drivers com mais de $($MaxAgeDays/30) meses: $driverListText" `
                    "Atualizar drivers para melhorar estabilidade e seguranca. Visite os sites dos fabricantes." 2
            }

            # Adicionar suspects individuais (apenas para os top drivers)
            foreach ($driver in $topDrivers) {
                $penalty = if ($driver.AgeDays -gt 365) { 0.9 } elseif ($driver.AgeDays -gt 180) { 0.75 } else { 0.5 }
                Add-Suspect "Drivers" $penalty "Driver $($driver.DisplayName) com $($driver.AgeDays) dias"
            }
        } else {
            Write-DiagLog -Message "Nenhum driver antigo encontrado (limite: $MaxAgeDays dias)" -Level "Info" -Component "Drivers"
        }

        return $oldDrivers

    } catch {
        Write-DiagLog -Message "Erro ao verificar drivers: $($_.Exception.Message)" -Level "Error" -Component "Drivers"
        Add-Finding "Drivers" "Critical" 0.5 "Falha na verificacao de drivers" `
            "Nao foi possivel verificar as datas dos drivers: $($_.Exception.Message)" `
            "Verifique permissoes de administrador e servico WMI" 2
        return $null
    }
}