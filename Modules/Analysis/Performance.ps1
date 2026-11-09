# Performance analysis rules for ECG Diagnostic
# Analyzes CPU, DPC/interrupt, disk, and memory performance windows

# Performance window analysis
function Get-PerfWindow {
    param([int]$Seconds = 4, [int]$Cores = 1, [string]$Label = "W1")
    $selfPid = $PID
    $t0 = @{}
    # Correction V3: Unique process identifier by startup ticks
    foreach ($p in (Get-Process)) {
        try { if ($null -ne $p.CPU) { $t0["$($p.Id)|$($p.StartTime.Ticks)"] = [double]$p.CPU } } catch { }
    }
    $raw0 = @(Get-CimInstance -ClassName Win32_PerfRawData_PerfDisk_PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne '_Total' })
    $ts0 = [System.Diagnostics.Stopwatch]::GetTimestamp()

    $cpu  = New-Object System.Collections.Generic.List[double]
    $perf = New-Object System.Collections.Generic.List[double]
    $dpc  = New-Object System.Collections.Generic.List[double]
    $intr = New-Object System.Collections.Generic.List[double]
    $pgIn = New-Object System.Collections.Generic.List[double]
    $dq = @{}
    $dtm = @{}
    for ($i = 0; $i -lt $Seconds; $i++) {
        Start-Sleep -Seconds 1
        if ($i -gt 0) {
            $m = Get-CimInstance -ClassName Win32_PerfFormattedData_Counters_ProcessorInformation -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq '_Total' } | Select-Object -First 1
            if ($m) {
                if ($null -ne $m.PercentProcessorUtility)     { $cpu.Add([double]$m.PercentProcessorUtility) }
                if ($null -ne $m.PercentProcessorPerformance) { $perf.Add([double]$m.PercentProcessorPerformance) }
                if ($null -ne $m.PercentDPCTime)              { $dpc.Add([double]$m.PercentDPCTime) }
                if ($null -ne $m.PercentInterruptTime)        { $intr.Add([double]$m.PercentInterruptTime) }
            }
            $pm = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Memory -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($pm -and $null -ne $pm.PagesInputPersec) { $pgIn.Add([double]$pm.PagesInputPersec) }
            foreach ($dd in @(Get-CimInstance -ClassName Win32_PerfFormattedData_PerfDisk_PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne '_Total' })) {
                if (-not $dq.ContainsKey($dd.Name)) {
                    $dq[$dd.Name] = New-Object System.Collections.Generic.List[double]
                    $dtm[$dd.Name] = New-Object System.Collections.Generic.List[double]
                }
                $dq[$dd.Name].Add([double]$dd.CurrentDiskQueueLength)
                $dtm[$dd.Name].Add([double]$dd.PercentDiskTime)
            }
        }
    }

    $raw1 = @(Get-CimInstance -ClassName Win32_PerfRawData_PerfDisk_PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne '_Total' })
    $ts1 = [System.Diagnostics.Stopwatch]::GetTimestamp()
    $dt = ($ts1 - $ts0) / [System.Diagnostics.Stopwatch]::Frequency

    $disks = @()
    foreach ($r1 in $raw1) {
        $r0 = $raw0 | Where-Object { $_.Name -eq $r1.Name } | Select-Object -First 1
        if (-not $r0) { continue }
        $f = [double]$r1.Frequency_PerfTime
        if ($f -le 0) { $f = 10000000.0 }
        $rdOps = [double]$r1.AvgDisksecPerRead_Base - [double]$r0.AvgDisksecPerRead_Base
        $wrOps = [double]$r1.AvgDisksecPerWrite_Base - [double]$r0.AvgDisksecPerWrite_Base
        $rdMs = $null; $wrMs = $null
        if ($rdOps -gt 0) { $rdMs = ((([double]$r1.AvgDisksecPerRead - [double]$r0.AvgDisksecPerRead) / $f) / $rdOps) * 1000 }
        if ($wrOps -gt 0) { $wrMs = ((([double]$r1.AvgDisksecPerWrite - [double]$r0.AvgDisksecPerWrite) / $f) / $wrOps) * 1000 }
        if ($null -ne $rdMs -and ($rdMs -lt 0 -or $rdMs -gt 60000)) { $rdMs = $null }
        if ($null -ne $wrMs -and ($wrMs -lt 0 -or $wrMs -gt 60000)) { $wrMs = $null }
        $disks += [pscustomobject]@{
            Name      = $r1.Name
            DiskIndex = [regex]::Match("$($r1.Name)", '^\d+').Value
            ReadMs    = if ($null -ne $rdMs) { [math]::Round($rdMs, 1) } else { $null }
            WriteMs   = if ($null -ne $wrMs) { [math]::Round($wrMs, 1) } else { $null }
            ReadOps   = [int]$rdOps
            WriteOps  = [int]$wrOps
            QueueAvg  = if ($dq.ContainsKey($r1.Name)) { Get-Avg $dq[$r1.Name] } else { $null }
            BusyPct   = if ($dtm.ContainsKey($r1.Name)) { Get-Avg $dtm[$r1.Name] } else { $null }
        }
    }

    $procSum = 0.0
    $hogs = @()
    foreach ($p1 in (Get-Process)) {
        try {
            if ($null -eq $p1.CPU -or $p1.Id -eq $selfPid) { continue }
            $key = "$($p1.Id)|$($p1.StartTime.Ticks)"
            if ($t0.ContainsKey($key)) {
                $delta = [double]$p1.CPU - $t0[$key]
                if ($delta -gt 0 -and $dt -gt 0) {
                    $usage = ($delta / ($dt * $Cores)) * 100
                    $procSum += $usage
                    if ($usage -ge 1.0) { $hogs += [pscustomobject]@{ Id = $p1.Id; ProcessName = $p1.ProcessName; InstantCPU = $usage } }
                }
            }
        } catch {}
    }
    $top = @($hogs | Sort-Object InstantCPU -Descending | Select-Object -First 5 | ForEach-Object {
        $pp = Get-Process -Id $_.Id -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Id          = $_.Id
            ProcessName = $_.ProcessName
            InstantCPU  = [math]::Round($_.InstantCPU, 1)
            Company     = if ($pp -and $pp.Company) { "$($pp.Company)".Trim() } else { "N/A" }
            Description = if ($pp -and $pp.Description) { "$($pp.Description)".Trim() } else { "N/A" }
            Path        = if ($pp -and $pp.Path) { $pp.Path } else { "N/A" }
        }
    })

    return [pscustomobject]@{
        Label            = $Label
        Seconds          = [math]::Round($dt, 1)
        CpuAvg           = Get-Avg $cpu
        PerfPctAvg       = Get-Avg $perf
        DpcAvg           = Get-Avg $dpc
        InterruptAvg     = Get-Avg $intr
        ProcSumPct       = [math]::Round($procSum, 1)
        PagesInputAvg    = Get-Avg $pgIn
        Disks            = $disks
        TopHogs          = $top
    }
}

# Performance rules analysis
function Invoke-PerformanceRules {
    param(
        $PerfWindows = $null
    )
    if ($null -eq $PerfWindows) {
        $PerfWindows = $script:PerfWindows
    }
    
    $W = @()
    if ($PerfWindows -is [System.Collections.IEnumerable]) {
        foreach ($item in $PerfWindows) {
            $W += $item
        }
    } elseif ($null -ne $PerfWindows) {
        $W += $PerfWindows
    }

    $CpuVals = @($W | ForEach-Object { $_.CpuAvg } | Where-Object { $null -ne $_ })
    $CpuTotal = if ($CpuVals.Count -gt 0) { [int][math]::Round(($CpuVals | Measure-Object -Average).Average, 0) } else { [int]$CpuCim.LoadPercentage }
    $HighWin = @($CpuVals | Where-Object { $_ -ge 85 }).Count
    $HogWin = $W | Sort-Object CpuAvg -Descending | Select-Object -First 1
    $Hogs = if ($HogWin) { @($HogWin.TopHogs) } else { @() }
    $PerfAvg = Get-Avg ($W | ForEach-Object { $_.PerfPctAvg })
    $DpcAvg = Get-Avg ($W | ForEach-Object { $_.DpcAvg })
    $IntAvg = Get-Avg ($W | ForEach-Object { $_.InterruptAvg })
    $PgAvg = Get-Avg ($W | ForEach-Object { $_.PagesInputAvg })

    $F.Performance = [ordered]@{
        Mode = if ($W.Count -ge 3) { 'Extended (3 janelas)' } else { 'Standard (1 janela)' }
        CpuAvgPct = $CpuTotal; CpuWindowsAbove85 = $HighWin; PerformancePctAvg = $PerfAvg
        DpcPctAvg = $DpcAvg; InterruptPctAvg = $IntAvg; PagesInputPerSecAvg = $PgAvg
        Windows = @($W | ForEach-Object { [ordered]@{ Label = $_.Label; Seconds = $_.Seconds; CpuAvgPct = $_.CpuAvg; ProcessSumPct = $_.ProcSumPct; PagesInputPerSec = $_.PagesInputAvg; Disks = $_.Disks } })
    }
    $F.TopRealTimeCPU = $Hogs

    if ($HighWin -ge 1) {
        $hog = $Hogs | Select-Object -First 1
        $hogTxt = if ($hog) { " Processo topo: $($hog.ProcessName) ($($hog.InstantCPU)%)." } else { " Sem processo dominante (atividade de kernel/driver)." }
        $act = if ($hog) { "Investigar o processo $($hog.ProcessName) (PID $($hog.Id), $($hog.Path))." } else { "Repetir medicao; analisar interrupcoes." }
        if ($W.Count -ge 3 -and $HighWin -lt 2) {
            Add-Finding "Hardware" "Info" 0.5 "Pico Transitorio de CPU" "CPU >= 85% em 1 de $($W.Count) janelas (media global $CpuTotal%).$hogTxt" $act 1
        } else {
            $conf = if ($W.Count -ge 3) { 0.8 } else { 0.7 }
            $lbl = if ($W.Count -ge 3) { "Carga de CPU Sustentada" } else { "Utilizacao de CPU Elevada" }
            Add-Finding "Hardware" "Warning" $conf $lbl "CPU >= 85% em $HighWin de $($W.Count) janela(s); media $CpuTotal%.$hogTxt" $act 2
            if ($hog) { Add-Suspect "Software/Aplicacao" 1.5 "Processo $($hog.ProcessName) com CPU dominante" }
        }
    }

    # V3 - Power Plan
    if ($F.System.PowerPlan -match 'Poupaná|Power saver|Economia' -and -not $script:IsVM) {
        Add-Finding "Hardware" "Warning" 0.7 "Sistema Limitado pelo Plano de Energia (Throttling)" "Plano de energia ativo: '$($F.System.PowerPlan)'. Pode bloquear o CPU em frequencias baixas." "Alterar para Equilibrado ou Alto Desempenho." 1
    } elseif ($null -ne $PerfAvg -and $PerfAvg -lt 60 -and $CpuTotal -ge 50) {
        Add-Finding "Hardware" "Warning" 0.6 "CPU a Correr Abaixo da Frequencia Base" "PercentProcessorPerformance medio $PerfAvg% com carga de $CpuTotal%." "Verificar limites termicos/PL1." 1
        Add-Suspect "Arrefecimento" 1.5 "CPU abaixo da frequencia base sob carga"
    }

    $dpcInt = ([double]$DpcAvg + [double]$IntAvg)
    if ($dpcInt -ge 30) {
        Add-Finding "Hardware" "Critical" 0.7 "Tempo de DPC/Interrupt Muito Elevado" "DPC $DpcAvg% + Interrupt $IntAvg% = $([math]::Round($dpcInt,1))% do CPU." "Identificar driver (LatencyMon); atualizar rede, audio." 2
        Add-Suspect "Drivers" 2.5 "DPC+Interrupt muito elevados"
    } elseif ($dpcInt -ge 15) {
        Add-Finding "Hardware" "Warning" 0.65 "Tempo de DPC/Interrupt Elevado" "DPC $DpcAvg% + Interrupt $IntAvg% = $([math]::Round($dpcInt,1))% do CPU." "Identificar o driver causador." 1
        Add-Suspect "Drivers" 1.5 "DPC+Interrupt elevados"
    }

    $samples = @($W | ForEach-Object { $_.Disks } | Where-Object { $_ })
    foreach ($grp in ($samples | Group-Object DiskIndex)) {
        $media = (@($F.PhysicalDisks) | Where-Object { $_.DeviceId -eq $grp.Name } | Select-Object -First 1).MediaType
        $isHdd = ($media -eq 'HDD')
        $warnMs = if ($isHdd) { 40 } else { 25 }
        $critMs = if ($isHdd) { 120 } else { 100 }
        $rd = Get-Max ($grp.Group | Where-Object { $_.ReadOps -ge 10 } | ForEach-Object { $_.ReadMs })
        $wr = Get-Max ($grp.Group | Where-Object { $_.WriteOps -ge 10 } | ForEach-Object { $_.WriteMs })
        $worst = Get-Max @($rd, $wr)
        $q = Get-Avg ($grp.Group | ForEach-Object { $_.QueueAvg })
        $busy = Get-Avg ($grp.Group | ForEach-Object { $_.BusyPct })
        if ($null -ne $worst -and $worst -ge $critMs) {
            Add-Finding "Storage" "Critical" 0.8 "Latencia de Disco Muito Elevada" "Disco $($grp.Name) ($media): max $worst ms (leitura $rd / escrita $wr)." "Verificar SMART, cabos e processos I/O." 2
            Add-Suspect "Armazenamento" 2 "Latencia de disco $worst ms"
        } elseif ($null -ne $worst -and $worst -ge $warnMs) {
            Add-Finding "Storage" "Warning" 0.7 "Latencia de Disco Elevada" "Disco $($grp.Name) ($media): max $worst ms (leitura $rd / escrita $wr)." "Verificar I/O em background e saude." 1
            Add-Suspect "Armazenamento" 1 "Latencia de disco $worst ms"
        }
        if ($null -ne $q -and $q -ge 2 -and $null -ne $busy -and $busy -ge 90) {
            Add-Finding "Storage" "Warning" 0.65 "Disco Saturado (fila e ocupacao altas)" "Disco $($grp.Name): fila $q, ocupacao $busy%." "Identificar processos pesados (Monitor de Recursos)." 1
        }
    }

    $availPct = $F.Memory.AvailableRAM_Pct
    if ($null -ne $PgAvg -and $PgAvg -ge 100 -and $availPct -lt 25) {
        $sev = if ($PgAvg -ge 500) { "Critical" } else { "Warning" }
        Add-Finding "Memory" $sev 0.7 "Paginacao Intensiva (hard faults)" "Pages Input/s medio $PgAvg com $availPct% de RAM disponivel." "Expandir RAM ou fechar aplicacoes." 2
        Add-Suspect "RAM insuficiente" 2.5 "Paginacao intensiva ($PgAvg pag/s)"
    }
    return $null
}