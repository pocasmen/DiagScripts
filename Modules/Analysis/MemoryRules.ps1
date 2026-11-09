# Memory analysis rules for ECG Diagnostic
# Analyzes memory availability, pool leaks, WSL/Docker, commit pressure, pagefile, and process memory usage

# Memory rules analysis
function Invoke-MemoryRules {
    $m = $F.Memory
    if ($m.AvailableRAM_MB -lt 1024 -and $m.AvailableRAM_Pct -lt 15) {
        Add-Finding "Memory" "Critical" 0.9 "Memoria Fisica Disponivel Muito Baixa" "Apenas $($m.AvailableRAM_MB) MB disponiveis ($($m.AvailableRAM_Pct)% de $($m.TotalRAM_MB) MB)." "Verificar fugas de memoria ou expandir RAM." 2
        Add-Suspect "RAM insuficiente" 1.5 "Memoria disponivel muito baixa"
    }

    # V3 - Kernel Pool Leak Rule
    $np = $m.PoolNonPaged_MB
    if ($np -ge 800) {
        $sev = if ($np -ge 1500) { "Critical" } else { "Warning" }
        Add-Finding "Memory" $sev 0.85 "Consumo Excessivo de Memoria Nao Paginada (Pool Leak)" "Pool Non-Paged consome $np MB (normalmente < 500 MB)." "Fuga num driver de kernel (NIC, AV, VPN). Usar o PoolMon." 2
        Add-Suspect "Drivers" 2.5 "Fuga de Non-Paged Pool ($np MB)"
    }

    # V3 - WSL/Docker
    $wsl = $m.WSL_Docker_RAM_MB
    if ($wsl -ge 2048) {
        Add-Finding "Memory" "Info" 0.7 "Consumo Elevado por Virtualizacao Invisivel (WSL/Docker)" "Processo vmmem usa $wsl MB fora do alcance normal." "Desligar VM ou ajustar limite de memoria." 1
    }

    if ($m.CommitUtilization -gt 85) {
        Add-Finding "Memory" "Warning" 0.85 "Commit Limit Sob Pressao" "Memoria comprometida em $($m.CommitUtilization)% do limite." "Garantir pagefile gerido pelo sistema." 1
    }
    if ($null -ne $m.PageFilePeakPct -and $m.PageFilePeakPct -ge 85) {
        Add-Finding "Memory" "Warning" 0.7 "Pagefile Quase Cheio no Pico" "Pico: $($m.PageFilePeakPct)% ($($m.PageFilePeak_MB) de $($m.PageFileAllocated_MB) MB)." "Verificar fugas de memoria." 1
    }
    $resEx = $F.AggregatedEvents.ResourceExhaustion_Count
    if ($resEx -gt 0) {
        $evDays = if ($script:Report -and $script:Report.Metadata -and $script:Report.Metadata.EventWindowDays) { $script:Report.Metadata.EventWindowDays } else { 30 }
        Add-Finding "Memory" "Critical" 0.9 "Esgotamento de Recursos Recente (Event 2004)" "$resEx evento(s) de Resource-Exhaustion nos ultimos $evDays dias." "Verificar processos abusivos." 2
    }
    $tp = $F.TopProcesses
    $totalMB = [double]$m.TotalRAM_MB
    $topMem = $tp.ByPrivateMemory | Select-Object -First 1
    $topHnd = $tp.ByHandles | Select-Object -First 1
    if ($topMem -and $totalMB -gt 0 -and ($topMem.PrivateMB / $totalMB) -ge 0.4) {
        Add-Finding "Memory" "Warning" 0.7 "Processo com Consumo de Memoria Dominante" "$($topMem.Name) (PID $($topMem.Id)) usa $($topMem.PrivateMB) MB privados." "Verificar fuga; reiniciar a aplicacao." 1
        if ($m.CommitUtilization -gt 85 -or $resEx -gt 0) { Add-Suspect "Fuga de memoria: $($topMem.Name)" 3 "Commit/Resource-Exhaustion + processo dominante" }
    }
    if ($topHnd -and $topHnd.Handles -ge 20000) {
        Add-Finding "Memory" "Warning" 0.6 "Numero de Handles Muito Elevado" "$($topHnd.Name) com $($topHnd.Handles) handles." "Suspeita de fuga de handles." 1
        Add-Suspect "Fuga de memoria: $($topHnd.Name)" 1.5 "Handles elevados ($($topHnd.Handles))"
    }
    $pm = $F.PhysicalMemory
    if ($pm -and -not $script:IsVM) {
        if ($pm.MismatchedCapacity -or $pm.MismatchedSpeed) {
            Add-Finding "Memory" "Info" 0.6 "Modulos de RAM Desemparelhados" "Capacidades ou velocidades diferentes." "Preferir modulos identicos." 1
        }
        if ($pm.SingleChannelPossible) {
            Add-Finding "Memory" "Info" 0.6 "Possivel Single-Channel" "$($pm.ModuleCount) modulo(s) em $($pm.SlotCount) slots." "Adicionar segundo modulo identico." 1
        }
        if ($pm.XmpPossiblyOff) {
            Add-Finding "Memory" "Info" 0.5 "RAM Abaixo da Velocidade Nominal" "Velocidade inferior a 90% da nominal." "Ativar XMP/EXPO na BIOS." 1
        }
    }
    $md = $F.AggregatedEvents.MemoryDiagnostics
    if ($md.RunsWithErrors -gt 0) {
        Add-Finding "Memory" "Critical" 0.95 "Windows Memory Diagnostic Detetou Erros" "$($md.RunsWithErrors) execucao(oes) com erros (ultimo: $($md.LastEvent))." "Substituir o modulo defeituoso." 2
        Add-Suspect "RAM" 4 "Windows Memory Diagnostic reportou erros"
    }
}