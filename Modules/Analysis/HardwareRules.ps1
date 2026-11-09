# Hardware analysis rules for ECG Diagnostic
# Analyzes temperature, throttling, WHEA, battery, GPU, audio, USB, and crash events

# Hardware rules analysis
function Invoke-HardwareRules {
    $tz = $F.System.ThermalZone_ACPI_C
    if ($tz -and $tz -ge 88 -and -not $script:IsVM) {
        Add-Finding "Hardware" "Warning" 0.5 "Temperatura Termica ACPI Elevada" "Sonda ACPI reportou $tz C." "Confirmar com HWiNFO e inspecionar pasta termica." 1
        Add-Suspect "Arrefecimento" 2 "Sonda ACPI a $tz C"
    }
    $thr = $F.AggregatedEvents.CpuThrottlingEvents
    if ($thr -gt 0 -and -not $script:IsVM) {
        Add-Finding "Hardware" "Warning" 0.7 "CPU Limitado pelo Firmware (Throttling)" "$thr evento(s) Kernel-Processor-Power 37." "Verificar temperaturas e BIOS." 2
        Add-Suspect "Arrefecimento" 2 "Eventos de throttling ($thr)"
    }
    $wf = @($F.AggregatedEvents.WHEA_Fatal)
    if ($wf.Count -gt 0) {
        $nm = ($wf | ForEach-Object { "ID $($_.Name) (x$($_.Count))" }) -join ", "
        Add-Finding "Hardware" "Critical" 0.95 "Erros Fatais de Hardware (WHEA)" "Eventos WHEA Criticos: $nm." "Inspecionar CPU, RAM e PCIe." 2
        Add-Suspect "CPU/Hardware" 3 "WHEA fatal"
        Add-Suspect "RAM" 1 "WHEA fatal pode indicar RAM"
    }
    # V3 Trend WHEA
    if ($F.AggregatedEvents.WheaTrendIncrease -gt 0) {
        Add-Finding "Hardware" "Warning" 0.8 "Frequencia de Erros WHEA a Aumentar" "Aumento de $($F.AggregatedEvents.WheaTrendIncrease)% nos ultimos 7 dias comparado com a media anterior." "Sinal claro de hardware em degradacao rapida." 1
    }

    $wc = @($F.AggregatedEvents.WHEA_Corrected)
    if ($wc.Count -gt 0) {
        $tot = ($wc | Measure-Object -Property Count -Sum).Sum
        $nm = ($wc | ForEach-Object { "ID $($_.Name) (x$($_.Count))" }) -join ", "
        $sev = if ($tot -ge 20) { "Warning" } else { "Info" }
        Add-Finding "Hardware" $sev 0.6 "Erros de Hardware Corrigidos (WHEA)" "Eventos WHEA corrigidos: $nm." "Se frequentes, atualizar BIOS." 1
    }

    $bt = $F.Battery
    if ($bt -and $bt.Present -and $null -ne $bt.WearPct -and -not $script:IsVM) {
        $healthPct = 100 - $bt.WearPct
        if ($bt.WearPct -ge 60) {
            Add-Finding "Hardware" "Critical" 0.8 "Bateria Muito Desgastada" "Bateria com $healthPct% de saude (desgaste de $($bt.WearPct)%). Capacidade atual: $($bt.FullChargeCapacityMWh)mWh, Original: $($bt.DesignCapacityMWh)mWh." "Substituir a bateria imediatamente. Risco de desligamentos abruptos." 2
            Add-Suspect "Bateria" 3 "Desgaste $($bt.WearPct)%"
        } elseif ($bt.WearPct -ge 40) {
            Add-Finding "Hardware" "Warning" 0.8 "Desgaste da Bateria Significativo: $($bt.WearPct)%" "Bateria com $healthPct% de saude (desgaste de $($bt.WearPct)%). Capacidade atual: $($bt.FullChargeCapacityMWh)mWh, Original: $($bt.DesignCapacityMWh)mWh." "Considerar substituir a bateria. Autonomia significativamente reduzida." 1
            Add-Suspect "Bateria" 1.5 "Desgaste $($bt.WearPct)%"
        } elseif ($bt.WearPct -ge 30) {
            Add-Finding "Hardware" "Warning" 0.75 "Desgaste da Bateria: $($bt.WearPct)%" "Bateria com $healthPct% de saude (desgaste de $($bt.WearPct)%). Capacidade atual: $($bt.FullChargeCapacityMWh)mWh, Original: $($bt.DesignCapacityMWh)mWh." "Considerar substituir a bateria. Baterias com mais de 30% de desgaste tem autonomia significativamente reduzida." 1
            Add-Suspect "Hardware" 0.75 "Bateria com desgaste de $($bt.WearPct)%"
        } elseif ($bt.WearPct -ge 20) {
            Add-Finding "Hardware" "Info" 0.5 "Desgaste da Bateria: $($bt.WearPct)%" "Bateria com $healthPct% de saude (desgaste de $($bt.WearPct)%). Capacidade atual: $($bt.FullChargeCapacityMWh)mWh, Original: $($bt.DesignCapacityMWh)mWh." "Monitorizar a bateria. Substituir quando desgaste superar 30%." 1
        }
    }
    foreach ($g in @($F.Gpu)) {
        if ($g.Name -like 'Microsoft Basic Display*') {
            Add-Finding "Hardware" "Warning" 0.7 "Driver Grafico Generico em Uso" "Adaptador: $($g.Name)." "Instalar o driver do fabricante da GPU." 1
            Add-Suspect "GPU" 1.5 "Driver grafico generico"
        }
        if ($g.ConfigErrorCode -and $g.ConfigErrorCode -ne 0) {
            Add-Finding "Hardware" "Warning" 0.8 "Adaptador Grafico com Erro no Gestor de Dispositivos" "$($g.Name): codigo $($g.ConfigErrorCode)." "Reinstalar o driver." 1
            Add-Suspect "GPU" 2 "Erro PnP no adaptador grafico"
        }
        # V3 Refresh Rate
        if ($g.RefreshRate -and $g.RefreshRate -lt 60) {
            Add-Finding "Hardware" "Warning" 0.7 "Taxa de Atualizacao do EcrÃ£ Lenta ($($g.RefreshRate) Hz)" "Monitor ligado a $($g.Name) configurado com refresh rate inferior ao normal." "Ir as definicoes de monitor do Windows e corrigir a frequencia." 1
        }
    }
    $tdr = $F.AggregatedEvents.DisplayTDR_Count
    if ($tdr -gt 0) {
        $sev = if ($tdr -ge 3) { "Critical" } else { "Warning" }
        $evDays = if ($script:Report -and $script:Report.Metadata -and $script:Report.Metadata.EventWindowDays) { $script:Report.Metadata.EventWindowDays } else { 30 }
        Add-Finding "Hardware" $sev 0.85 "Resets do Driver Grafico (TDR 4101)" "$tdr evento(s) nos ultimos $evDays dias." "Reinstalar driver com DDU." 2
        Add-Suspect "GPU" 3 "Eventos TDR ($tdr)"
    }
    $kp = $F.AggregatedEvents.KernelPower41
    if ($kp.CrashesWithBugcheck -gt 0) {
        Add-Finding "Hardware" "Critical" 0.9 "Reinicios por Ecra Azul (BugCheck) Detetados" "$($kp.CrashesWithBugcheck) falha(s) com BugCheck." "Analisar minidumps." 2
    }
    if ($kp.DirtyPowerLosses -ge 2) {
        Add-Finding "Hardware" "Warning" 0.7 "Desligamentos Abruptos / Perda de Energia" "$($kp.DirtyPowerLosses) reinicios sem BugCheck." "Testar PSU/bateria." 1
        Add-Suspect "Alimentacao/PSU" 2.5 "Desligamentos abruptos repetidos"
    }
    # V3 USB & Audio
    if ($F.AggregatedEvents.USB_BTH -ge 5) {
        Add-Finding "Hardware" "Warning" 0.6 "Falhas no Barramento USB ou Bluetooth" "$($F.AggregatedEvents.USB_BTH) eventos no subsistema periferico." "Testar desligar dispositivos problematicos e atualizar BIOS." 1
    }
    if ($F.AggregatedEvents.AudioCrash -ge 3) {
        Add-Finding "Windows" "Warning" 0.65 "Crashes Sucessivos no Subsistema de Audio" "$($F.AggregatedEvents.AudioCrash) crashes em audiodg.exe." "Atualizar driver da placa de som." 1
        Add-Suspect "Drivers de Audio" 1.5 "Crashes audiodg.exe"
    }
}