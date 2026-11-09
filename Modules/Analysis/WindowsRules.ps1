# Windows analysis rules for ECG Diagnostic
# Analyzes component store, SFC, services, drivers, boot, startup, updates, and OS support

# Windows rules analysis
function Invoke-WindowsRules {
    # Contexto e privilegios
    if (-not $script:IsAdmin) {
        Add-Finding "Windows" "Info" 1.0 "Executado sem privilegios de administrador" `
            "Resultados parciais: sensores ACPI, fiabilidade, SMART, DISM, SFC, BitLocker, tarefas e TPM nao avaliados." `
            "Voltar a executar numa consola PowerShell elevada (Executar como administrador)." 1
    }
    if ($script:IsVM) {
        Add-Finding "Hardware" "Info" 1.0 "Maquina virtual detetada" `
            "Modelo: $($F.System.Manufacturer) $($F.System.Model). Regras termicas podem nao se aplicar." `
            "Interpretar os resultados de hardware com cautela." 1
    }
    $up = $F.System.UptimeDays
    if ($up -ge 30) {
        $fs = if ($script:FastStartup) { " Com o Fast Startup ativo, 'Encerrar' nao reinicia o kernel: usar 'Reiniciar'." } else { "" }
        Add-Finding "Windows" "Info" 0.6 "Uptime Prolongado" "Sistema ligado ha $up dias sem reiniciar.$fs" "Reiniciar (nao apenas encerrar) para aplicar atualizacoes e limpar estados acumulados." 1
    }
    if ($F.System.RebootPending) {
        $sev = if ($script:RebootStrong) { "Warning" } else { "Info" }
        Add-Finding "Windows" $sev 0.9 "Reinicio Pendente" "Motivo(s): $($F.System.RebootReasons)." "Reiniciar o equipamento para concluir operacoes pendentes." 1
    }

    if ($F.ComponentStoreHealth -eq "Corrompido (Reparavel)") {
        Add-Finding "Windows" "Critical" 0.9 "Corrupcao no Component Store do Windows" "DISM CheckHealth: reparavel." "Executar: DISM /Online /Cleanup-Image /RestoreHealth." 2
        Add-Suspect "Sistema Windows (integridade)" 3 "Component store corrompido"
    } elseif ($F.ComponentStoreHealth -eq "Corrompido (Nao reparavel)") {
        Add-Finding "Windows" "Critical" 0.95 "Component Store do Windows Nao Reparavel" "DISM CheckHealth: nao reparavel." "Reparacao in-place." 2
    }
    if ($F.SFC_Status -eq "Violacoes Encontradas") {
        Add-Finding "Windows" "Warning" 0.8 "SFC Reporta Violacoes de Integridade" "Ficheiros danificados." "Executar sfc /scannow." 1
    }
    $scmBad = @($F.ServiceControlManagerEvents | Where-Object { $_.Count -ge 3 -or $_.Event -match '^(7000|7001|7009|7011|7023)\|' })
    if ($scmBad.Count -gt 0) {
        Add-Finding "Windows" "Warning" 0.65 "Falhas Recorrentes de Servicos (SCM)" (($scmBad | Select-Object -First 5 | ForEach-Object { "$($_.Event) x$($_.Count)" }) -join '; ') "Investigar em services.msc." 1
    }

    $dr = $F.Drivers
    if ($dr.UnsignedCount -gt 0) {
        Add-Finding "Windows" "Warning" 0.6 "Drivers Nao Assinados" "$($dr.UnsignedCount) driver(s)." "Substituir por assinados." 1
    }
    if ($F.PnPErrorCount -gt 0) {
        Add-Finding "Windows" "Warning" 0.75 "Dispositivos com Erro no Gestor de Dispositivos" "$($F.PnPErrorCount) dispositivo(s): $(($F.PnPErrors | Select-Object -First 4 | ForEach-Object { "$($_.Name) [$($_.Code)]" }) -join '; ')." "Reinstalar drivers." 1
        Add-Suspect "Drivers" 2 "Dispositivos PnP com erro ($($F.PnPErrorCount))"
    }

    $bt = $F.Boot
    if ($bt -and $bt.BootsAnalyzed -gt 0) {
        if ($bt.AvgBootSeconds -ge 120) {
            Add-Finding "Windows" "Warning" 0.7 "Arranque Muito Lento" "Media de $($bt.AvgBootSeconds) s." "Migrar HDD para SSD ou remover arranque extra." 1
            Add-Suspect "Software/Arranque" 1.5 "Arranque lento ($($bt.AvgBootSeconds) s)"
        }
    }

    $si = @($F.StartupItems)
    $susp = @($si | Where-Object { $_.SuspiciousPath -and $_.Signature -ne 'Valid' })
    if ($susp.Count -gt 0) {
        Add-Finding "Windows" "Warning" 0.6 "Itens de Arranque Suspeitos" (($susp | Select-Object -First 4 | ForEach-Object { "$($_.Name): $($_.Executable)" }) -join '; ') "Verificar no Autoruns." 1
        Add-Suspect "Seguranca/Malware" 2.5 "Arranque suspeito ($($susp.Count))"
    }

    $up = $F.Updates
    if ($up -and $up.FailureEvents30d -gt 0) {
        Add-Finding "Windows" "Warning" 0.7 "Falhas do Windows Update" "$($up.FailureEvents30d) evento(s) falhados." "Correr Troubleshooting." 1
    }
    $os = $F.OsSupport
    if ($os -and $os.OutOfSupport) {
        Add-Finding "Windows" "Warning" 0.8 "Versao do Windows Fora de Suporte" "$($os.Label) ($($os.Edition))." "Atualizar o SO." 2
    }
}