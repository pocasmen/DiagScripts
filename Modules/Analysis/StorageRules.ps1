# Storage analysis rules for ECG Diagnostic
# Analyzes disk health, SMART, volume space, dirty bit, storage events, trends, and VSS

# Storage rules analysis
function Invoke-StorageRules {
    foreach ($dk in @($F.PhysicalDisks)) {
        $dn = "$($dk.FriendlyName) (disco $($dk.DeviceId))"
        switch ($dk.HealthStatus) {
            "Unhealthy" { Add-Finding "Storage" "Critical" 0.95 "Disco Reportado como Nao Saudavel" "${dn} : Status Unhealthy." "Substituicao imediata." 2; Add-Suspect "Armazenamento" 4 "HealthStatus Unhealthy em $dn" }
            "Warning"   { Add-Finding "Storage" "Warning" 0.85 "Disco com Aviso de Saude" "${dn} : Status Warning." "Verificar SMART." 2; Add-Suspect "Armazenamento" 2.5 "HealthStatus Warning em $dn" }
        }
        if ($null -ne $dk.WearPercentage -and $dk.WearPercentage -ge 80) {
            $sev = if ($dk.WearPercentage -ge 90) { "Critical" } else { "Warning" }
            Add-Finding "Storage" $sev 0.9 "Desgaste de SSD Elevado" "${dn} : desgaste $($dk.WearPercentage)%." "Planear substituicao do SSD $dn." 2; Add-Suspect "Armazenamento" 2.5 "Desgaste SSD $($dk.WearPercentage)%"
        }
        $un = 0
        if ($null -ne $dk.ReadErrorsUncorrected)  { $un += [int64]$dk.ReadErrorsUncorrected }
        if ($null -ne $dk.WriteErrorsUncorrected) { $un += [int64]$dk.WriteErrorsUncorrected }
        if ($un -gt 0) { Add-Finding "Storage" "Warning" 0.75 "Erros de I/O Nao Corrigidos no Disco" "${dn} : $un erros acumulados." "Garantir backup." 2; Add-Suspect "Armazenamento" 2 "Erros nao corrigidos em $dn" }
    }
    $sp = $F.SmartPredictFailure
    if ($sp -and $sp.Count -gt 0) {
        Add-Finding "Storage" "Critical" 0.95 "SMART Preve Falha Iminente de Disco" "$($sp.Count) dispositivo(s) com PredictFailure=True." "Backup IMEDIATO." 2
        Add-Suspect "Armazenamento" 4 "SMART PredictFailure"
    }
    foreach ($vol in @($F.Volumes)) {
        if (($vol.FreePct -lt 10 -and $vol.FreeGB -lt 50) -or $vol.FreeGB -lt 5) {
            Add-Finding "Storage" "Critical" 0.98 "Volume $($vol.DriveLetter): em Esgotamento Critico" "Apenas $($vol.FreeGB) GB disponiveis." "Libertar espaco." 2
        } elseif ($vol.FreePct -lt 15 -and $vol.FreeGB -lt 100) {
            Add-Finding "Storage" "Warning" 0.85 "Volume $($vol.DriveLetter): com Espaco Reduzido" "Apenas $($vol.FreePct)% de espaco livre." "Limpeza de disco." 1
        }
        if ($vol.DirtyBit -eq $true) {
            Add-Finding "Storage" "Warning" 0.85 "Dirty Bit Ativo no Volume $($vol.DriveLetter):" "Volume marcado como 'sujo'." "Executar chkdsk." 1
            Add-Suspect "Armazenamento" 1.5 "Dirty bit em $($vol.DriveLetter):"
        }
    }

    $ae = $F.AggregatedEvents
    $physErr = @($ae.PhysicalStorageErrors); $physWarn = @($ae.PhysicalStorageWarnings)
    $critHit = @(@($physErr) + @($physWarn) | Where-Object { $CriticalStorageIds -contains $_.Key })
    if ($physErr.Count -gt 0 -or $critHit.Count -gt 0) {
        $all = @(@($physErr) + @($critHit) | Select-Object -Unique)
        Add-Finding "Storage" "Critical" 0.9 "Erros no Barramento ou Controlador de Armazenamento" "Eventos criticos: $(Format-EventSummary $all)." "Verificar cabos e saude." 2
        Add-Suspect "Armazenamento" 3 "Eventos de storage criticos"
    }

    # V3 - Trend Analysis
    if ($ae.StorageTrendIncrease -gt 0) {
        Add-Finding "Storage" "Critical" 0.85 "Aumento Acelerado de Erros de Disco (Tendencia)" "Os erros subiram $($ae.StorageTrendIncrease)% na ultima semana face a media do mes." "O disco podera falhar num futuro muito proximo." 2
    }
    # V3 - VSS
    if ($ae.VSS -gt 0) {
        Add-Finding "Storage" "Warning" 0.7 "Falhas nos Servicos de Shadow Copy (VSS)" "$($ae.VSS) evento(s) de erro." "Verificar se as copias de seguranca estao a falhar e libertar espaco em disco." 1
    }

    $lg = @($ae.LogicalFilesystemErrors)
    if ($lg.Count -gt 0) {
        Add-Finding "Storage" "Warning" 0.8 "Erros Logicos no Sistema de Ficheiros (NTFS/volmgr)" "Eventos: $(Format-EventSummary $lg)." "Agendar chkdsk." 1
        Add-Suspect "Armazenamento" 1.5 "Erros NTFS/volmgr"
    }
}