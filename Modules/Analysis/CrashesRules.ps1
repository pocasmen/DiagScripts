# Crash analysis rules for ECG Diagnostic
# Analyzes bug checks, minidumps, application crashes, and stability index

# Crash rules analysis
function Invoke-CrashesRules {
    $bcs = @($F.CrashDumps.BugcheckAnalysis)
    $catPoints = @{ 'Drivers' = 'Drivers'; 'RAM' = 'RAM'; 'Armazenamento' = 'Armazenamento'; 'GPU' = 'GPU'; 'CPU/Hardware' = 'CPU/Hardware'; 'Software/Sistema' = 'Software/Aplicacao' }
    if ($bcs.Count -gt 0) {
        $txt = ($bcs | ForEach-Object { "$($_.Code) $($_.Name) [$($_.Category)] x$($_.Occurrences)" }) -join "; "
        Add-Finding "Windows" "Warning" 0.85 "BugChecks Classificados" $txt "Tratar a categoria dominante." 1
        foreach ($b in $bcs) {
            $sn = if ($null -ne $b.Category -and $catPoints.ContainsKey($b.Category)) { $catPoints[$b.Category] } else { $null }
            if ($sn) { Add-Suspect $sn (1.5 + [math]::Min(2.0, [double]$b.Occurrences * 0.5)) "BugCheck $($b.Code) $($b.Name)" }
            # V3 - Add extracted modules as extra suspects
            if ($b.RootCauseModules) {
                $modArr = $b.RootCauseModules -split ', '
                foreach ($m in $modArr) {
                    $modName = $m.Replace("Culpado_", "")
                    Add-Finding "Windows" "Critical" 0.9 "Driver/Modulo Culpado Identificado no BugCheck" "O modulo $modName causou a falha de sistema $($b.Code)." "Atualizar, reparar ou remover este componente." 2
                    Add-Suspect "Driver: $modName" 4 "Detetado nos dados do evento BSOD 1001"
                }
            }
        }
    }

    $dc = $F.CrashDumps.MinidumpCount
    if ($dc -gt 0) {
        $recent = $script:LatestDumpDt -and ($script:LatestDumpDt -gt (Get-Date).AddDays(-30))
        $sev = if ($recent) { "Warning" } else { "Info" }
        Add-Finding "Windows" $sev 0.85 "Historico de Crash Dumps Presente" "$dc minidump(s)." "Examinar com WinDbg ou BlueScreenView se instavel." 1
    }
    $si = $F.CrashDumps.SystemStabilityIndex
    if ($null -ne $si -and $si -lt 5) {
        Add-Finding "Windows" "Warning" 0.7 "Indice de Fiabilidade Baixo" "SystemStabilityIndex = $si." "Abrir o Monitor de Fiabilidade." 1
    }

    # Applications and Trend (V3)
    $ac = $F.AppCrashes
    $topApp = @($ac.TopApps) | Select-Object -First 1
    if ($topApp -and $topApp.Crashes -ge 3) {
        Add-Finding "Windows" "Warning" 0.7 "Aplicacao com Crashes Repetidos" "$($topApp.App): $($topApp.Crashes) crash(es), modulo $($topApp.TopFaultingModule)." "Atualizar ou reinstalar $($topApp.App)." 1
        if ($topApp.Crashes -ge 5) { Add-Suspect "Software: $($topApp.App)" 3 "$($topApp.Crashes) crashes (modulo $($topApp.TopFaultingModule))" }
    }
    if ($ac.TrendIncrease -gt 0) {
        Add-Finding "Windows" "Warning" 0.75 "Aumento Subito de Crashes de Aplicacoes (Tendencia)" "Taxa de crashes subiu $($ac.TrendIncrease)% nos ultimos dias face ao historico normal." "Suspeitar de RAM, ou atualizacao problematica recente." 1
    }
}