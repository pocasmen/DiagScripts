# Security analysis rules for ECG Diagnostic
# Analyzes antivirus, firewall, scheduled tasks, local admins, and security findings

# Security rules analysis
function Invoke-SecurityRules {
    $sc = $F.Security
    $def = $sc.Defender
    $tp = @($sc.ThirdPartyAV | Where-Object { $_.Name -notmatch 'Windows Defender|Microsoft Defender' })
    $tpActive = @($tp | Where-Object { $_.Enabled })
    $defActive = ($def -and $def.RealTimeProtection)

    if (-not $defActive -and $tpActive.Count -eq 0 -and ($def -or $tp.Count -gt 0)) {
        Add-Finding "Windows" "Critical" 0.85 "Sem Antivirus Ativo" "Defender sem protecao em tempo real e de terceiros desativado." "Ativar AV." 2
        Add-Suspect "Seguranca/Malware" 2 "Sem antivirus ativo"
    }
    if ($defActive -and $null -ne $def.SignatureAgeDays -and $def.SignatureAgeDays -ge 7) {
        $sev = if ($def.SignatureAgeDays -ge 30) { "Critical" } else { "Warning" }
        Add-Finding "Windows" $sev 0.8 "Assinaturas do Defender Desatualizadas" "Com $($def.SignatureAgeDays) dias." "Atualizar definicoes." 1
    }

    foreach ($fw in @($sc.Firewall)) {
        if ($fw.Enabled -eq 'False') {
            $sev = if ($fw.Profile -eq 'Public') { "Critical" } else { "Warning" }
            Add-Finding "Windows" $sev 0.7 "Firewall Desligada ($($fw.Profile))" "A firewall do windows esta desativada." "Ativar ou confirmar substituto." 1
        }
    }

    # V3 - Scheduled Tasks and Admins
    $st = $sc.SuspiciousTasks
    if ($st -and $st.Count -gt 0) {
        Add-Finding "Security" "Warning" 0.85 "Tarefas Agendadas Suspeitas Detetadas" "$(($st | Select-Object -First 3 | ForEach-Object { $_.Name }) -join ', ')" "Rever no Agendador de Tarefas entradas que executem scripts em pastas temporarias." 2
        Add-Suspect "Seguranca/Malware" 2.5 "Tarefas agendadas anormais"
    }

    $adm = $sc.LocalAdmins
    if ($adm -and $adm.Count -ge 5) {
        Add-Finding "Security" "Info" 0.5 "Multiplos Administradores Locais" "O grupo Administradores tem $($adm.Count) membros locais: $(($adm | Select-Object -First 3) -join ', ')..." "Rever permissoes na gestao de utilizadores." 1
    }
}