# Network analysis rules for ECG Diagnostic
# Analyzes network integrity, connectivity, DNS, packet loss, and Wi-Fi signal

# Network rules analysis
function Invoke-NetworkRules {
    $ni = $F.NetworkIntegrity
    if ($ni.SuspiciousHostsEntries -and $ni.SuspiciousHostsEntries.Count -gt 0) {
        Add-Finding "Network" "Critical" 0.95 "Ficheiro Hosts Modificado (Suspeito)" "Linhas ativas referem dominios vitais: $(($ni.SuspiciousHostsEntries | Select-Object -First 3) -join '; ')" "Remover imediatamente estas entradas do ficheiro hosts." 2
        Add-Suspect "Seguranca/Malware" 3 "Ficheiro hosts manipulado"
    }
    if ($ni.ProxyEnabled) {
        Add-Finding "Network" "Info" 0.6 "Configuracao Proxy Ativa no Registo" "ProxyEnable=1 no perfil de utilizador." "Confirmar se isto e legitimo (rede empresarial) ou residual de adware." 1
    }

    $N = $F.Network
    if ($N.AdapterActive -eq "Nenhum") {
        Add-Finding "Network" "Critical" 1.0 "Sem Adaptadores de Rede com Link Ativo" "Nenhuma placa conectada." "Verificar cabos ou Wi-Fi." 2
        Add-Suspect "Rede" 3 "Sem adaptador ativo"
        return
    }

    if (-not $ni.NCSI_ConnectTest_OK) {
        Add-Finding "Network" "Warning" 0.8 "Sem Acesso Aberto a Internet (NCSI Fail)" "Sinal do endpoint Microsoft falhou (pode ser um Captive Portal em hotel/aeroporto ou Offline real)." "Abrir um browser e confirmar autenticacao." 1
    }

    if ($N.IsApipa) {
        Add-Finding "Network" "Critical" 0.95 "Endereco APIPA (169.254.x.x): Sem DHCP" "IPv4: $($N.IPv4 -join ', ')." "Renovar IP; testar ligacao fisica." 2
        Add-Suspect "Rede" 3 "APIPA (sem DHCP)"
    }

    foreach ($pair in @(@('Gateway', $N.Latency.Gateway, 50, 20), @('Internet', $N.Latency.Internet, 150, 40))) {
        $lbl = $pair[0]; $lt = $pair[1]
        if (-not $lt -or $lt.Sent -eq 0) { continue }
        if ($lbl -eq 'Gateway' -and $lt.Received -eq 0) { continue }
        if ($lt.LossPct -ge 20) {
            Add-Finding "Network" "Critical" 0.85 "Perda de Pacotes Elevada ($lbl)" "$($lt.LossPct)% de perda (media $($lt.AvgMs) ms)." "Verificar ligacao fisica ou router." 2
            Add-Suspect "Rede" 2.5 "Perda de pacotes $lbl $($lt.LossPct)%"
        } elseif ($lt.LossPct -ge 5) {
            Add-Finding "Network" "Warning" 0.75 "Perda de Pacotes ($lbl)" "$($lt.LossPct)% de perda." "Verificar qualidade do sinal." 1
        }
    }

    $dt = @($N.DnsServerTests)
    $dfail = @($dt | Where-Object { -not $_.Ok })
    if ($dfail.Count -gt 0 -and $dfail.Count -lt $dt.Count) {
        Add-Finding "Network" "Warning" 0.7 "Servidor DNS Nao Responde" "Falhou: $(($dfail | ForEach-Object { $_.Server }) -join ', ')." "Trocar ou remover este DNS." 1
    }
    $s = $N.Statistics
    if ($s) {
        $errs = [int64]$s.ReceivedPacketErrors + [int64]$s.OutboundPacketErrors + [int64]$s.ReceivedDiscardedPackets + [int64]$s.OutboundDiscardedPackets
        $pk = [int64]$s.ReceivedUnicastPackets + [int64]$s.SentUnicastPackets
        if ($errs -gt 100 -and $pk -gt 0 -and (100.0 * $errs / $pk) -ge 0.1) {
            Add-Finding "Network" "Warning" 0.65 "Erros/Descartes no Adaptador de Rede" "$errs erros/descartes." "Atualizar driver ou substituir cabo." 1
            Add-Suspect "Rede" 1.5 "Erros no adaptador"
        }
    }
    $wf = $N.WiFiDetails
    if ($wf) {
        if ($null -ne $wf.SignalPct -and $wf.SignalPct -lt 50) {
            $sev = if ($wf.SignalPct -lt 30) { "Critical" } else { "Warning" }
            Add-Finding "Network" $sev 0.75 "Sinal Wi-Fi Fraco" "SSID $($wf.SSID): sinal $($wf.SignalPct)%." "Aproximar do router ou usar cabo." 1
            Add-Suspect "Rede" 1.5 "Sinal Wi-Fi $($wf.SignalPct)%"
        }
    }
}