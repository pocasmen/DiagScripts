# Historical comparison for ECG Diagnostic
# Compares current results with previous JSON report to detect trends

# History comparison rules
function Invoke-HistoryRules {
    if ($NoHistory) { return }
    $prevPath = $null
    if ($CompareWith -and (Test-Path -LiteralPath $CompareWith)) { $prevPath = $CompareWith }
    else {
        $cand = Get-ChildItem -LiteralPath $OutputDir -Filter "ECG_*_$($env:COMPUTERNAME)_*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($cand) { $prevPath = $cand.FullName }
    }
    if (-not $prevPath) { return }
    $prev = Get-Content -LiteralPath $prevPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $days = $null
    try { $days = [math]::Round(((Get-Date) - [datetime]$prev.Metadata.Timestamp).TotalDays, 1) } catch { }
    $rows = @(Get-TrendRows -Prev $prev -Cur $Report)
    $Report.Trend = [ordered]@{ PreviousFile = (Split-Path $prevPath -Leaf); DaysSincePrevious = $days; Rows = $rows }

    foreach ($r in $rows) {
        if (-not $r.Worse) { continue }
        switch -Wildcard ($r.Key) {
            'VolFree:*' {
                if ($r.Previous -gt 0 -and (-not $r.Delta) -eq $false -and ([math]::Abs($r.Delta) -ge 10) -and (([math]::Abs($r.Delta) / $r.Previous) -ge 0.15)) {
                    Add-Finding "Storage" "Warning" 0.6 "Espaco Livre a Diminuir ($($r.Metric))" "De $($r.Previous) para $($r.Current) GB ($($r.Delta) GB) em $days dias." "Investigar e libertar espaco." 1
                }
            }
            'DiskWear:*' { if ($r.Delta -ge 3) { Add-Finding "Storage" "Warning" 0.7 "Desgaste de Disco a Aumentar Depressa" "$($r.Metric): de $($r.Previous)% para $($r.Current)% em $days dias." "Rever cargas de escrita e planear substituicao." 1 } }
            'DiskErr:*'  { if ($r.Delta -gt 0) { Add-Finding "Storage" "Warning" 0.75 "Novos Erros de I/O Nao Corrigidos" "$($r.Metric): +$($r.Delta) desde a ultima analise." "Verificar SMART." 2; Add-Suspect "Armazenamento" 1.5 "Erros de I/O a aumentar" } }
            'Stability'  { if ($r.Delta -le -2) { Add-Finding "Windows" "Warning" 0.6 "Indice de Fiabilidade a Descer" "De $($r.Previous) para $($r.Current)." "Rever o Monitor de Fiabilidade." 1 } }
            'Minidumps'  { if ($r.Delta -gt 0) { Add-Finding "Windows" "Warning" 0.7 "Novos Minidumps desde a Ultima Analise" '+$($r.Delta) minidump(s).' "Analisar crashes." 1 } }
            'BatteryWear'{ if ($r.Delta -ge 5) { Add-Finding "Hardware" "Info" 0.6 "Desgaste da Bateria a Aumentar" "De $($r.Previous)% para $($r.Current)%." "Planear substituicao." 1 } }
            'Score'      { if ($r.Delta -le -15) { Add-Finding "Windows" "Info" 0.5 "HealthScore Piorou Bastante" "De $($r.Previous) para $($r.Current)." "Rever os findings novos." 1 } }
        }
    }
    return $null
}