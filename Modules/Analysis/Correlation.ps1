# Correlation and suspect ranking for ECG Diagnostic
# Cross-references findings and suspects to identify primary suspect and overall health score

# Correlation rules - cross-reference findings and suspects
function Invoke-CorrelationRules {
    $kp = $F.AggregatedEvents.KernelPower41
    if ($script:Suspects.Contains('Armazenamento') -and $kp.TotalCount -ge 1) {
        Add-Suspect "Armazenamento" 1.5 "Reinicios inesperados coexistem com sinais de armazenamento"
    }
    if ($script:Suspects.Contains('GPU') -and $F.AggregatedEvents.DisplayTDR_Count -gt 0 -and @($F.CrashDumps.BugcheckAnalysis | Where-Object { $_.Category -eq 'GPU' }).Count -gt 0) {
        Add-Suspect "GPU" 2 "TDR coincide com BugCheck grafico"
    }
    $ranked = @($script:Suspects.Values | Sort-Object { $_.Points } -Descending)
    $Report.Suspects = @($ranked | ForEach-Object { [ordered]@{ Name = $_.Name; Points = [math]::Round($_.Points, 1); Reasons = $_.Reasons } })
    $top = $ranked | Select-Object -First 1
    if ($top -and $top.Points -ge 3.0) {
        $Report.PrimarySuspect = [ordered]@{ Name = $top.Name; Points = [math]::Round($top.Points, 1); Reasons = $top.Reasons }
    }
}