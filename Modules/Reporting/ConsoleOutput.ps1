# Console output presentation for ECG Diagnostic
# Displays diagnostic results in terminal with color coding

function Show-ConsoleOutput {
    param(
        [Parameter(Mandatory=$true)][object]$Report,
        [Parameter(Mandatory=$false)][AllowEmptyCollection()][array]$SortedFindings = @(),
        [string]$Issue = "",
        [array]$IssueProfiles = @(),
        [int]$CovPct = 100,
        [string]$CovLevel = "Alta"
    )

    if (-not $Silent) {
        Write-Host ""
        Write-Host "==========================================================" -ForegroundColor Cyan
        Write-Host "         PARECER CLINICO DO ECG (TRIAGEM LOCAL)           " -ForegroundColor Cyan
        Write-Host "   Schema: v$($Report.SchemaVersion) | Tempo: $($Report.Metadata.DurationSeconds)s | Queixa: $Issue" -ForegroundColor Gray
        if ($IssueProfiles.Count -gt 0) { Write-Host "   Perfis da queixa: $($IssueProfiles -join ', ') | Foco: $($script:FocusCategories -join ', ')" -ForegroundColor Gray }
        Write-Host "==========================================================" -ForegroundColor Cyan
        
        Write-Host "`nPONTUACAO DE SAUDE PONDERADA (0-100):" -ForegroundColor White
        $ScoreColor = if ($Report.HealthScore.Overall -ge 80) { "Green" } elseif ($Report.HealthScore.Overall -ge 50) { "Yellow" } else { "Red" }
        Write-Host "  GLOBAL   : $($Report.HealthScore.Overall)/100   (cobertura de dados: $CovPct% - confianca $CovLevel)" -ForegroundColor $ScoreColor
        Write-Host "  Hardware : $($Report.HealthScore.Hardware) | Storage : $($Report.HealthScore.Storage) | RAM : $($Report.HealthScore.Memory)" -ForegroundColor Gray
        Write-Host "  Windows  : $($Report.HealthScore.Windows)  | Rede    : $($Report.HealthScore.Network)" -ForegroundColor Gray
        
        if ($Report.PrimarySuspect) {
            Write-Host "`nSUSPEITO PRINCIPAL: $($Report.PrimarySuspect.Name) ($($Report.PrimarySuspect.Points) pts)" -ForegroundColor Magenta
            Write-Host "  Motivos: $($Report.PrimarySuspect.Reasons -join '; ')" -ForegroundColor Gray
            $others = @($Report.Suspects | Select-Object -Skip 1 -First 2)
            foreach ($o in $others) { Write-Host "  Tambem: $($o.Name) ($($o.Points) pts)" -ForegroundColor DarkGray }
        }
        
        Write-Host "`nDIAGNOSTICOS E EVIDENCIAS ($($SortedFindings.Count)):" -ForegroundColor White
        if ($SortedFindings.Count -eq 0) {
            Write-Host "  [OK] Nenhuma anomalia identificada nos sinais vitais." -ForegroundColor Green
        } else {
            foreach ($f in $SortedFindings) {
                $color = if ($f.Severity -eq "Critical") { "Red" } elseif ($f.Severity -eq "Warning") { "Yellow" } else { "Cyan" }
                $tag = if ($f.RelevantToIssue) { " *" } else { "" }
                Write-Host "  [$($f.Severity)] $($f.Category): $($f.Finding)$tag" -ForegroundColor $color
                Write-Host "    Evidencia : $($f.Evidence)" -ForegroundColor Gray
                Write-Host "    Acao      : $($f.RecommendedAction)" -ForegroundColor DarkCyan
            }
        }
        
        if ($Report.Trend -and @($Report.Trend.Rows | Where-Object { $_.Worse }).Count -gt 0) {
            Write-Host "`nTENDENCIA vs ANALISE ANTERIOR ($($Report.Trend.PreviousFile), ha $($Report.Trend.DaysSincePrevious) dias):" -ForegroundColor White
            foreach ($r in @($Report.Trend.Rows | Where-Object { $_.Worse })) {
                Write-Host "  [pior] $($r.Metric): $($r.Previous) -> $($r.Current) $($r.Unit) (delta $($r.Delta))" -ForegroundColor Yellow
            }
        }
        
        if ($Report.RecommendedActions.Count -gt 0) {
            Write-Host "`nPLANO DE INTERVENCAO PROPOSTO:" -ForegroundColor Yellow
            foreach ($act in $Report.RecommendedActions) { Write-Host "  [ ] $act" -ForegroundColor White }
        }
        if ($script:DiagErrors.Count -gt 0) {
            Write-Host "`nAVISOS DE RECOLHA ($($script:DiagErrors.Count)) - ver Facts.CollectionErrors no JSON." -ForegroundColor DarkYellow
        }
        Write-Host "==========================================================" -ForegroundColor Cyan
    }
}