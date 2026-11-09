# Text report generation for ECG Diagnostic
# Generates plain text report from diagnostic findings

function Get-TextReport {
    param(
        [Parameter(Mandatory=$true)]
        [object]$Report
    )

    $ScriptVersion = "3.1"
    $SortedFindings = @($Report.Findings | Sort-Object @{ Expression = { switch ($_.Severity) { 'Critical' { 0 } 'Warning' { 1 } default { 2 } } } }, @{ Expression = { if ($_.RelevantToIssue) { 0 } else { 1 } } })

    $FindingsText = if ($SortedFindings.Count -eq 0) { "Nenhuma anomalia identificada." } else {
        ($SortedFindings | ForEach-Object {
            "[$($_.Severity)] ($($_.Category)) $($_.Finding)$(if ($_.RelevantToIssue) { ' *' })`n  Evidencia: $($_.Evidence)`n  Acao     : $($_.RecommendedAction)"
        }) -join "`n`n"
    }

    $ActionsText = if ($Report.RecommendedActions) {
        ($Report.RecommendedActions | ForEach-Object { "- $_" }) -join "`n"
    } else { "(nenhum plano de acao)" }

    $errs = $Report.Facts.CollectionErrors
    $ErrorsText  = if ($errs -and $errs.Count -gt 0) { ($errs | ForEach-Object { "- $_" }) -join "`n" } else { "(nenhum)" }
    
    $SuspectsText = if (@($Report.Suspects).Count -gt 0) {
        (@($Report.Suspects) | Select-Object -First 5 | ForEach-Object { "- $($_.Name) ($($_.Points) pts): $($_.Reasons -join '; ')" }) -join "`n"
    } else { "(sem suspeitos)" }
    
    $PrimaryText = if ($Report.PrimarySuspect) { "$($Report.PrimarySuspect.Name) ($($Report.PrimarySuspect.Points) pts)" } else { "(nenhum acima do limiar)" }
    
    $TrendText = if ($Report.Trend) {
        "Anterior: $($Report.Trend.PreviousFile) (ha $($Report.Trend.DaysSincePrevious) dias)`n" +
        ((@($Report.Trend.Rows) | ForEach-Object { "- $($_.Metric): $($_.Previous) -> $($_.Current) $($_.Unit)$(if ($_.Worse) { '  [PIOR]' })" }) -join "`n")
    } else { "(sem analise anterior para comparar)" }

    $CovPct = if ($Report.DataCoverage) { $Report.DataCoverage.Percent } else { 100 }
    $CovLevel = if ($Report.DataCoverage) { $Report.DataCoverage.ConfidenceLevel } else { "Alta" }

    $ReportText = @"
==================================================================
RELATORIO CLINICO DE TRIAGEM (ECG v$ScriptVersion)
Computador : $($Report.Metadata.ComputerName)
Data/Hora  : $($Report.Metadata.Timestamp)
Queixa     : $($Report.Metadata.IssueReported)
Perfis     : $(@($Report.Metadata.IssueProfiles) -join ', ')
Admin      : $($Report.Metadata.RanAsAdmin) | Extended: $($Report.Metadata.ExtendedMode)
Duracao    : $($Report.Metadata.DurationSeconds) segundos
Schema     : v$($Report.SchemaVersion)
==================================================================

SCORES DE SAUDE PONDERADOS (heuristicos):
- Global   : $($Report.HealthScore.Overall)/100
- Hardware : $($Report.HealthScore.Hardware)/100
- Storage  : $($Report.HealthScore.Storage)/100
- Memoria  : $($Report.HealthScore.Memory)/100
- Windows  : $($Report.HealthScore.Windows)/100
- Rede     : $($Report.HealthScore.Network)/100
Cobertura de dados: $CovPct% (confianca $CovLevel)

SUSPEITO PRINCIPAL: $PrimaryText
$SuspectsText

DIAGNOSTICOS FORENSES ($($SortedFindings.Count)):
$FindingsText

TENDENCIA vs ANALISE ANTERIOR:
$TrendText

PLANO DE INTERVENCAO PROPOSTO:
$ActionsText

AVISOS DE RECOLHA:
$ErrorsText
==================================================================
"@

    return $ReportText
}
