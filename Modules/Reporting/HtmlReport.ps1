# HTML report generation for ECG Diagnostic
# Generates a styled HTML report from diagnostic findings

# Export HTML report
function Export-HtmlReport {
    param(
        [object]$Report,
        [string]$OutputPath
    )

    Write-DiagLog -Message "Gerando relatorio HTML em: $OutputPath" -Level "Info" -Component "Report"

    # Generate HTML
    $html = @"
<!DOCTYPE html>
<html lang="pt-PT">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ECG Diagnostic Report - $($Report.Metadata.ComputerName)</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .header-meta {
            opacity: 0.9;
            font-size: 0.9em;
            margin-top: 10px;
        }
        h2 {
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-top: 30px;
        }
        h3 {
            color: #764ba2;
            margin-top: 25px;
        }
        .score-container {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin: 20px 0;
        }
        .score-card {
            flex: 1;
            min-width: 200px;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        .score-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }
        .score-label {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .score-global {
            font-size: 3em;
        }
        .finding {
            background: white;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-left: 4px solid;
        }
        .finding.critical { border-left-color: #dc3545; }
        .finding.warning { border-left-color: #ffc107; }
        .finding.info { border-left-color: #17a2b8; }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .finding-severity {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }
        .finding.critical .finding-severity { background: #dc3545; }
        .finding.warning .finding-severity { background: #ffc107; color: #333; }
        .finding.info .finding-severity { background: #17a2b8; }
        .finding-category {
            font-weight: bold;
            color: #667eea;
        }
        .evidence {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            white-space: pre-wrap;
        }
        .action {
            background: #e7f3ff;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
            border-left: 3px solid #17a2b8;
        }
        .suspect {
            background: #fff3cd;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 4px solid #ffc107;
        }
        .suspect-primary {
            background: #f8d7da;
            border-left-color: #dc3545;
        }
        .table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        .table th, .table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .table th {
            background-color: #667eea;
            color: white;
        }
        .table tr:hover {
            background-color: #f5f5f5;
        }
        .relevant {
            font-weight: bold;
            color: #667eea;
        }
        .coverage {
            display: flex;
            gap: 20px;
            margin: 20px 0;
        }
        .coverage-item {
            text-align: center;
            padding: 15px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            flex: 1;
        }
        .coverage-value {
            font-size: 1.5em;
            font-weight: bold;
        }
        .metadata {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin: 20px 0;
        }
        .metadata-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        .metadata-item {
            padding: 10px;
            border-bottom: 1px solid #eee;
        }
        .metadata-label {
            font-weight: bold;
            color: #667eea;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>ðŸ“Š ECG Diagnostic Report</h1>
        <div class="header-meta">
            <div>Computador: <strong>$($Report.Metadata.ComputerName)</strong></div>
            <div>Data: <strong>$($Report.Metadata.Timestamp)</strong></div>
            <div>Versao: <strong>$($Report.SchemaVersion)</strong></div>
            <div>Engine: <strong>$($Report.DiagnosticEngine) v$($Report.DiagnosticEngineVersion)</strong></div>
        </div>
    </div>

    <h2>ðŸŽ¯ Resumo Executivo</h2>

    <div class="metadata">
        <h3>Queixa Reportada</h3>
        <p><strong>$($Report.Metadata.IssueReported)</strong></p>
        <p>Perfis: <strong>$($Report.Metadata.IssueProfiles -join ', ')</strong></p>
        <p>Categorias de foco: <strong>$($Report.Metadata.FocusCategories -join ', ')</strong></p>
    </div>

    <h2>ðŸ“ˆ PontuaÃ§Ã£o de SaÃºde</h2>
    <div class="score-container">
        <div class="score-card">
            <div class="score-value score-global">$($Report.HealthScore.Overall)</div>
            <div class="score-label">Global</div>
        </div>
        <div class="score-card">
            <div class="score-value">$($Report.HealthScore.Hardware)</div>
            <div class="score-label">Hardware</div>
        </div>
        <div class="score-card">
            <div class="score-value">$($Report.HealthScore.Storage)</div>
            <div class="score-label">Armazenamento</div>
        </div>
        <div class="score-card">
            <div class="score-value">$($Report.HealthScore.Memory)</div>
            <div class="score-label">MemÃ³ria</div>
        </div>
        <div class="score-card">
            <div class="score-value">$($Report.HealthScore.Windows)</div>
            <div class="score-label">Windows</div>
        </div>
        <div class="score-card">
            <div class="score-value">$($Report.HealthScore.Network)</div>
            <div class="score-label">Rede</div>
        </div>
    </div>
"@

    # Add Suspects
    if ($Report.PrimarySuspect) {
        $html += @"
    <h2>ðŸ” Suspeito Principal</h2>
    <div class="suspect suspect-primary">
        <h3>$($Report.PrimarySuspect.Name) <span style="color: #dc3545;">($([math]::Round($Report.PrimarySuspect.Points, 1)) pts)</span></h3>
        <p><strong>Motivos:</strong> $($Report.PrimarySuspect.Reasons -join ', ')</p>
    </div>

    <h2>ðŸ‘¥ Outros Suspeitos</h2>
"@
        if ($Report.Suspects.Count -gt 0) {
            $html += @"
    <div class="suspects-container">
"@
            foreach ($suspect in $Report.Suspects) {
                $html += @"
        <div class="suspect">
            <h4>$($suspect.Name) <span style="color: #ffc107;">($([math]::Round($suspect.Points, 1)) pts)</span></h4>
            <p><strong>Motivos:</strong> $($suspect.Reasons -join ', ')</p>
        </div>
"@
            }
            $html += @"
    </div>
"@
        }
    }

    # Add Findings
    $html += @"
    <h2>âš ï¸ DiagnÃ³sticos e EvidÃªncias</h2>
"@

    $SortedFindings = @($Report.Findings | Sort-Object @{ Expression = { switch ($_.Severity) { 'Critical' { 0 } 'Warning' { 1 } default { 2 } } } }, @{ Expression = { if ($_.RelevantToIssue) { 0 } else { 1 } } })

    if ($SortedFindings.Count -eq 0) {
        $html += @"
    <p style="text-align: center; color: #28a745; font-size: 1.2em;">âœ… Nenhuma anomalia identificada nos sinais vitais.</p>
"@
    } else {
        foreach ($f in $SortedFindings) {
            $relevantTag = if ($f.RelevantToIssue) { '<span class="relevant">[Relevante]</span>' } else { '' }
            $html += @"
    <div class="finding $($f.Severity.ToLower())">
        <div class="finding-header">
            <span class="finding-severity">$($f.Severity)</span>
            <span class="finding-category">$($f.Category)</span>
            $relevantTag
        </div>
        <h4>$($f.Finding)</h4>
        <div class="evidence"><strong>EvidÃªncia:</strong> $($f.Evidence)</div>
        <div class="action"><strong>AÃ§Ã£o Recomendada:</strong> $($f.RecommendedAction)</div>
    </div>
"@
        }
    }

    # Add Plan of Action
    if ($Report.RecommendedActions.Count -gt 0) {
        $html += @"
    <h2>ðŸ“‹ Plano de IntervenÃ§Ã£o Proposto</h2>
    <ol>
"@
        foreach ($act in $Report.RecommendedActions) {
            $html += "        <li>$act</li>`n"
        }
        $html += @"
    </ol>
"@
    }

    # Add Data Coverage
    $html += @"
    <h2>ðŸ“Š Cobertura de Dados</h2>
    <div class="coverage">
        <div class="coverage-item">
            <div class="coverage-value">$($Report.DataCoverage.StepsOk)</div>
            <div>Passos ConcluÃ­dos</div>
        </div>
        <div class="coverage-item">
            <div class="coverage-value">$($Report.DataCoverage.StepsFailed)</div>
            <div>Passos Falhados</div>
        </div>
        <div class="coverage-item">
            <div class="coverage-value">$($Report.DataCoverage.StepsSkipped)</div>
            <div>Passos Ignorados</div>
        </div>
        <div class="coverage-item">
            <div class="coverage-value">$($Report.DataCoverage.Percent)%</div>
            <div>Cobertura Total</div>
        </div>
        <div class="coverage-item">
            <div class="coverage-value">$($Report.DataCoverage.ConfidenceLevel)</div>
            <div>NÃ­vel de ConfianÃ§a</div>
        </div>
    </div>
"@

    # Add Facts (summary)
    $html += @"
    <h2>ðŸ”§ InformaÃ§Ãµes do Sistema</h2>
    <div class="metadata">
        <div class="metadata-grid">
            <div class="metadata-item">
                <span class="metadata-label">Sistema Operativo:</span><br>
                $($Report.Facts.System.OSCaption) (Build $($Report.Facts.System.OSBuild))
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Uptime:</span><br>
                $($Report.Facts.System.UptimeDays) dias
            </div>
            <div class="metadata-item">
                <span class="metadata-label">CPU:</span><br>
                $($Report.Facts.System.CPUModel) ($($Report.Facts.System.LogicalCores) nÃºcleos)
            </div>
            <div class="metadata-item">
                <span class="metadata-label">RAM Total:</span><br>
                $($Report.Facts.Memory.TotalRAM_MB) MB
            </div>
            <div class="metadata-item">
                <span class="metadata-label">RAM DisponÃ­vel:</span><br>
                $($Report.Facts.Memory.AvailableRAM_MB) MB ($($Report.Facts.Memory.AvailableRAM_Pct)%)
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Plano de Energia:</span><br>
                $($Report.Facts.System.PowerPlan)
            </div>
        </div>
    </div>
"@

    # Add footer
    $html += @"
    <div class="footer">
        <p>RelatÃ³rio gerado por <strong>ECG-Diagnostic v$($Report.SchemaVersion)</strong> em <strong>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</strong></p>
        <p>Engine: $($Report.DiagnosticEngine) v$($Report.DiagnosticEngineVersion) | DuraÃ§Ã£o: $($Report.Metadata.DurationSeconds)s</p>
    </div>
</body>
</html>
"@

    # Save file
    try {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8 -ErrorAction Stop
        Write-DiagLog -Message "Relatorio HTML gerado com sucesso: $OutputPath" -Level "Info" -Component "Report"
        return $true
    } catch {
        Write-DiagLog -Message "Erro ao gerar relatorio HTML: $($_.Exception.Message)" -Level "Error" -Component "Report"
        return $false
    }
}