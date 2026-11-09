<#
.SYNOPSIS
    ECG-Diagnostic-v3.1.ps1 - Agente de Triagem e Diagnostico Clinico Windows (Orchestrator Modular)
.DESCRIPTION
    Versao 3.1. Melhorias:
      - Verificacao de versao do PowerShell (5.1+)
      - Logging estruturado para ficheiro
      - Timeout configuravel em chamadas WMI/CIM
      - Validacao de modulos disponiveis
      - Exportacao de relatorio em HTML
.PARAMETER Issue
    Sintoma reportado pelo cliente. Se omitido, e pedido interativamente.
.PARAMETER DeepIntegrity
    Executa tambem SFC /verifyonly (requer admin, pode demorar 1-3 min).
.PARAMETER Extended
    3 janelas de amostragem de CPU/disco/memoria (ativado automaticamente para queixas de lentidao).
.PARAMETER OutputDir
    Pasta de saida. Por defeito: pasta do script; se nao existir, o Ambiente de Trabalho.
.PARAMETER EventDays
    Janela de analise do Event Log em dias (1-90). Por defeito 30.
.PARAMETER PingCount
    Numero de pings por alvo no teste de latencia (5-200). Por defeito 20.
.PARAMETER CompareWith
    JSON anterior a comparar. Por defeito: o mais recente do mesmo computador em OutputDir.
.PARAMETER NoHistory
    Desativa a comparacao com o historico.
.PARAMETER Silent
    Modo silencioso - sem output para consola, apenas logging para ficheiro.
.PARAMETER LogPath
    Caminho para o ficheiro de log. Por defeito: OutputDir/ECG_[computador]_[timestamp].log
.PARAMETER WmiTimeout
    Timeout em segundos para chamadas WMI/CIM. Por defeito: 60.
.PARAMETER ExportHtml
    Exportar relatorio em formato HTML.
#>

[CmdletBinding()]
param (
    [string]$Issue = "",
    [switch]$DeepIntegrity,
    [switch]$Extended,
    [string]$OutputDir = "",
    [ValidateRange(1, 90)][int]$EventDays = 30,
    [ValidateRange(5, 200)][int]$PingCount = 20,
    [string]$CompareWith = "",
    [switch]$NoHistory,
    [switch]$Silent,
    [string]$LogPath = "",
    [int]$WmiTimeout = 60,
    [switch]$ExportHtml
)

# ==========================================================================
# MENU INTERATIVO (apenas se nao tiver parametros)
# ==========================================================================
if (-not $PSBoundParameters.ContainsKey('Issue') -and
    -not $PSBoundParameters.ContainsKey('DeepIntegrity') -and
    -not $PSBoundParameters.ContainsKey('Extended') -and
    -not $PSBoundParameters.ContainsKey('OutputDir') -and
    -not $PSBoundParameters.ContainsKey('EventDays') -and
    -not $PSBoundParameters.ContainsKey('PingCount') -and
    -not $PSBoundParameters.ContainsKey('CompareWith') -and
    -not $PSBoundParameters.ContainsKey('NoHistory') -and
    -not $PSBoundParameters.ContainsKey('Silent') -and
    -not $PSBoundParameters.ContainsKey('LogPath') -and
    -not $PSBoundParameters.ContainsKey('WmiTimeout') -and
    -not $PSBoundParameters.ContainsKey('ExportHtml')) {

    Clear-Host
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "  ECG-Diagnostic v3.1 - Menu Interativo" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Parametros disponiveis:" -ForegroundColor Yellow
    Write-Host "  -Issue          : Sintoma reportado (ex: 'PC lento')" -ForegroundColor Gray
    Write-Host "  -Silent         : Modo silencioso (sem output no console)" -ForegroundColor Gray
    Write-Host "  -LogPath        : Caminho para o ficheiro de log" -ForegroundColor Gray
    Write-Host "  -WmiTimeout     : Timeout para chamadas WMI (segundos)" -ForegroundColor Gray
    Write-Host "  -ExportHtml     : Exportar relatorio em HTML" -ForegroundColor Gray
    Write-Host "  -DeepIntegrity  : Executar SFC /verifyonly (requer admin)" -ForegroundColor Gray
    Write-Host "  -Extended       : 3 janelas de amostragem CPU/disco/memoria" -ForegroundColor Gray
    Write-Host "  -OutputDir      : Pasta de saida para os ficheiros" -ForegroundColor Gray
    Write-Host "  -EventDays      : Janela de analise de eventos (1-90 dias)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Pressione ENTER para continuar com o menu..." -ForegroundColor Gray
    Read-Host
    
    # Pergunta 1: Issue
    $menuIssue = Read-Host "Sintoma reportado (Enter para pular)"
    if (-not [string]::IsNullOrWhiteSpace($menuIssue)) { $Issue = $menuIssue }
    
    # Pergunta 2: Modo Silencioso
    $silentAnswer = Read-Host "Executar em modo silencioso (sem output no console)? (S/N)"
    if ($silentAnswer -eq 'S' -or $silentAnswer -eq 's') { $Silent = $true }
    
    # Pergunta 3: Caminho do Log
    $logPathAnswer = Read-Host "Caminho para o ficheiro de log (Enter para default)"
    if (-not [string]::IsNullOrEmpty($logPathAnswer)) { $LogPath = $logPathAnswer }
    
    # Pergunta 4: Timeout WMI
    $timeoutAnswer = Read-Host "Timeout para chamadas WMI em segundos (Enter para default: 60)"
    if (-not [string]::IsNullOrEmpty($timeoutAnswer) -and $timeoutAnswer -match '^\d+$') { 
        $WmiTimeout = [int]$timeoutAnswer
        $global:WmiTimeout = $WmiTimeout
    }
    
    # Pergunta 5: Exportar HTML
    $exportHtmlAnswer = Read-Host "Exportar relatorio para HTML? (S/N)"
    if ($exportHtmlAnswer -eq 'S' -or $exportHtmlAnswer -eq 's') { $ExportHtml = $true }
    
    # Pergunta 6: DeepIntegrity
    $deepIntegrityAnswer = Read-Host "Executar verificacao de integridade do sistema (SFC)? (S/N)"
    if ($deepIntegrityAnswer -eq 'S' -or $deepIntegrityAnswer -eq 's') { $DeepIntegrity = $true }
    
    # Pergunta 7: Extended
    $extendedAnswer = Read-Host "Modo estendido (3 janelas de amostragem)? (S/N)"
    if ($extendedAnswer -eq 'S' -or $extendedAnswer -eq 's') { $Extended = $true }
    
    Write-Host ""
    Write-Host "Iniciando diagnostico com as opcoes selecionadas..." -ForegroundColor Green
    Write-Host ""
    Start-Sleep -Seconds 2
}

# ==========================================================================
# CARREGAMENTO DOS MODULOS
# ==========================================================================
$ModuleLoaderPath = Join-Path $PSScriptRoot "Modules\Core\ModuleLoader.ps1"
if (-not (Test-Path -LiteralPath $ModuleLoaderPath)) {
    Write-Host "[ERRO] ModuleLoader.ps1 nao encontrado em: $ModuleLoaderPath" -ForegroundColor Red
    exit 1
}
. $ModuleLoaderPath

# ==========================================================================
# VERIFICACAO DE REQUISITOS
# ==========================================================================
$RequiredPSVersion = [Version]"5.1"
$CurrentPSVersion = $PSVersionTable.PSVersion

$global:WmiTimeout = $WmiTimeout

if ($CurrentPSVersion -lt $RequiredPSVersion) {
    $errorMsg = "ECG-Diagnostic requer PowerShell $($RequiredPSVersion.ToString()) ou superior. " +
                "Versao atual: $($CurrentPSVersion.ToString())."
    Write-Host "[ERRO] $errorMsg" -ForegroundColor Red
    exit 1
}

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:IsAdmin = $IsAdmin

# ==========================================================================
# LOGGING ESTRUTURADO
# ==========================================================================
if ([string]::IsNullOrWhiteSpace($LogPath)) {
    if ([string]::IsNullOrWhiteSpace($OutputDir)) {
        $OutputDir = if ($PSScriptRoot) { $PSScriptRoot } else { [Environment]::GetFolderPath('Desktop') }
    }
    if (-not (Test-Path -LiteralPath $OutputDir)) {
        try { New-Item -ItemType Directory -Path $OutputDir -Force -ErrorAction Stop | Out-Null }
        catch { $OutputDir = [Environment]::GetFolderPath('Desktop') }
    }
    $LogPath = Join-Path $OutputDir ("ECG_$($env:COMPUTERNAME)_" + (Get-Date).ToString('yyyyMMdd_HHmmss') + ".log")
}

Initialize-Logging -LogPathParam $LogPath -SilentParam:$Silent

Write-DiagLog -Message "Iniciando ECG-Diagnostic v3.1" -Level "Info" -Component "System"
Write-DiagLog -Message "PowerShell Version: $($CurrentPSVersion.ToString())" -Level "Info" -Component "System"
Write-DiagLog -Message "Executando como administrador: $IsAdmin" -Level "Info" -Component "System"
Write-DiagLog -Message "Modo silencioso: $Silent" -Level "Info" -Component "System"

# ==========================================================================
# VALIDACAO DE MODULOS CRITICOS
# ==========================================================================
$RequiredModules = @{
    'NetAdapter' = @{ Module = 'NetAdapter'; Fallback = 'netsh' }
    'NetTCPIP'   = @{ Module = 'NetTCPIP'; Fallback = 'ipconfig' }
    'DnsClient'  = @{ Module = 'DnsClient'; Fallback = 'nslookup' }
}

foreach ($mod in $RequiredModules.Keys) {
    $info = $RequiredModules[$mod]
    if (-not (Test-ModuleAvailable -ModuleName $info.Module -FallbackCommand $info.Fallback)) {
        Write-DiagLog -Message "Aviso: Modulo $($info.Module) nao disponivel. Algumas funcionalidades de rede podem nao funcionar." -Level "Warning" -Component "ModuleCheck"
    }
}

# ==========================================================================
# 0. ENTRADA, PERFIS DA QUEIXA E PASTA DE SAIDA
# ==========================================================================
$ScriptVersion = "3.1"
$StepTotal = 11
$SampleSeconds = 4

if ([string]::IsNullOrWhiteSpace($Issue)) {
    $Issue = "Revisao preventiva geral"
}

$IssueProfiles = @(Get-IssueProfiles -Text $Issue -ProfileMap $IssueProfileMap)
foreach ($pn in $IssueProfiles) {
    foreach ($c in $IssueFocusMap[$pn]) {
        if ($script:FocusCategories -notcontains $c) { $script:FocusCategories += $c }
    }
}
$ExtendedMode = ([bool]$Extended -or ($IssueProfiles -contains 'Performance'))
$EffEventDays = if ($IssueProfiles -contains 'Stability') { [math]::Max($EventDays, 14) } else { $EventDays }
$EffPingCount = if ($IssueProfiles -contains 'Network') { [math]::Max($PingCount, 40) } else { $PingCount }
$BootDays = if ($IssueProfiles -contains 'Boot') { 30 } else { 14 }
$CrashDays = [math]::Max($EffEventDays, 30)

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = if ($PSScriptRoot) { $PSScriptRoot } else { [Environment]::GetFolderPath('Desktop') }
}
if (-not (Test-Path -LiteralPath $OutputDir)) {
    try { New-Item -ItemType Directory -Path $OutputDir -Force -ErrorAction Stop | Out-Null }
    catch { $OutputDir = [Environment]::GetFolderPath('Desktop') }
}

$Watch = [System.Diagnostics.Stopwatch]::StartNew()

$Report = [ordered]@{
    SchemaVersion           = "3.0"
    DiagnosticEngine        = "ECG-Universal"
    DiagnosticEngineVersion = "3.0.0"
    Metadata = [ordered]@{
        ComputerName    = $env:COMPUTERNAME
        Timestamp       = (Get-Date).ToString("o")
        IssueReported   = $Issue
        IssueProfiles   = $IssueProfiles
        FocusCategories = $script:FocusCategories
        RanAsAdmin      = $IsAdmin
        DeepIntegrity   = [bool]$DeepIntegrity
        ExtendedMode    = $ExtendedMode
        EventWindowDays = $EffEventDays
        PingCount       = $EffPingCount
        ConfidenceNote  = "Confidence = constante heuristica atribuida manualmente, nao uma medicao."
    }
    HealthScore = [ordered]@{
        Overall  = 100
        Hardware = 100
        Storage  = 100
        Memory   = 100
        Windows  = 100
        Network  = 100
    }
    Facts = [ordered]@{}
    Findings = @()
    RecommendedActions = @()
    Suspects = @()
    PrimarySuspect = $null
    Trend = $null
    DataCoverage = $null
}

# ==========================================================================
# 1. CONTEXTO, HARDWARE BASE, FIRMWARE, BATERIA, GPU
# ==========================================================================
Invoke-CollectionContext

# ==========================================================================
# 2. AMOSTRAGEM E 3. MEMORIA E SUBSISTEMAS OCULTOS (WSL)
# ==========================================================================
Invoke-CollectionMemory -SampleSeconds $SampleSeconds -ExtendedMode $ExtendedMode

# ==========================================================================
# 4. ARMAZENAMENTO (e amostragem 2/3 se Extended)
# ==========================================================================
Invoke-CollectionStorage -SampleSeconds $SampleSeconds -ExtendedMode $ExtendedMode

# ==========================================================================
# 5. EVENTOS DE SISTEMA (COM TENDENCIAS) E 6. CRASHES
# ==========================================================================
Invoke-CollectionEvents -EventDays $EffEventDays -CrashDays $CrashDays

# ==========================================================================
# 7. REDE
# ==========================================================================
Invoke-CollectionNetwork -PingCount $EffPingCount

# ==========================================================================
# 8. WINDOWS & 9. SEGURANCA (e amostragem 3/3 se Extended)
# ==========================================================================
Invoke-CollectionServices -DeepIntegrity ([bool]$DeepIntegrity) -BootDays $BootDays -SampleSeconds $SampleSeconds -ExtendedMode $ExtendedMode

# ==========================================================================
# 10. MOTOR HEURISTICO, CORRELACAO, HISTORICO E RELATORIO
# ==========================================================================
Show-Step "A avaliar regras forenses, correlacionar suspeitos e gerar relatorio..."
$F = $Report.Facts

# Regras Forenses Modulares
Invoke-WindowsRules
Invoke-PerformanceRules -PerfWindows $script:PerfWindows
Invoke-MemoryRules
Invoke-HardwareRules
Invoke-StorageRules
Invoke-CrashesRules
Invoke-NetworkRules
Invoke-SecurityRules
Invoke-CorrelationRules
Invoke-HistoryRules -OutputDir $OutputDir -CompareWith $CompareWith -NoHistory:$NoHistory

# --------------------------------------------------------------------------
# Cobertura de dados
# --------------------------------------------------------------------------
$cov = if ($script:Coverage) { @($script:Coverage.ToArray()) } else { @() }
$covOk = @($cov | Where-Object { $_.Status -eq 'Ok' }).Count
$covFail = @($cov | Where-Object { $_.Status -eq 'Failed' }).Count
$covSkip = @($cov | Where-Object { $_.Status -eq 'Skipped' }).Count
$covTo = @($cov | Where-Object { $_.Status -eq 'Timeout' }).Count
$covPct = if ($cov.Count -gt 0) { [int][math]::Round(100.0 * $covOk / $cov.Count, 0) } else { 0 }
$covLevel = if ($covPct -ge 90) { 'Alta' } elseif ($covPct -ge 70) { 'Media' } else { 'Baixa' }
$Report.DataCoverage = [ordered]@{
    StepsTotal = $cov.Count; StepsOk = $covOk; StepsFailed = $covFail; StepsSkipped = $covSkip; StepsTimeout = $covTo
    Percent = $covPct; ConfidenceLevel = $covLevel
    Note = "A pontuacao so e totalmente fiavel com cobertura Alta (executar como administrador)."
    Steps = $cov
}

$Watch.Stop()
$Report.Metadata.DurationSeconds = [math]::Round($Watch.Elapsed.TotalSeconds, 2)
$Report.Facts.CollectionErrors = @($script:DiagErrors)

# =========================================================================
# APRESENTACAO NO TERMINAL E EXPORTACAO
# =========================================================================
$SortedFindings = @($Report.Findings | Sort-Object @{ Expression = { switch ($_.Severity) { 'Critical' { 0 } 'Warning' { 1 } default { 2 } } } }, @{ Expression = { if ($_.RelevantToIssue) { 0 } else { 1 } } })

if (-not $Silent) {
    Show-ConsoleOutput -Report $Report -SortedFindings $SortedFindings -Issue $Issue -IssueProfiles $IssueProfiles -CovPct $covPct -CovLevel $covLevel
}

# Gravacao dos ficheiros (UTF-8)
$TimeStampStr = (Get-Date).ToString('yyyyMMdd_HHmmss')
$BaseName = "ECG_v31_$($env:COMPUTERNAME)_$TimeStampStr"
$JsonPath = Join-Path $OutputDir "$BaseName.json"
$TxtPath  = Join-Path $OutputDir "$BaseName.txt"
$HtmlPath = Join-Path $OutputDir "$BaseName.html"

try {
    $Report | ConvertTo-Json -Depth 10 | Out-File -FilePath $JsonPath -Encoding UTF8 -ErrorAction Stop
    $textRep = Get-TextReport -Report $Report
    $textRep | Out-File -FilePath $TxtPath -Encoding UTF8 -ErrorAction Stop
    Write-DiagLog -Message "Relatorio JSON gravado: $JsonPath" -Level "Info" -Component "Report"
    Write-DiagLog -Message "Relatorio TXT gravado: $TxtPath" -Level "Info" -Component "Report"

    if ($ExportHtml) {
        $htmlSuccess = Export-HtmlReport -Report $Report -OutputPath $HtmlPath
        if ($htmlSuccess) {
            Write-DiagLog -Message "Relatorio HTML gravado: $HtmlPath" -Level "Info" -Component "Report"
        }
    }

    if (-not $Silent) {
        Write-Host "`nRelatorio de texto gravado em : $TxtPath" -ForegroundColor Cyan
        Write-Host "Payload JSON para o Agente    : $JsonPath`n" -ForegroundColor Cyan
        if ($ExportHtml -and $htmlSuccess) {
            Write-Host "Relatorio HTML gerado            : $HtmlPath`n" -ForegroundColor Cyan
        }
    }
} catch {
    Write-DiagLog -Message "ERRO ao gravar relatorios: $($_.Exception.Message)" -Level "Error" -Component "Report"
    if (-not $Silent) {
        Write-Host "`nERRO ao gravar relatorios em '$OutputDir': $($_.Exception.Message)" -ForegroundColor Red
    }
}