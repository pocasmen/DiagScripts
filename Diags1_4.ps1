<#
.SYNOPSIS
    ECG-Diagnostic-v2.3.ps1 - Agente de Triagem e Diagnostico Clinico Windows
.DESCRIPTION
    Versao 2.3. Sobre a v2.2 acrescenta:
      Prioridade alta
        - Dispositivos PnP com erro (Win32_PnPEntity)
        - Quem esta a crashar: Application log 1000/1002 + Win32_ReliabilityRecords (por app e modulo)
        - Classificacao de BugChecks (tabela codigo -> categoria), evento 1001 e cabecalho dos minidumps
        - Throttling (Kernel-Processor-Power 37, PerformancePct) e % DPC / Interrupt
        - Latencia e fila de disco (contadores RAW, sem depender do idioma)
        - Pressao de memoria real (Pages Input/s, pagefile, top processos por memoria e handles)
        - Bateria (desgaste = FullCharged/Designed, ciclos)
        - Arranque (Diagnostics-Performance 100-110) e Fast Startup
      Por area
        - Storage: previsao de falha SMART, PowerOnHours, ciclos, IDs de eventos especificos,
          dirty bit, TRIM
        - RAM/GPU: modulos, canais, XMP, Windows Memory Diagnostic, TDR (4101), driver grafico
        - Rede: latencia/jitter/perda, estatisticas do adaptador, velocidade negociada, APIPA,
          tempo por servidor DNS, Wi-Fi (canal, banda, taxas, sinal)
        - Seguranca/atualizacoes: Defender, AV de terceiros, firewall, BitLocker, TPM, Secure Boot,
          falhas do Windows Update, idade da ultima atualizacao, versao fora de suporte
        - Servicos/drivers: Service Control Manager, drivers nao assinados/antigos,
          itens de arranque com caminho suspeito ou sem assinatura
      Robustez do motor
        - Contexto: VM vs fisico, portatil vs desktop (regras desligadas onde nao fazem sentido)
        - DataCoverage: cobertura por coletor, tempos, timeouts (runspaces) e nivel de confianca
        - Uso da queixa ($Issue): perfis (Performance, Stability, Network, Boot, Battery, Display,
          Security, Storage) que priorizam categorias e ajustam a recolha (todos os testes correm sempre)
        - Correlacao: lista de suspeitos com pontuacao e PrimarySuspect
        - Historico: comparacao com o JSON anterior do mesmo equipamento (Trend)
        - Modo -Extended: 3 janelas de amostragem espacadas (distingue pico de carga sustentada)
    Codigo-fonte em ASCII puro. Os relatorios (JSON e TXT) sao gravados em UTF-8.
    Os valores de Confidence sao constantes heuristicas, nao medicoes.
    A tabela de fim de suporte do Windows ($OsSupportTable) e interna: validar nas paginas
    de ciclo de vida da Microsoft.
.PARAMETER Issue
    Sintoma reportado pelo cliente. Se omitido, e pedido interativamente.
.PARAMETER DeepIntegrity
    Executa tambem SFC /verifyonly (requer admin, pode demorar 1-3 min).
.PARAMETER Extended
    3 janelas de amostragem de CPU/disco/memoria (ativado automaticamente para queixas de lentidao).
.PARAMETER OutputDir
    Pasta de saida. Por defeito: pasta do script; se nao existir, o Ambiente de Trabalho.
.PARAMETER EventDays
    Janela de analise do Event Log em dias (1-30). Por defeito 3.
.PARAMETER PingCount
    Numero de pings por alvo no teste de latencia (5-200). Por defeito 20.
.PARAMETER CompareWith
    JSON anterior a comparar. Por defeito: o mais recente do mesmo computador em OutputDir.
.PARAMETER NoHistory
    Desativa a comparacao com o historico.
#>

[CmdletBinding()]
param (
    [string]$Issue = "",
    [switch]$DeepIntegrity,
    [switch]$Extended,
    [string]$OutputDir = "",
    [ValidateRange(1, 30)][int]$EventDays = 3,
    [ValidateRange(5, 200)][int]$PingCount = 20,
    [string]$CompareWith = "",
    [switch]$NoHistory
)

$ScriptVersion = "2.3"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:DiagErrors = New-Object System.Collections.Generic.List[string]
$script:Coverage = New-Object System.Collections.Generic.List[object]
$script:Suspects = [ordered]@{}
$script:FocusCategories = @()
$script:StepNo = 0
$StepTotal = 10
$SampleSeconds = 4

# ==========================================================================
# TABELAS INTERNAS
# ==========================================================================

# BugCheck: chave = '0x' + hex maiusculo sem zeros a esquerda -> (nome, categoria)
$BugCheckTable = @{
    '0xA'        = @('IRQL_NOT_LESS_OR_EQUAL', 'Drivers')
    '0x1A'       = @('MEMORY_MANAGEMENT', 'RAM')
    '0x1E'       = @('KMODE_EXCEPTION_NOT_HANDLED', 'Drivers')
    '0x24'       = @('NTFS_FILE_SYSTEM', 'Armazenamento')
    '0x3B'       = @('SYSTEM_SERVICE_EXCEPTION', 'Drivers')
    '0x3D'       = @('INTERRUPT_EXCEPTION_NOT_HANDLED', 'Drivers')
    '0x3F'       = @('NO_MORE_SYSTEM_PTES', 'Drivers')
    '0x4E'       = @('PFN_LIST_CORRUPT', 'RAM')
    '0x50'       = @('PAGE_FAULT_IN_NONPAGED_AREA', 'RAM')
    '0x7A'       = @('KERNEL_DATA_INPAGE_ERROR', 'Armazenamento')
    '0x7B'       = @('INACCESSIBLE_BOOT_DEVICE', 'Armazenamento')
    '0x7E'       = @('SYSTEM_THREAD_EXCEPTION_NOT_HANDLED', 'Drivers')
    '0x7F'       = @('UNEXPECTED_KERNEL_MODE_TRAP', 'CPU/Hardware')
    '0x9C'       = @('MACHINE_CHECK_EXCEPTION', 'CPU/Hardware')
    '0x9F'       = @('DRIVER_POWER_STATE_FAILURE', 'Drivers')
    '0xBE'       = @('ATTEMPTED_WRITE_TO_READONLY_MEMORY', 'Drivers')
    '0xC2'       = @('BAD_POOL_CALLER', 'Drivers')
    '0xC4'       = @('DRIVER_VERIFIER_DETECTED_VIOLATION', 'Drivers')
    '0xC5'       = @('DRIVER_CORRUPTED_EXPOOL', 'Drivers')
    '0xCE'       = @('DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS', 'Drivers')
    '0xD1'       = @('DRIVER_IRQL_NOT_LESS_OR_EQUAL', 'Drivers')
    '0xEA'       = @('THREAD_STUCK_IN_DEVICE_DRIVER', 'GPU')
    '0xEF'       = @('CRITICAL_PROCESS_DIED', 'Software/Sistema')
    '0xF4'       = @('CRITICAL_OBJECT_TERMINATION', 'Armazenamento')
    '0xFC'       = @('ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY', 'Drivers')
    '0x101'      = @('CLOCK_WATCHDOG_TIMEOUT', 'CPU/Hardware')
    '0x109'      = @('CRITICAL_STRUCTURE_CORRUPTION', 'RAM')
    '0x116'      = @('VIDEO_TDR_FAILURE', 'GPU')
    '0x117'      = @('VIDEO_TDR_TIMEOUT_DETECTED', 'GPU')
    '0x119'      = @('VIDEO_SCHEDULER_INTERNAL_ERROR', 'GPU')
    '0x124'      = @('WHEA_UNCORRECTABLE_ERROR', 'CPU/Hardware')
    '0x133'      = @('DPC_WATCHDOG_VIOLATION', 'Drivers')
    '0x139'      = @('KERNEL_SECURITY_CHECK_FAILURE', 'Drivers')
    '0x13A'      = @('KERNEL_MODE_HEAP_CORRUPTION', 'Drivers')
    '0x141'      = @('VIDEO_ENGINE_TIMEOUT_DETECTED', 'GPU')
    '0x154'      = @('UNEXPECTED_STORE_EXCEPTION', 'Armazenamento')
    '0xC000021A' = @('STATUS_SYSTEM_PROCESS_TERMINATED', 'Software/Sistema')
    '0xC0000221' = @('STATUS_IMAGE_CHECKSUM_MISMATCH', 'Armazenamento')
}

# Eventos de storage: 'provider|id' -> descricao
$StorageEventMap = @{
    'disk|7'         = 'bloco invalido (bad block)'
    'disk|11'        = 'erro do controlador'
    'disk|15'        = 'dispositivo nao pronto'
    'disk|51'        = 'erro de paginacao no disco'
    'disk|52'        = 'falha prevista pelo disco (SMART)'
    'disk|153'       = 'operacao de I/O repetida (retry)'
    'disk|157'       = 'disco removido inesperadamente'
    'storahci|129'   = 'reset ao dispositivo (timeout)'
    'stornvme|129'   = 'reset ao dispositivo (timeout)'
    'iaStorA|129'    = 'reset ao dispositivo (timeout)'
    'iaStorAVC|129'  = 'reset ao dispositivo (timeout)'
    'Ntfs|50'        = 'delayed write falhou'
    'Ntfs|55'        = 'estrutura NTFS corrompida'
    'Ntfs|98'        = 'volume requer verificacao'
    'Ntfs|140'       = 'write-through falhou'
    'volmgr|46'      = 'falha ao preparar crash dump'
    'volmgr|161'     = 'falha ao criar crash dump'
}
$CriticalStorageIds = @('disk|7', 'disk|11', 'disk|51', 'disk|52', 'storahci|129', 'stornvme|129', 'iaStorA|129', 'iaStorAVC|129', 'Ntfs|55')

# Fim de suporte (data ISO). Tabela interna: validar nas paginas de ciclo de vida da Microsoft.
$OsSupportTable = @(
    @{ Min = 10240; Max = 19045; Label = 'Windows 10';        Consumer = '2025-10-14'; Enterprise = '2025-10-14' },
    @{ Min = 22000; Max = 22000; Label = 'Windows 11 21H2';   Consumer = '2023-10-10'; Enterprise = '2024-10-08' },
    @{ Min = 22621; Max = 22621; Label = 'Windows 11 22H2';   Consumer = '2024-10-08'; Enterprise = '2025-10-14' },
    @{ Min = 22631; Max = 22631; Label = 'Windows 11 23H2';   Consumer = '2025-11-11'; Enterprise = '2026-11-10' },
    @{ Min = 26100; Max = 26100; Label = 'Windows 11 24H2';   Consumer = '2026-10-13'; Enterprise = '2027-10-12' },
    @{ Min = 26200; Max = 26200; Label = 'Windows 11 25H2';   Consumer = '2027-10-12'; Enterprise = '2028-10-10' }
)

# Perfis de queixa -> categorias priorizadas
$IssueProfileMap = [ordered]@{
    Performance = 'lent|travar|trava|demor|slow|devagar|pesado|congel'
    Stability   = 'azul|bsod|reinicia|reinicio|desliga|crash|bloque|falha'
    Network     = 'internet|rede|wifi|wi-fi|ligacao|dns|router|ping|sem net'
    Boot        = 'arranque|boot|iniciar|liga devagar|demora a ligar'
    Battery     = 'bateria|carreg|autonomia'
    Display     = 'ecra|video|imagem|grafic|artefact|gpu|monitor|pisca'
    Security    = 'virus|malware|pop-up|popup|publicidade|seguranca|trojan|ransom|infet'
    Storage     = 'disco|ficheiro|espaco|armazen|ssd|hdd|cheio'
}
$IssueFocusMap = @{
    Performance = @('Hardware', 'Memory', 'Storage')
    Stability   = @('Hardware', 'Windows', 'Storage', 'Memory')
    Network     = @('Network')
    Boot        = @('Windows', 'Storage')
    Battery     = @('Hardware')
    Display     = @('Hardware')
    Security    = @('Windows')
    Storage     = @('Storage')
}

# ==========================================================================
# FUNCOES
# ==========================================================================

function Add-Finding {
    param(
        [string]$Category,
        [ValidateSet("Critical", "Warning", "Info")][string]$Severity,
        [double]$Confidence,
        [string]$Finding,
        [string]$Evidence,
        [string]$Action,
        [int]$ImpactWeight = 1
    )
    $relevant = ($script:FocusCategories -contains $Category)
    $script:Report.Findings += [PSCustomObject]@{
        Category          = $Category
        Severity          = $Severity
        Confidence        = $Confidence
        Finding           = $Finding
        Evidence          = $Evidence
        RecommendedAction = $Action
        RelevantToIssue   = $relevant
    }
    if ($Action -and ($script:Report.RecommendedActions -notcontains $Action)) {
        $script:Report.RecommendedActions += $Action
    }
    $BasePenalty = switch ($Severity) { "Critical" { 20 } "Warning" { 10 } default { 0 } }
    $Mult = if ($relevant) { 1.25 } else { 1.0 }
    $CalculatedPenalty = [math]::Round($BasePenalty * $Confidence * ($ImpactWeight / 2.0) * $Mult, 0)
    if ($script:Report.HealthScore.Contains($Category)) {
        $script:Report.HealthScore[$Category] = [math]::Max(0, $script:Report.HealthScore[$Category] - $CalculatedPenalty)
    }
    $OverallPenalty = [math]::Round($CalculatedPenalty * 0.6, 0)
    $script:Report.HealthScore.Overall = [math]::Max(0, $script:Report.HealthScore.Overall - $OverallPenalty)
}

function Add-Suspect {
    param([string]$Name, [double]$Points, [string]$Reason)
    if (-not $script:Suspects.Contains($Name)) {
        $script:Suspects[$Name] = [ordered]@{ Name = $Name; Points = 0.0; Reasons = @() }
    }
    $script:Suspects[$Name].Points += $Points
    $script:Suspects[$Name].Reasons += $Reason
}

function Show-Step {
    param([string]$Text)
    $script:StepNo++
    Write-Host " [$($script:StepNo)/$StepTotal] $Text" -ForegroundColor Gray
}

# Executa um coletor no processo atual, com registo de cobertura. Devolve o que o bloco emitir.
function Invoke-Step {
    param([string]$Name, [scriptblock]$Block, [switch]$RequiresAdmin, [switch]$Internal)
    $entry = [ordered]@{ Name = $Name; Status = 'Ok'; Seconds = 0; Error = $null }
    if ($RequiresAdmin -and -not $script:IsAdmin) {
        $entry.Status = 'Skipped'; $entry.Error = 'requer admin'
        $script:Coverage.Add([pscustomobject]$entry)
        return $null
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try { & $Block }
    catch {
        $entry.Status = 'Failed'; $entry.Error = $_.Exception.Message
        $script:DiagErrors.Add("Step[$Name]: $($_.Exception.Message)")
    }
    $sw.Stop()
    $entry.Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    if (-not $Internal -or $entry.Status -ne 'Ok') { $script:Coverage.Add([pscustomobject]$entry) }
}

# Executa um coletor num runspace com timeout (o bloco tem de ser autonomo; usa -ArgumentList).
function Invoke-TimedStep {
    param([string]$Name, [scriptblock]$Block, [object[]]$ArgumentList = @(), [int]$TimeoutSec = 60, [switch]$RequiresAdmin)
    $entry = [ordered]@{ Name = $Name; Status = 'Ok'; Seconds = 0; Error = $null }
    if ($RequiresAdmin -and -not $script:IsAdmin) {
        $entry.Status = 'Skipped'; $entry.Error = 'requer admin'
        $script:Coverage.Add([pscustomobject]$entry)
        return $null
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $ps = [powershell]::Create()
    $result = $null
    try {
        [void]$ps.AddScript($Block.ToString())
        foreach ($a in $ArgumentList) { [void]$ps.AddArgument($a) }
        $handle = $ps.BeginInvoke()
        if ($handle.AsyncWaitHandle.WaitOne($TimeoutSec * 1000)) {
            $result = $ps.EndInvoke($handle)
            if ($ps.HadErrors -and @($result).Count -eq 0 -and $ps.Streams.Error.Count -gt 0) {
                $entry.Status = 'Failed'; $entry.Error = "$($ps.Streams.Error[0])"
            }
            $ps.Dispose()
        } else {
            $entry.Status = 'Timeout'; $entry.Error = "excedeu $TimeoutSec s"
            [void]$ps.BeginStop($null, $null)
        }
    } catch {
        $entry.Status = 'Failed'; $entry.Error = $_.Exception.Message
        $script:DiagErrors.Add("TimedStep[$Name]: $($_.Exception.Message)")
    }
    $sw.Stop()
    $entry.Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    $script:Coverage.Add([pscustomobject]$entry)
    if ($entry.Status -in 'Timeout', 'Failed') { $script:DiagErrors.Add("TimedStep[$Name]: $($entry.Status) $($entry.Error)") }
    return $result
}

# Leitura segura do Event Log
function Get-EventsSafe {
    param([hashtable]$Filter, [string]$Label)
    try {
        Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            $script:DiagErrors.Add("EventLog[$Label]: $($_.Exception.Message)")
        }
        @()
    }
}

function Get-EventDataMap {
    param($EventRecord)
    $h = @{}
    try {
        $x = [xml]$EventRecord.ToXml()
        foreach ($d in @($x.Event.EventData.Data)) {
            if ($d.Name) { $h[[string]$d.Name] = "$($d.'#text')" }
        }
    } catch { }
    return $h
}

function Group-EventSummary {
    param($Events, [hashtable]$Map = @{})
    $list = @($Events)
    if ($list.Count -eq 0) { return @() }
    $out = foreach ($g in ($list | Group-Object { "$($_.ProviderName)|$($_.Id)" })) {
        $last = ($g.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
        [pscustomobject]@{
            Key         = $g.Name
            Count       = $g.Count
            Description = if ($Map.ContainsKey($g.Name)) { $Map[$g.Name] } else { "" }
            LastSeen    = if ($last) { $last.ToString("yyyy-MM-dd HH:mm") } else { $null }
        }
    }
    return @($out)
}

function Format-EventSummary {
    param($Items, [int]$Max = 5)
    $parts = @($Items) | Select-Object -First $Max | ForEach-Object {
        if ($_.Description) { "$($_.Key) x$($_.Count) ($($_.Description))" } else { "$($_.Key) x$($_.Count)" }
    }
    return ($parts -join "; ")
}

function Get-TextField {
    param($Lines, [string]$Pattern)
    foreach ($l in @($Lines)) {
        if ("$l" -match $Pattern) { return $Matches[1].Trim() }
    }
    return $null
}

function Get-Avg {
    param($Values)
    $v = @($Values | Where-Object { $null -ne $_ })
    if ($v.Count -eq 0) { return $null }
    return [math]::Round((($v | Measure-Object -Average).Average), 1)
}

function Get-Max {
    param($Values)
    $v = @($Values | Where-Object { $null -ne $_ })
    if ($v.Count -eq 0) { return $null }
    return [math]::Round((($v | Measure-Object -Maximum).Maximum), 1)
}

function Get-IssueProfiles {
    param([string]$Text, $ProfileMap)
    $t = "$Text".ToLowerInvariant()
    try { $t = [regex]::Replace($t.Normalize([System.Text.NormalizationForm]::FormD), '\p{M}', '') } catch { }
    $found = @()
    foreach ($k in $ProfileMap.Keys) {
        if ($t -match $ProfileMap[$k]) { $found += $k }
    }
    return $found
}

function Get-BugCheckInfo {
    param([int64]$Code, $Table)
    $key = '0x{0:X}' -f $Code
    if ($Table.ContainsKey($key)) {
        return [pscustomobject]@{ Code = $key; Name = $Table[$key][0]; Category = $Table[$key][1] }
    }
    return [pscustomobject]@{ Code = $key; Name = 'DESCONHECIDO'; Category = 'Outros' }
}

# Le o BugCheckCode do cabecalho de um minidump (PAGEDU64 -> offset 56; PAGEDUMP 32-bit -> offset 40)
function Read-MinidumpBugCheck {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        try {
            $buf = New-Object byte[] 128
            $n = $fs.Read($buf, 0, 128)
        } finally { $fs.Close() }
        if ($n -lt 64) { return $null }
        if ([System.Text.Encoding]::ASCII.GetString($buf, 0, 4) -ne 'PAGE') { return $null }
        $kind = [System.Text.Encoding]::ASCII.GetString($buf, 4, 4)
        if ($kind -eq 'DU64') { return [pscustomobject]@{ Code = [int64][BitConverter]::ToUInt32($buf, 56); Bits = 64 } }
        if ($kind -eq 'DUMP') { return [pscustomobject]@{ Code = [int64][BitConverter]::ToUInt32($buf, 40); Bits = 32 } }
        return $null
    } catch { return $null }
}

function Get-LatencyStats {
    param($Rtts, [int]$Lost, [int]$Sent)
    $r = @($Rtts | ForEach-Object { [double]$_ })
    $recv = $r.Count
    $jit = $null
    if ($recv -ge 2) {
        $s = 0.0
        for ($i = 1; $i -lt $recv; $i++) { $s += [math]::Abs($r[$i] - $r[$i - 1]) }
        $jit = [math]::Round($s / ($recv - 1), 1)
    }
    return [ordered]@{
        Sent      = $Sent
        Received  = $recv
        LossPct   = if ($Sent -gt 0) { [math]::Round(100.0 * ($Sent - $recv) / $Sent, 1) } else { $null }
        MinMs     = if ($recv -gt 0) { ($r | Measure-Object -Minimum).Minimum } else { $null }
        AvgMs     = if ($recv -gt 0) { [math]::Round(($r | Measure-Object -Average).Average, 1) } else { $null }
        MaxMs     = if ($recv -gt 0) { ($r | Measure-Object -Maximum).Maximum } else { $null }
        JitterMs  = $jit
    }
}

function Test-PingTarget {
    param([string]$Target, [int]$Count = 20, [int]$TimeoutMs = 1000)
    $ping = New-Object System.Net.NetworkInformation.Ping
    $rtts = New-Object System.Collections.Generic.List[double]
    for ($i = 0; $i -lt $Count; $i++) {
        try {
            $r = $ping.Send($Target, $TimeoutMs)
            if ($r.Status -eq 'Success') { $rtts.Add([double]$r.RoundtripTime) }
        } catch { }
        Start-Sleep -Milliseconds 100
    }
    $ping.Dispose()
    return (Get-LatencyStats -Rtts $rtts -Lost ($Count - $rtts.Count) -Sent $Count)
}

function Get-AvState {
    param([uint32]$ProductState)
    $hex = '{0:X6}' -f $ProductState
    $prod = $hex.Substring(2, 2)
    $sig = $hex.Substring(4, 2)
    return [pscustomobject]@{
        Enabled  = ($prod -eq '10' -or $prod -eq '11')
        Snoozed  = ($prod -eq '01')
        UpToDate = ($sig -eq '00')
    }
}

function Get-OsSupportInfo {
    param([int]$Build, [string]$Caption, $Table, [datetime]$Now)
    if ($Caption -match 'Server|LTSC|LTSB|IoT') { return $null }
    $row = $Table | Where-Object { $Build -ge $_.Min -and $Build -le $_.Max } | Select-Object -First 1
    if (-not $row) { return $null }
    $isEnt = ($Caption -match 'Enterprise|Education')
    $eol = [datetime]::ParseExact($(if ($isEnt) { $row.Enterprise } else { $row.Consumer }), 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    $days = [int][math]::Floor(($eol - $Now).TotalDays)
    return [pscustomobject]@{
        Label = $row.Label; Edition = $(if ($isEnt) { 'Enterprise/Education' } else { 'Home/Pro' })
        EndOfSupport = $eol.ToString('yyyy-MM-dd'); DaysToEnd = $days; OutOfSupport = ($days -lt 0)
    }
}

# Amostragem: CPU (media), processos (delta), DPC/Interrupt, memoria (Pages Input/s) e disco (latencia RAW + fila)
function Get-PerfWindow {
    param([int]$Seconds = 4, [int]$Cores = 1, [string]$Label = "W1")
    $selfPid = $PID
    $t0 = @{}
    foreach ($p in (Get-Process)) {
        if ($null -ne $p.CPU) { $t0["$($p.Id)|$($p.ProcessName)"] = [double]$p.CPU }
    }
    $raw0 = @(Get-CimInstance -ClassName Win32_PerfRawData_PerfDisk_PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne '_Total' })
    $ts0 = [System.Diagnostics.Stopwatch]::GetTimestamp()

    $cpu  = New-Object System.Collections.Generic.List[double]
    $perf = New-Object System.Collections.Generic.List[double]
    $dpc  = New-Object System.Collections.Generic.List[double]
    $intr = New-Object System.Collections.Generic.List[double]
    $pgIn = New-Object System.Collections.Generic.List[double]
    $dq = @{}
    $dtm = @{}
    for ($i = 0; $i -lt $Seconds; $i++) {
        Start-Sleep -Seconds 1
        if ($i -gt 0) {
            $m = Get-CimInstance -ClassName Win32_PerfFormattedData_Counters_ProcessorInformation -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq '_Total' } | Select-Object -First 1
            if ($m) {
                if ($null -ne $m.PercentProcessorUtility)     { $cpu.Add([double]$m.PercentProcessorUtility) }
                if ($null -ne $m.PercentProcessorPerformance) { $perf.Add([double]$m.PercentProcessorPerformance) }
                if ($null -ne $m.PercentDPCTime)              { $dpc.Add([double]$m.PercentDPCTime) }
                if ($null -ne $m.PercentInterruptTime)        { $intr.Add([double]$m.PercentInterruptTime) }
            }
            $pm = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Memory -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($pm -and $null -ne $pm.PagesInputPersec) { $pgIn.Add([double]$pm.PagesInputPersec) }
            foreach ($dd in @(Get-CimInstance -ClassName Win32_PerfFormattedData_PerfDisk_PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne '_Total' })) {
                if (-not $dq.ContainsKey($dd.Name)) {
                    $dq[$dd.Name] = New-Object System.Collections.Generic.List[double]
                    $dtm[$dd.Name] = New-Object System.Collections.Generic.List[double]
                }
                $dq[$dd.Name].Add([double]$dd.CurrentDiskQueueLength)
                $dtm[$dd.Name].Add([double]$dd.PercentDiskTime)
            }
        }
    }

    $raw1 = @(Get-CimInstance -ClassName Win32_PerfRawData_PerfDisk_PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne '_Total' })
    $ts1 = [System.Diagnostics.Stopwatch]::GetTimestamp()
    $dt = ($ts1 - $ts0) / [System.Diagnostics.Stopwatch]::Frequency

    $disks = @()
    foreach ($r1 in $raw1) {
        $r0 = $raw0 | Where-Object { $_.Name -eq $r1.Name } | Select-Object -First 1
        if (-not $r0) { continue }
        $f = [double]$r1.Frequency_PerfTime
        if ($f -le 0) { $f = 10000000.0 }
        $rdOps = [double]$r1.AvgDisksecPerRead_Base - [double]$r0.AvgDisksecPerRead_Base
        $wrOps = [double]$r1.AvgDisksecPerWrite_Base - [double]$r0.AvgDisksecPerWrite_Base
        $rdMs = $null; $wrMs = $null
        if ($rdOps -gt 0) { $rdMs = ((([double]$r1.AvgDisksecPerRead - [double]$r0.AvgDisksecPerRead) / $f) / $rdOps) * 1000 }
        if ($wrOps -gt 0) { $wrMs = ((([double]$r1.AvgDisksecPerWrite - [double]$r0.AvgDisksecPerWrite) / $f) / $wrOps) * 1000 }
        if ($null -ne $rdMs -and ($rdMs -lt 0 -or $rdMs -gt 60000)) { $rdMs = $null }
        if ($null -ne $wrMs -and ($wrMs -lt 0 -or $wrMs -gt 60000)) { $wrMs = $null }
        $disks += [pscustomobject]@{
            Name      = $r1.Name
            DiskIndex = [regex]::Match("$($r1.Name)", '^\d+').Value
            ReadMs    = if ($null -ne $rdMs) { [math]::Round($rdMs, 1) } else { $null }
            WriteMs   = if ($null -ne $wrMs) { [math]::Round($wrMs, 1) } else { $null }
            ReadOps   = [int]$rdOps
            WriteOps  = [int]$wrOps
            QueueAvg  = if ($dq.ContainsKey($r1.Name)) { Get-Avg $dq[$r1.Name] } else { $null }
            BusyPct   = if ($dtm.ContainsKey($r1.Name)) { Get-Avg $dtm[$r1.Name] } else { $null }
        }
    }

    $procSum = 0.0
    $hogs = @()
    foreach ($p1 in (Get-Process)) {
        if ($null -eq $p1.CPU -or $p1.Id -eq $selfPid) { continue }
        $key = "$($p1.Id)|$($p1.ProcessName)"
        if ($t0.ContainsKey($key)) {
            $delta = [double]$p1.CPU - $t0[$key]
            if ($delta -gt 0 -and $dt -gt 0) {
                $usage = ($delta / ($dt * $Cores)) * 100
                $procSum += $usage
                if ($usage -ge 1.0) { $hogs += [pscustomobject]@{ Id = $p1.Id; ProcessName = $p1.ProcessName; InstantCPU = $usage } }
            }
        }
    }
    $top = @($hogs | Sort-Object InstantCPU -Descending | Select-Object -First 5 | ForEach-Object {
        $pp = Get-Process -Id $_.Id -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Id          = $_.Id
            ProcessName = $_.ProcessName
            InstantCPU  = [math]::Round($_.InstantCPU, 1)
            Company     = if ($pp -and $pp.Company) { "$($pp.Company)".Trim() } else { "N/A" }
            Description = if ($pp -and $pp.Description) { "$($pp.Description)".Trim() } else { "N/A" }
            Path        = if ($pp -and $pp.Path) { $pp.Path } else { "N/A" }
        }
    })

    return [pscustomobject]@{
        Label            = $Label
        Seconds          = [math]::Round($dt, 1)
        CpuAvg           = Get-Avg $cpu
        PerfPctAvg       = Get-Avg $perf
        DpcAvg           = Get-Avg $dpc
        InterruptAvg     = Get-Avg $intr
        ProcSumPct       = [math]::Round($procSum, 1)
        PagesInputAvg    = Get-Avg $pgIn
        Disks            = $disks
        TopHogs          = $top
    }
}

# --- Historico ---------------------------------------------------------
function New-TrendRow {
    param([string]$Key, [string]$Metric, $Prev, $Cur, [string]$Unit, [string]$Direction)
    if ($null -eq $Prev -or $null -eq $Cur) { return $null }
    try { $p = [double]$Prev; $c = [double]$Cur } catch { return $null }
    $d = [math]::Round($c - $p, 2)
    $worse = switch ($Direction) { 'HigherWorse' { $d -gt 0 } 'LowerWorse' { $d -lt 0 } default { $false } }
    return [pscustomobject]@{ Key = $Key; Metric = $Metric; Previous = $p; Current = $c; Delta = $d; Unit = $Unit; Worse = [bool]$worse }
}

function Get-TrendRows {
    param($Prev, $Cur)
    $rows = New-Object System.Collections.Generic.List[object]
    $push = { param($r) if ($r) { $rows.Add($r) } }

    foreach ($v in @($Cur.Facts.Volumes)) {
        $pv = @($Prev.Facts.Volumes) | Where-Object { $_.DriveLetter -eq $v.DriveLetter } | Select-Object -First 1
        if ($pv) { & $push (New-TrendRow "VolFree:$($v.DriveLetter)" "Volume $($v.DriveLetter): espaco livre" $pv.FreeGB $v.FreeGB 'GB' 'LowerWorse') }
    }
    foreach ($d in @($Cur.Facts.PhysicalDisks)) {
        $pd = @($Prev.Facts.PhysicalDisks) | Where-Object { $_.FriendlyName -eq $d.FriendlyName } | Select-Object -First 1
        if (-not $pd) { continue }
        & $push (New-TrendRow "DiskWear:$($d.FriendlyName)" "Desgaste $($d.FriendlyName)" $pd.WearPercentage $d.WearPercentage '%' 'HigherWorse')
        $pe = [double]$pd.ReadErrorsUncorrected + [double]$pd.WriteErrorsUncorrected
        $ce = [double]$d.ReadErrorsUncorrected + [double]$d.WriteErrorsUncorrected
        & $push (New-TrendRow "DiskErr:$($d.FriendlyName)" "Erros nao corrigidos $($d.FriendlyName)" $pe $ce 'erros' 'HigherWorse')
    }
    & $push (New-TrendRow 'Stability' 'Indice de fiabilidade' $Prev.Facts.CrashDumps.SystemStabilityIndex $Cur.Facts.CrashDumps.SystemStabilityIndex '' 'LowerWorse')
    & $push (New-TrendRow 'Minidumps' 'Numero de minidumps' $Prev.Facts.CrashDumps.MinidumpCount $Cur.Facts.CrashDumps.MinidumpCount '' 'HigherWorse')
    & $push (New-TrendRow 'BatteryWear' 'Desgaste da bateria' $Prev.Facts.Battery.WearPct $Cur.Facts.Battery.WearPct '%' 'HigherWorse')
    & $push (New-TrendRow 'BootSec' 'Tempo medio de arranque' $Prev.Facts.Boot.AvgBootSeconds $Cur.Facts.Boot.AvgBootSeconds 's' 'HigherWorse')
    & $push (New-TrendRow 'Score' 'HealthScore global' $Prev.HealthScore.Overall $Cur.HealthScore.Overall '' 'LowerWorse')
    return @($rows)
}

# ==========================================================================
# 0. ENTRADA, PERFIS DA QUEIXA E PASTA DE SAIDA
# ==========================================================================
if ([string]::IsNullOrWhiteSpace($Issue)) {
    try {
        Clear-Host
        Write-Host "==========================================================" -ForegroundColor Cyan
        Write-Host "     ECG DIAGNOSTIC v$ScriptVersion - TRIAGEM CLINICA UNIVERSAL     " -ForegroundColor Cyan
        Write-Host "==========================================================" -ForegroundColor Cyan
        $Issue = Read-Host "`nQueixa do cliente / Sintoma reportado"
    } catch { $Issue = "" }
    if ([string]::IsNullOrWhiteSpace($Issue)) { $Issue = "Revisao preventiva geral" }
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
    SchemaVersion           = "2.3"
    DiagnosticEngine        = "ECG-Universal"
    DiagnosticEngineVersion = "2.3.0"
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
Show-Step "A recolher contexto, hardware base, bateria e GPU..."
$OS = Get-CimInstance Win32_OperatingSystem
$CS = Get-CimInstance Win32_ComputerSystem
$CpuCim = Get-CimInstance Win32_Processor | Select-Object -First 1
$BIOS = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
$LogicalCores = [Environment]::ProcessorCount
$ChassisTypes = @(Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue | ForEach-Object { $_.ChassisTypes } | ForEach-Object { [int]$_ })
$IsVM = ("$($CS.Manufacturer) $($CS.Model)" -match 'Virtual|VMware|VirtualBox|KVM|QEMU|Xen|Hyper-V|Parallels|Bochs')
$IsLaptop = [bool](@($ChassisTypes | Where-Object { @(8, 9, 10, 11, 14, 30, 31, 32) -contains $_ }).Count)
$Battery = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
$FastStartup = $null
try { $FastStartup = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -ErrorAction Stop).HiberbootEnabled -eq 1) } catch { }

$Report.Facts.Context = [ordered]@{
    IsVirtualMachine   = $IsVM
    IsLaptop           = $IsLaptop
    ChassisTypes       = $ChassisTypes
    BatteryPresent     = [bool]$Battery
    FastStartupEnabled = $FastStartup
    IssueProfiles      = $IssueProfiles
}

Invoke-Step "HardwareBase" {
    $KernelBaseClock = try {
        (Get-ItemProperty -Path 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0' -ErrorAction Stop).'~MHz'
    } catch { [int]$CpuCim.MaxClockSpeed }

    $ThermalZoneC = $null
    if (-not $IsVM) {
        try {
            $Thermal = Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop | Select-Object -First 1
            if ($Thermal -and $Thermal.CurrentTemperature -gt 2732) {
                $ThermalZoneC = [math]::Round(($Thermal.CurrentTemperature - 2732) / 10, 1)
            }
        } catch { }
    }

    $RebootReasons = @()
    $script:RebootStrong = $false
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        $script:RebootStrong = $true; $RebootReasons += "CBS_RebootPending"
    }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
        $script:RebootStrong = $true; $RebootReasons += "WindowsUpdate_RebootRequired"
    }
    $FileRename = try { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ErrorAction SilentlyContinue).PendingFileRenameOperations } catch { $null }
    if ($FileRename) { $RebootReasons += "PendingFileRenameOperations" }

    $Report.Facts.System = [ordered]@{
        ComputerName       = $env:COMPUTERNAME
        Manufacturer       = "$($CS.Manufacturer)".Trim()
        Model              = "$($CS.Model)".Trim()
        OSCaption          = "$($OS.Caption)".Trim()
        OSBuild            = $OS.BuildNumber
        UptimeDays         = [math]::Round(((Get-Date) - $OS.LastBootUpTime).TotalDays, 2)
        RebootPending      = ($RebootReasons.Count -gt 0)
        RebootReasons      = ($RebootReasons -join ", ")
        CPUModel           = "$($CpuCim.Name)".Trim()
        LogicalCores       = $LogicalCores
        BaseClockMHz       = $KernelBaseClock
        ThermalZone_ACPI_C = $ThermalZoneC
        BIOSVersion        = if ($BIOS) { $BIOS.SMBIOSBIOSVersion } else { "N/A" }
        BIOSDate           = if ($BIOS -and $BIOS.ReleaseDate) { $BIOS.ReleaseDate.ToString('yyyy-MM-dd') } else { $null }
    }
}

Invoke-Step "Battery" {
    if (-not $Battery) { $Report.Facts.Battery = [ordered]@{ Present = $false }; return }
    $b = [ordered]@{
        Present = $true; ChargePercent = $Battery.EstimatedChargeRemaining; Status = $Battery.BatteryStatus
        DesignCapacityMWh = $null; FullChargeCapacityMWh = $null; WearPct = $null; CycleCount = $null
    }
    try {
        $full = Get-CimInstance -Namespace root/wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop | Select-Object -First 1
        $stat = Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData -ErrorAction Stop | Select-Object -First 1
        $b.FullChargeCapacityMWh = [int]$full.FullChargedCapacity
        $b.DesignCapacityMWh = [int]$stat.DesignedCapacity
        if ($b.DesignCapacityMWh -gt 0) {
            $b.WearPct = [math]::Max(0, [math]::Round((1 - ($b.FullChargeCapacityMWh / $b.DesignCapacityMWh)) * 100, 1))
        }
    } catch { }
    try {
        $cyc = Get-CimInstance -Namespace root/wmi -ClassName BatteryCycleCount -ErrorAction Stop | Select-Object -First 1
        $b.CycleCount = [int]$cyc.CycleCount
    } catch { }
    $Report.Facts.Battery = $b
}

Invoke-Step "GPU" {
    $Report.Facts.Gpu = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{
            Name            = "$($_.Name)"
            DriverVersion   = "$($_.DriverVersion)"
            DriverDate      = if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { $null }
            DriverAgeDays   = if ($_.DriverDate) { [int]((Get-Date) - $_.DriverDate).TotalDays } else { $null }
            Status          = "$($_.Status)"
            ConfigErrorCode = $_.ConfigManagerErrorCode
        }
    })
}

# ==========================================================================
# 2. AMOSTRAGEM (CPU, DPC/Interrupt, disco, memoria)
# ==========================================================================
Show-Step "A amostrar CPU, disco e memoria (janela de $SampleSeconds s$(if ($ExtendedMode) { ', modo Extended: 3 janelas' }))..."
$PerfWindows = New-Object System.Collections.Generic.List[object]
Invoke-Step "PerfWindow1" { $PerfWindows.Add((Get-PerfWindow -Seconds $SampleSeconds -Cores $LogicalCores -Label 'W1')) }

# ==========================================================================
# 3. MEMORIA
# ==========================================================================
Show-Step "A recolher memoria (disponibilidade, commit, modulos, pagefile, processos)..."
Invoke-Step "Memory" {
    $PerfMem = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory -ErrorAction SilentlyContinue | Select-Object -First 1
    $TotalRamMB = [int][math]::Round($OS.TotalVisibleMemorySize / 1024, 0)
    $FreeOnlyMB = [int][math]::Round($OS.FreePhysicalMemory / 1024, 0)
    if ($PerfMem -and $null -ne $PerfMem.AvailableMBytes) {
        $AvailRamMB = [int]$PerfMem.AvailableMBytes; $AvailSource = "PerfOS_Memory.AvailableMBytes"
    } else {
        $AvailRamMB = $FreeOnlyMB; $AvailSource = "Win32_OperatingSystem.FreePhysicalMemory (subestima a memoria disponivel)"
    }
    $CommitTotalMB = if ($PerfMem) { [int][math]::Round($PerfMem.CommittedBytes / 1MB, 0) } else { 0 }
    $CommitLimitMB = if ($PerfMem) { [int][math]::Round($PerfMem.CommitLimit / 1MB, 0) } else { 0 }
    $pf = @(Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue)
    $pfAlloc = ($pf | Measure-Object -Property AllocatedBaseSize -Sum).Sum
    $pfPeak  = ($pf | Measure-Object -Property PeakUsage -Sum).Sum
    $pfCur   = ($pf | Measure-Object -Property CurrentUsage -Sum).Sum

    $Report.Facts.Memory = [ordered]@{
        TotalRAM_MB       = $TotalRamMB
        AvailableRAM_MB   = $AvailRamMB
        AvailableRAM_Pct  = if ($TotalRamMB -gt 0) { [math]::Round(($AvailRamMB / $TotalRamMB) * 100, 1) } else { 0 }
        AvailableSource   = $AvailSource
        UsedRAM_Pct       = if ($TotalRamMB -gt 0) { [math]::Round((($TotalRamMB - $AvailRamMB) / $TotalRamMB) * 100, 1) } else { 0 }
        Committed_MB      = $CommitTotalMB
        CommitLimit_MB    = $CommitLimitMB
        CommitUtilization = if ($CommitLimitMB -gt 0) { [math]::Round(($CommitTotalMB / $CommitLimitMB) * 100, 1) } else { 0 }
        PoolPaged_MB      = if ($PerfMem) { [int][math]::Round($PerfMem.PoolPagedBytes / 1MB, 0) } else { 0 }
        PoolNonPaged_MB   = if ($PerfMem) { [int][math]::Round($PerfMem.PoolNonpagedBytes / 1MB, 0) } else { 0 }
        PageFileActive    = ($pf.Count -gt 0)
        PageFileAllocated_MB = $pfAlloc
        PageFileCurrent_MB   = $pfCur
        PageFilePeak_MB      = $pfPeak
        PageFilePeakPct      = if ($pfAlloc -gt 0) { [math]::Round(100.0 * $pfPeak / $pfAlloc, 1) } else { $null }
    }

    $procs = @(Get-Process -ErrorAction SilentlyContinue)
    $Report.Facts.TopProcesses = [ordered]@{
        ByPrivateMemory = @($procs | Sort-Object PrivateMemorySize64 -Descending | Select-Object -First 5 | ForEach-Object {
            [ordered]@{ Id = $_.Id; Name = $_.ProcessName; PrivateMB = [math]::Round($_.PrivateMemorySize64 / 1MB, 0); Handles = $_.HandleCount } })
        ByHandles = @($procs | Sort-Object HandleCount -Descending | Select-Object -First 5 | ForEach-Object {
            [ordered]@{ Id = $_.Id; Name = $_.ProcessName; Handles = $_.HandleCount; PrivateMB = [math]::Round($_.PrivateMemorySize64 / 1MB, 0) } })
    }
}

Invoke-Step "PhysicalMemory" {
    $dimms = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue)
    $slots = (Get-CimInstance Win32_PhysicalMemoryArray -ErrorAction SilentlyContinue | Measure-Object -Property MemoryDevices -Sum).Sum
    $mods = @($dimms | ForEach-Object {
        [ordered]@{
            Locator = "$($_.DeviceLocator)"; Bank = "$($_.BankLabel)"
            CapacityGB = [math]::Round($_.Capacity / 1GB, 1)
            SpeedMHz = $_.Speed; ConfiguredMHz = $_.ConfiguredClockSpeed
            Manufacturer = "$($_.Manufacturer)".Trim(); PartNumber = "$($_.PartNumber)".Trim()
        } })
    $caps = @($mods | ForEach-Object { $_.CapacityGB } | Select-Object -Unique)
    $spds = @($mods | ForEach-Object { $_.SpeedMHz } | Where-Object { $_ } | Select-Object -Unique)
    $xmpOff = @($mods | Where-Object { $_.SpeedMHz -and $_.ConfiguredMHz -and ($_.ConfiguredMHz -lt (0.9 * $_.SpeedMHz)) }).Count -gt 0
    $Report.Facts.PhysicalMemory = [ordered]@{
        ModuleCount = $mods.Count; SlotCount = $slots
        MismatchedCapacity = ($caps.Count -gt 1); MismatchedSpeed = ($spds.Count -gt 1)
        SingleChannelPossible = ($mods.Count -eq 1 -and $slots -ge 2)
        XmpPossiblyOff = $xmpOff
        Modules = $mods
    }
}

# ==========================================================================
# 4. ARMAZENAMENTO
# ==========================================================================
Show-Step "A mapear discos, SMART, volumes, dirty bit e TRIM..."
Invoke-Step "PhysicalDisks" {
    $DiskList = @()
    foreach ($d in @(Get-PhysicalDisk -ErrorAction SilentlyContinue)) {
        $rel = if ($IsAdmin) { Get-StorageReliabilityCounter -PhysicalDisk $d -ErrorAction SilentlyContinue } else { $null }
        $DiskList += [ordered]@{
            DeviceId               = "$($d.DeviceId)"
            FriendlyName           = "$($d.FriendlyName)".Trim()
            MediaType              = "$($d.MediaType)"
            BusType                = "$($d.BusType)"
            HealthStatus           = "$($d.HealthStatus)"
            OperationalStatus      = ($d.OperationalStatus -join ", ")
            SizeGB                 = [math]::Round($d.Size / 1GB, 1)
            TemperatureC           = if ($rel) { $rel.Temperature } else { $null }
            MaxTemperatureC        = if ($rel) { $rel.MaxTemperature } else { $null }
            WearPercentage         = if ($rel) { $rel.Wear } else { $null }
            PowerOnHours           = if ($rel) { $rel.PowerOnHours } else { $null }
            StartStopCycleCount    = if ($rel) { $rel.StartStopCycleCount } else { $null }
            StartStopCycleCountMax = if ($rel) { $rel.StartStopCycleCountMax } else { $null }
            LoadUnloadCycleCount   = if ($rel) { $rel.LoadUnloadCycleCount } else { $null }
            LoadUnloadCycleCountMax = if ($rel) { $rel.LoadUnloadCycleCountMax } else { $null }
            ReadErrorsTotal        = if ($rel) { $rel.ReadErrorsTotal } else { $null }
            WriteErrorsTotal       = if ($rel) { $rel.WriteErrorsTotal } else { $null }
            ReadErrorsUncorrected  = if ($rel) { $rel.ReadErrorsUncorrected } else { $null }
            WriteErrorsUncorrected = if ($rel) { $rel.WriteErrorsUncorrected } else { $null }
            ReadLatencyMaxMs       = if ($rel) { $rel.ReadLatencyMax } else { $null }
            WriteLatencyMaxMs      = if ($rel) { $rel.WriteLatencyMax } else { $null }
        }
    }
    $Report.Facts.PhysicalDisks = $DiskList
}

Invoke-Step "SmartPredict" -RequiresAdmin {
    $fail = @(Get-CimInstance -Namespace root/wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue | Where-Object { $_.PredictFailure })
    $Report.Facts.SmartPredictFailure = [ordered]@{ Count = $fail.Count; Instances = @($fail | ForEach-Object { "$($_.InstanceName)" }) }
}

Invoke-Step "Volumes" {
    $dirty = @{}
    foreach ($wv in @(Get-CimInstance Win32_Volume -Filter "DriveType=3" -ErrorAction SilentlyContinue)) {
        if ($wv.DriveLetter) { $dirty["$($wv.DriveLetter)".TrimEnd(':')] = [bool]$wv.DirtyBitSet }
    }
    $Report.Facts.Volumes = @(Get-Volume -ErrorAction SilentlyContinue |
        Where-Object { $_.DriveLetter -and $_.Size -gt 0 -and "$($_.DriveType)" -eq 'Fixed' } |
        ForEach-Object {
            $dl = "$($_.DriveLetter)"
            [ordered]@{
                DriveLetter = $dl; FileSystemLabel = "$($_.FileSystemLabel)"; FileSystem = "$($_.FileSystem)"
                SizeGB = [math]::Round($_.Size / 1GB, 1); FreeGB = [math]::Round($_.SizeRemaining / 1GB, 1)
                FreePct = [math]::Round(($_.SizeRemaining / $_.Size) * 100, 1)
                DirtyBit = if ($dirty.ContainsKey($dl)) { $dirty[$dl] } else { $null }
            }
        })
}

Invoke-Step "Trim" -RequiresAdmin {
    $raw = & fsutil.exe behavior query DisableDeleteNotify 2>$null
    $Report.Facts.Trim = [ordered]@{ NtfsDisableDeleteNotify = (Get-TextField $raw '(?i)NTFS\s+DisableDeleteNotify\s*=\s*(\d)') }
}

if ($ExtendedMode) {
    Write-Host "    [Extended] janela de amostragem 2/3..." -ForegroundColor Gray
    Invoke-Step "PerfWindow2" { $PerfWindows.Add((Get-PerfWindow -Seconds $SampleSeconds -Cores $LogicalCores -Label 'W2')) }
}

# ==========================================================================
# 5. EVENTOS DE SISTEMA
# ==========================================================================
Show-Step "A analisar eventos de sistema (ultimos $EffEventDays dias)..."
$Since = (Get-Date).AddDays(-$EffEventDays)
$Ev = [ordered]@{}
$BugCodeSources = @{}   # codigo -> lista de fontes

Invoke-Step "Events.Storage" {
    $phys = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = @('disk', 'stornvme', 'storahci', 'iaStorA', 'iaStorAVC'); Level = 1, 2, 3; StartTime = $Since } 'PhysicalStorage')
    $Ev.PhysicalStorageErrors   = @(Group-EventSummary -Events @($phys | Where-Object { $_.Level -le 2 }) -Map $StorageEventMap)
    $Ev.PhysicalStorageWarnings = @(Group-EventSummary -Events @($phys | Where-Object { $_.Level -eq 3 }) -Map $StorageEventMap)
    $log = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = @('Ntfs', 'volmgr'); Level = 1, 2, 3; StartTime = $Since } 'LogicalFilesystem')
    $Ev.LogicalFilesystemErrors = @(Group-EventSummary -Events $log -Map $StorageEventMap)
}

Invoke-Step "Events.Whea" {
    $w = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = $Since } 'WHEA')
    $Ev.WHEA_Fatal     = @($w | Where-Object { $_.Level -le 2 } | Group-Object Id | Select-Object Count, Name)
    $Ev.WHEA_Corrected = @($w | Where-Object { $_.Level -gt 2 } | Group-Object Id | Select-Object Count, Name)
}

Invoke-Step "Events.KernelPower" {
    $kpRaw = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $Since } 'KernelPower41')
    $withBc = 0; $dirtyCnt = 0
    foreach ($e in $kpRaw) {
        [int64]$code = 0
        $map = Get-EventDataMap $e
        if ($map.ContainsKey('BugcheckCode')) { [void][int64]::TryParse($map['BugcheckCode'], [ref]$code) }
        if ($code -ne 0) {
            $withBc++
            $k = '0x{0:X}' -f $code
            if (-not $BugCodeSources.ContainsKey($k)) { $BugCodeSources[$k] = @{} }
            $BugCodeSources[$k]['KernelPower41'] = 1 + [int]$BugCodeSources[$k]['KernelPower41']
        } else { $dirtyCnt++ }
    }
    $Ev.KernelPower41 = [ordered]@{ TotalCount = $kpRaw.Count; CrashesWithBugcheck = $withBc; DirtyPowerLosses = $dirtyCnt }
}

Invoke-Step "Events.Misc" {
    $Ev.CpuThrottlingEvents = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Processor-Power'; Id = 37; StartTime = $Since } 'Throttling').Count
    $Ev.DisplayTDR_Count    = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Display'; Id = 4101; StartTime = $Since } 'DisplayTDR').Count
    $Ev.ResourceExhaustion_Count = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Resource-Exhaustion-Detector'; Id = 2004; StartTime = $Since } 'ResourceExhaustion').Count
    $md = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results'; StartTime = (Get-Date).AddDays(-90) } 'MemoryDiagnostics')
    $last = ($md | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
    $Ev.MemoryDiagnostics = [ordered]@{
        Runs90d = @($md | Where-Object { $_.Id -in 1201, 1202 }).Count
        RunsWithErrors = @($md | Where-Object { $_.Id -eq 1202 }).Count
        LastEvent = if ($last) { $last.ToString('yyyy-MM-dd') } else { $null }
    }
}
$Report.Facts.AggregatedEvents = $Ev

# ==========================================================================
# 6. CRASHES (BugCheck, minidumps, aplicacoes)
# ==========================================================================
Show-Step "A analisar crashes: BugChecks, minidumps e aplicacoes que falham..."
Invoke-Step "Crashes.Dumps" {
    $folder = "$env:SystemRoot\Minidump"
    $files = @()
    if (Test-Path $folder) { $files = @(Get-ChildItem -Path $folder -Filter "*.dmp" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending) }
    $script:DumpCount = $files.Count
    $script:LatestDumpDt = if ($files.Count -gt 0) { $files[0].LastWriteTime } else { $null }
    $dumpRows = @()
    foreach ($f in ($files | Select-Object -First 10)) {
        $hdr = Read-MinidumpBugCheck -Path $f.FullName
        $code = if ($hdr -and $hdr.Code -ne 0) { '0x{0:X}' -f $hdr.Code } else { $null }
        if ($code) {
            if (-not $BugCodeSources.ContainsKey($code)) { $BugCodeSources[$code] = @{} }
            $BugCodeSources[$code]['Minidump'] = 1 + [int]$BugCodeSources[$code]['Minidump']
        }
        $dumpRows += [ordered]@{ File = $f.Name; Modified = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'); SizeKB = [math]::Round($f.Length / 1KB, 0); BugCheck = $code }
    }
    $Report.Facts.CrashDumps = [ordered]@{
        MinidumpCount      = $files.Count
        LatestMinidumpDate = if ($script:LatestDumpDt) { $script:LatestDumpDt.ToString("yyyy-MM-dd HH:mm:ss") } else { "Nenhum" }
        Dumps              = $dumpRows
    }
}

Invoke-Step "Crashes.BugCheckEvents" {
    $ev1001 = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001; StartTime = (Get-Date).AddDays($CrashDays * -1) } 'BugCheck1001')
    foreach ($e in $ev1001) {
        $txt = if ($e.Properties.Count -gt 0) { "$($e.Properties[0].Value)" } else { "" }
        $m = [regex]::Match($txt, '0x[0-9a-fA-F]+')
        if ($m.Success) {
            $k = '0x{0:X}' -f ([Convert]::ToInt64($m.Value.Substring(2), 16))
            if (-not $BugCodeSources.ContainsKey($k)) { $BugCodeSources[$k] = @{} }
            $BugCodeSources[$k]['Event1001'] = 1 + [int]$BugCodeSources[$k]['Event1001']
        }
    }
    $analysis = @()
    foreach ($k in $BugCodeSources.Keys) {
        $info = Get-BugCheckInfo -Code ([Convert]::ToInt64($k.Substring(2), 16)) -Table $BugCheckTable
        $srcs = $BugCodeSources[$k]
        $cnt = ($srcs.Values | Measure-Object -Maximum).Maximum
        $analysis += [ordered]@{ Code = $info.Code; Name = $info.Name; Category = $info.Category; Occurrences = $cnt; Sources = (($srcs.Keys | Sort-Object) -join ", ") }
    }
    $Report.Facts.CrashDumps.BugcheckAnalysis = @($analysis | Sort-Object { $_.Occurrences } -Descending)
}

Invoke-Step "Crashes.Stability" {
    $rel = Get-CimInstance Win32_ReliabilityStabilityMetrics -ErrorAction SilentlyContinue | Sort-Object TimeGenerated -Descending | Select-Object -First 1
    $Report.Facts.CrashDumps.SystemStabilityIndex = if ($rel) { [math]::Round([double]$rel.SystemStabilityIndex, 1) } else { $null }
    $rc = Get-CimInstance Win32_OSRecoveryConfiguration -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($rc) { $Report.Facts.CrashDumps.DumpSettings = [ordered]@{ DebugInfoType = $rc.DebugInfoType; AutoReboot = $rc.AutoReboot } }
}

Invoke-Step "Crashes.Applications" {
    $crash = @(Get-EventsSafe @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000; StartTime = $Since } 'AppError1000')
    $hang  = @(Get-EventsSafe @{ LogName = 'Application'; ProviderName = 'Application Hang'; Id = 1002; StartTime = $Since } 'AppHang1002')
    $rows = @()
    foreach ($e in $crash) {
        if ($e.Properties.Count -ge 4) { $rows += [pscustomobject]@{ App = "$($e.Properties[0].Value)"; Module = "$($e.Properties[3].Value)" } }
    }
    $hangApps = @{}
    foreach ($e in $hang) { if ($e.Properties.Count -ge 1) { $a = "$($e.Properties[0].Value)"; $hangApps[$a] = 1 + [int]$hangApps[$a] } }
    $top = @($rows | Group-Object App | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
        $mod = ($_.Group | Group-Object Module | Sort-Object Count -Descending | Select-Object -First 1).Name
        [ordered]@{ App = $_.Name; Crashes = $_.Count; TopFaultingModule = $mod; Hangs = [int]$hangApps[$_.Name] }
    })
    $Report.Facts.AppCrashes = [ordered]@{
        Crashes1000 = $crash.Count; Hangs1002 = $hang.Count
        DistinctCrashingApps = @($rows | Select-Object -ExpandProperty App -Unique).Count
        TopApps = $top
    }
}

$rrRaw = @(Invoke-TimedStep "Crashes.ReliabilityRecords" {
    param($SinceDt)
    $dm = [Management.ManagementDateTimeConverter]::ToDmtfDateTime($SinceDt)
    try { $r = Get-CimInstance Win32_ReliabilityRecords -Filter "TimeGenerated >= '$dm'" -ErrorAction Stop }
    catch { $r = Get-CimInstance Win32_ReliabilityRecords -ErrorAction SilentlyContinue | Where-Object { $_.TimeGenerated -ge $SinceDt } }
    $r | Select-Object SourceName, EventIdentifier, ProductName, TimeGenerated
} -ArgumentList @($Since) -TimeoutSec 45)
$relTop = @($rrRaw | Where-Object { $_.SourceName -match 'Application|Windows Error|Hang' -and $_.ProductName } |
    Group-Object ProductName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { [ordered]@{ Product = $_.Name; Failures = $_.Count } })
$Report.Facts.AppCrashes.ReliabilityTop = $relTop
$Report.Facts.AppCrashes.ReliabilityRecordsTotal = $rrRaw.Count

# ==========================================================================
# 7. REDE
# ==========================================================================
Show-Step "A auditar rede: rota, latencia, jitter, DNS, estatisticas e Wi-Fi..."
$NetFacts = [ordered]@{
    AdapterActive = "Nenhum"; IsVirtualAdapter = $null; PhysicalMedia = $null; LinkSpeedMbps = $null
    GatewayIP = $null; GatewayPing = $false; DNSResolution = $false; InternetTcp443 = $false
    IPv4 = @(); IsApipa = $false; DnsServers = @(); DnsServerTests = @()
    Latency = [ordered]@{ Gateway = $null; Internet = $null }
    Statistics = $null; WiFiDetails = $null
}
$Report.Facts.Network = $NetFacts

Invoke-Step "Network" {
    $routes = @()
    try {
        $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | ForEach-Object {
            $ifm = (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).InterfaceMetric
            [pscustomobject]@{ IfIndex = $_.InterfaceIndex; NextHop = $_.NextHop; Metric = ([int]$_.RouteMetric + [int]$ifm) }
        } | Sort-Object Metric)
    } catch { }
    $best = $routes | Select-Object -First 1
    $adapter = $null; $gw = $null
    if ($best) { $adapter = Get-NetAdapter -InterfaceIndex $best.IfIndex -ErrorAction SilentlyContinue; $gw = $best.NextHop }
    if (-not $adapter) { $adapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and -not $_.Virtual } | Select-Object -First 1 }
    if (-not $adapter) { return }

    $NetFacts.AdapterActive    = $adapter.InterfaceAlias
    $NetFacts.IsVirtualAdapter = [bool]$adapter.Virtual
    $NetFacts.PhysicalMedia    = "$($adapter.PhysicalMediaType)"
    $NetFacts.LinkSpeedMbps    = if ($adapter.Speed) { [math]::Round([double]$adapter.Speed / 1e6, 0) } else { $null }
    $NetFacts.GatewayIP        = $gw

    $ips = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { "$($_.IPAddress)" })
    $NetFacts.IPv4 = $ips
    $NetFacts.IsApipa = [bool](@($ips | Where-Object { $_ -like '169.254.*' }).Count)

    $st = Get-NetAdapterStatistics -Name $adapter.Name -ErrorAction SilentlyContinue
    if ($st) {
        $NetFacts.Statistics = [ordered]@{
            ReceivedUnicastPackets = [int64]$st.ReceivedUnicastPackets; SentUnicastPackets = [int64]$st.SentUnicastPackets
            ReceivedDiscardedPackets = [int64]$st.ReceivedDiscardedPackets; ReceivedPacketErrors = [int64]$st.ReceivedPacketErrors
            OutboundDiscardedPackets = [int64]$st.OutboundDiscardedPackets; OutboundPacketErrors = [int64]$st.OutboundPacketErrors
        }
    }

    if ($gw -and $gw -ne '0.0.0.0') {
        $NetFacts.Latency.Gateway = Test-PingTarget -Target $gw -Count $EffPingCount
        $NetFacts.GatewayPing = ($NetFacts.Latency.Gateway.Received -gt 0)
    }
    $NetFacts.Latency.Internet = Test-PingTarget -Target '1.1.1.1' -Count $EffPingCount

    try {
        if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
            $dnsTest = Resolve-DnsName -Name "www.microsoft.com" -Type A -DnsOnly -ErrorAction Stop
        } else { $dnsTest = [System.Net.Dns]::GetHostAddresses("www.microsoft.com") }
        if ($dnsTest) { $NetFacts.DNSResolution = $true }
    } catch { }

    $servers = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } | Select-Object -First 3)
    $NetFacts.DnsServers = $servers
    $tests = @()
    foreach ($srv in $servers) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew(); $ok = $false
        try { $null = Resolve-DnsName -Name 'www.microsoft.com' -Server $srv -Type A -DnsOnly -QuickTimeout -ErrorAction Stop; $ok = $true } catch { }
        $sw.Stop()
        $tests += [ordered]@{ Server = $srv; Ok = $ok; Ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 0) }
    }
    $NetFacts.DnsServerTests = $tests

    $tcp = $null
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect("1.1.1.1", 443, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne(2000, $false) -and $tcp.Connected) { $tcp.EndConnect($iar); $NetFacts.InternetTcp443 = $true }
    } catch { } finally { if ($tcp) { $tcp.Close(); $tcp.Dispose() } }

    $wl = netsh wlan show interfaces 2>$null
    if ($wl) {
        $ssid = Get-TextField $wl '^\s*SSID\s*:\s*(.+)$'
        if ($ssid) {
            $sig = Get-TextField $wl '^\s*(?:Sinal|Signal)\s*:\s*(\d+)'
            $chan = Get-TextField $wl '^\s*(?:Channel|Canal)\s*:\s*(\d+)'
            $band = Get-TextField $wl '^\s*(?:Band|Banda)\s*:\s*(.+)$'
            if (-not $band -and $chan) { $band = if ([int]$chan -ge 36) { '5 GHz (inferido)' } else { '2.4 GHz (inferido)' } }
            $rx = Get-TextField $wl '^\s*(?:Receive rate|Taxa de rece.{1,3}o)\s*\(Mbps\)\s*:\s*([\d.,]+)'
            $tx = Get-TextField $wl '^\s*(?:Transmit rate|Taxa de transmiss.{1,3}o)\s*\(Mbps\)\s*:\s*([\d.,]+)'
            $NetFacts.WiFiDetails = [ordered]@{
                SSID = $ssid; SignalPct = if ($sig) { [int]$sig } else { $null }
                RadioType = Get-TextField $wl '^\s*(?:Radio type|Tipo de r.{1,2}dio)\s*:\s*(.+)$'
                Channel = $chan; Band = $band; ReceiveMbps = $rx; TransmitMbps = $tx
            }
        }
    }
}

# ==========================================================================
# 8. WINDOWS: servicos, atualizacoes, integridade, arranque, drivers
# ==========================================================================
Show-Step "A inspecionar servicos, atualizacoes, integridade, arranque e drivers..."
Invoke-Step "Services" {
    $Report.Facts.FaultedServices = @(Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" -ErrorAction SilentlyContinue |
        Where-Object { $_.ExitCode -ne 0 -and $_.ExitCode -ne 1077 } |
        Sort-Object Name | Select-Object -First 10 Name, DisplayName, State, ExitCode)
    $scm = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7000, 7001, 7009, 7011, 7022, 7023, 7024, 7031, 7034; StartTime = $Since } 'SCM')
    $rows = foreach ($e in $scm) {
        $nm = (@($e.Properties | ForEach-Object { "$($_.Value)" } | Where-Object { $_ -and $_ -notmatch '^\d+$' }) | Select-Object -First 1)
        [pscustomobject]@{ Key = "$($e.Id)|$nm"; Id = $e.Id }
    }
    $Report.Facts.ServiceControlManagerEvents = @($rows | Group-Object Key | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { [ordered]@{ Event = $_.Name; Count = $_.Count } })
}

Invoke-Step "Updates" {
    $wu = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; Id = 20, 25, 31; StartTime = (Get-Date).AddDays(-30) } 'WindowsUpdateFailures')
    $lastOk = $null
    try {
        $s = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install' -ErrorAction Stop).LastSuccessTime
        if ($s) { $lastOk = [datetime]$s }
    } catch { }
    $Report.Facts.Updates = [ordered]@{
        FailureEvents30d = $wu.Count
        FailureIds = @($wu | Group-Object Id | ForEach-Object { [ordered]@{ Id = $_.Name; Count = $_.Count } })
        LastSuccessfulInstall = if ($lastOk) { $lastOk.ToString('yyyy-MM-dd') } else { $null }
        DaysSinceLastInstall = if ($lastOk) { [int]((Get-Date) - $lastOk).TotalDays } else { $null }
    }
}

$hotfix = @(Invoke-TimedStep "Updates.Hotfixes" {
    Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 3 HotFixID, Description, InstalledOn
} -TimeoutSec 30)
$Report.Facts.RecentHotfixes = $hotfix
if ($null -ne $Report.Facts.Updates -and -not $Report.Facts.Updates.LastSuccessfulInstall -and $hotfix.Count -gt 0 -and $hotfix[0].InstalledOn) {
    $Report.Facts.Updates.LastSuccessfulInstall = ([datetime]$hotfix[0].InstalledOn).ToString('yyyy-MM-dd')
    $Report.Facts.Updates.DaysSinceLastInstall = [int]((Get-Date) - [datetime]$hotfix[0].InstalledOn).TotalDays
    $Report.Facts.Updates.LastInstallSource = 'Get-HotFix'
}

Invoke-Step "OsSupport" {
    $info = Get-OsSupportInfo -Build ([int]$OS.BuildNumber) -Caption "$($OS.Caption)" -Table $OsSupportTable -Now (Get-Date)
    $Report.Facts.OsSupport = if ($info) { $info } else { [pscustomobject]@{ Label = 'N/A'; OutOfSupport = $false } }
}

# DISM (CheckHealth) com timeout
$DismHealth = "Nao verificado"
if (-not $IsAdmin) {
    $DismHealth = "Nao verificado (requer admin)"
    $script:Coverage.Add([pscustomobject]@{ Name = 'DISM'; Status = 'Skipped'; Seconds = 0; Error = 'requer admin' })
} else {
    $img = @(Invoke-TimedStep "DISM" { Repair-WindowsImage -Online -CheckHealth -ErrorAction Stop } -TimeoutSec 120)
    if ($img.Count -gt 0) {
        $DismHealth = switch ("$($img[0].ImageHealthState)") {
            "Healthy"       { "Saudavel" }
            "Repairable"    { "Corrompido (Reparavel)" }
            "NonRepairable" { "Corrompido (Nao reparavel)" }
            default         { "Indeterminado" }
        }
    }
}
$Report.Facts.ComponentStoreHealth = $DismHealth

# SFC com Start-Process e timeout (saida UTF-16 lida corretamente)
if ($DeepIntegrity) {
    if (-not $IsAdmin) {
        $Report.Facts.SFC_Status = "Nao verificado (requer admin)"
        $script:Coverage.Add([pscustomobject]@{ Name = 'SFC'; Status = 'Skipped'; Seconds = 0; Error = 'requer admin' })
    } else {
        Write-Host "    [DeepIntegrity] A executar SFC /verifyonly (pode demorar 1-3 min)..." -ForegroundColor Yellow
        $sfcSw = [System.Diagnostics.Stopwatch]::StartNew()
        $sfcTmp = Join-Path $env:TEMP ("ecg_sfc_{0}.txt" -f ([guid]::NewGuid().ToString('N')))
        $sfcStatus = 'Indeterminado'; $sfcEntry = [ordered]@{ Name = 'SFC'; Status = 'Ok'; Seconds = 0; Error = $null }
        try {
            $proc = Start-Process -FilePath "$env:SystemRoot\System32\sfc.exe" -ArgumentList '/verifyonly' -NoNewWindow -PassThru -RedirectStandardOutput $sfcTmp
            if ($proc.WaitForExit(300000)) {
                $sfcOut = ""
                if (Test-Path $sfcTmp) { $sfcOut = (Get-Content -Path $sfcTmp -Raw -Encoding Unicode -ErrorAction SilentlyContinue) -replace "`0", "" }
                if ($sfcOut -match 'did not find any integrity violations|n.{1,2}o encontrou nenhuma viola') { $sfcStatus = 'Integro' }
                elseif ($sfcOut -match 'found integrity violations|encontrou viola') { $sfcStatus = 'Violacoes Encontradas' }
            } else {
                try { $proc.Kill() } catch { }
                $sfcEntry.Status = 'Timeout'; $sfcEntry.Error = 'excedeu 300 s'
            }
        } catch { $sfcEntry.Status = 'Failed'; $sfcEntry.Error = $_.Exception.Message }
        finally { Remove-Item -Path $sfcTmp -Force -ErrorAction SilentlyContinue }
        $sfcSw.Stop(); $sfcEntry.Seconds = [math]::Round($sfcSw.Elapsed.TotalSeconds, 2)
        $script:Coverage.Add([pscustomobject]$sfcEntry)
        $Report.Facts.SFC_Status = $sfcStatus
    }
}

# Itens de arranque + assinatura digital (timeout)
$startupRaw = @(Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue)
$startupRes = @(Invoke-TimedStep "StartupSignatures" {
    param($Items)
    foreach ($it in @(@($Items) | Select-Object -First 40)) {
        $c = [Environment]::ExpandEnvironmentVariables(("$($it.Command)").Trim())
        $exe = $null
        if ($c.StartsWith('"')) { $e = $c.IndexOf('"', 1); if ($e -gt 1) { $exe = $c.Substring(1, $e - 1) } }
        if (-not $exe) {
            $m = [regex]::Match($c, '^(.+?\.(?:exe|com|bat|cmd|lnk|msc|scr|vbs|ps1|dll))(?:\s|$)', 'IgnoreCase')
            $exe = if ($m.Success) { $m.Groups[1].Value } else { ($c -split '\s+')[0] }
        }
        $exists = $false; $sig = 'N/A'; $signer = $null
        if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf -ErrorAction SilentlyContinue)) {
            $exists = $true
            $s = Get-AuthenticodeSignature -FilePath $exe -ErrorAction SilentlyContinue
            if ($s) { $sig = "$($s.Status)"; if ($s.SignerCertificate) { $signer = $s.SignerCertificate.Subject } }
        }
        [pscustomobject]@{
            Name = "$($it.Name)"; Executable = $exe; Exists = $exists; Signature = $sig; Signer = $signer
            SuspiciousPath = [bool]($exe -match '\\AppData\\|\\Temp\\|\\Users\\Public\\|\\ProgramData\\')
            Location = "$($it.Location)"; User = "$($it.User)"
        }
    }
} -ArgumentList @(, $startupRaw) -TimeoutSec 60)
$Report.Facts.StartupItems = $startupRes

# Drivers (timeout)
$drvRaw = @(Invoke-TimedStep "Drivers" {
    Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object { $_.DeviceName } |
        Select-Object DeviceName, DeviceClass, Manufacturer, DriverVersion, DriverDate, IsSigned, InfName
} -TimeoutSec 60)
$oldCut = (Get-Date).AddYears(-4)
$unsignedDrv = @($drvRaw | Where-Object { $_.IsSigned -eq $false })
$oldDrv = @($drvRaw | Where-Object { $_.DriverDate -and $_.DriverDate -lt $oldCut -and $_.DeviceClass -in 'DISPLAY', 'NET', 'HDC', 'SCSIADAPTER', 'BLUETOOTH', 'MEDIA' } | Sort-Object DriverDate | Select-Object -First 8)
$Report.Facts.Drivers = [ordered]@{
    Total = $drvRaw.Count
    UnsignedCount = $unsignedDrv.Count
    Unsigned = @($unsignedDrv | Select-Object -First 8 | ForEach-Object { [ordered]@{ Device = "$($_.DeviceName)"; Class = "$($_.DeviceClass)"; Inf = "$($_.InfName)" } })
    OldCriticalDrivers = @($oldDrv | ForEach-Object { [ordered]@{ Device = "$($_.DeviceName)"; Class = "$($_.DeviceClass)"; Date = $_.DriverDate.ToString('yyyy-MM-dd'); Version = "$($_.DriverVersion)" } })
}

Invoke-Step "PnPErrors" {
    $codes = @{ 1 = 'mal configurado'; 3 = 'driver corrompido/pouca memoria'; 10 = 'nao consegue iniciar'; 12 = 'recursos insuficientes'; 14 = 'requer reinicio'; 18 = 'reinstalar drivers'; 19 = 'registo corrompido'; 28 = 'drivers nao instalados'; 31 = 'nao funciona corretamente'; 39 = 'driver corrompido/em falta'; 43 = 'o Windows parou o dispositivo (reportou problemas)'; 52 = 'assinatura digital nao verificada' }
    $bad = @(Get-CimInstance Win32_PnPEntity -Filter "ConfigManagerErrorCode <> 0" -ErrorAction SilentlyContinue |
        Where-Object { $_.ConfigManagerErrorCode -notin 22, 24, 45 })
    $Report.Facts.PnPErrors = @($bad | Select-Object -First 10 | ForEach-Object {
        [ordered]@{ Name = "$($_.Name)"; Class = "$($_.PNPClass)"; Code = [int]$_.ConfigManagerErrorCode; Meaning = if ($codes.ContainsKey([int]$_.ConfigManagerErrorCode)) { $codes[[int]$_.ConfigManagerErrorCode] } else { 'ver Gestor de Dispositivos' } }
    })
    $Report.Facts.PnPErrorCount = $bad.Count
}

Invoke-Step "Boot" {
    $b100 = @(Get-EventsSafe @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100; StartTime = (Get-Date).AddDays($BootDays * -1) } 'BootPerf100')
    $secs = @()
    foreach ($e in $b100) {
        $map = Get-EventDataMap $e
        $v = 0.0
        if ($map.ContainsKey('BootTime') -and [double]::TryParse($map['BootTime'], [ref]$v) -and $v -gt 0) { $secs += ($v / 1000.0) }
    }
    $deg = @(Get-EventsSafe @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 101, 102, 103, 106, 109, 110; StartTime = (Get-Date).AddDays($BootDays * -1) } 'BootDegradation')
    $degRows = foreach ($e in $deg) {
        $map = Get-EventDataMap $e
        $nm = if ($map.ContainsKey('Name')) { $map['Name'] } elseif ($map.ContainsKey('FriendlyName')) { $map['FriendlyName'] } else { '?' }
        [pscustomobject]@{ Key = "$($e.Id)|$nm" }
    }
    $Report.Facts.Boot = [ordered]@{
        DaysAnalyzed = $BootDays; BootsAnalyzed = $secs.Count
        AvgBootSeconds = if ($secs.Count -gt 0) { [math]::Round(($secs | Measure-Object -Average).Average, 1) } else { $null }
        LastBootSeconds = if ($secs.Count -gt 0) { [math]::Round($secs[0], 1) } else { $null }
        SlowBoots = @($secs | Where-Object { $_ -ge 120 }).Count
        FastStartupEnabled = $FastStartup
        DegradingItems = @($degRows | Group-Object Key | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { [ordered]@{ Item = $_.Name; Count = $_.Count } })
    }
}

# ==========================================================================
# 9. SEGURANCA
# ==========================================================================
Show-Step "A verificar seguranca: antivirus, firewall, BitLocker, TPM e Secure Boot..."
$Report.Facts.Security = [ordered]@{ Defender = $null; ThirdPartyAV = @(); Firewall = @(); BitLocker = @(); Tpm = $null; SecureBoot = $null }

$mp = @(Invoke-TimedStep "Security.Defender" {
    Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled, RealTimeProtectionEnabled, AntivirusEnabled, AntivirusSignatureAge, AntivirusSignatureLastUpdated, QuickScanAge, FullScanAge, IsTamperProtected
} -TimeoutSec 30)
if ($mp.Count -gt 0) {
    $m0 = $mp[0]
    $Report.Facts.Security.Defender = [ordered]@{
        ServiceEnabled = [bool]$m0.AMServiceEnabled; RealTimeProtection = [bool]$m0.RealTimeProtectionEnabled
        SignatureAgeDays = $m0.AntivirusSignatureAge; QuickScanAgeDays = $m0.QuickScanAge; FullScanAgeDays = $m0.FullScanAge
        TamperProtected = $m0.IsTamperProtected
    }
}

Invoke-Step "Security.ThirdPartyAV" {
    $av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object {
        $st = Get-AvState -ProductState ([uint32]$_.productState)
        [ordered]@{ Name = "$($_.displayName)"; Enabled = $st.Enabled; UpToDate = $st.UpToDate; Snoozed = $st.Snoozed }
    })
    $Report.Facts.Security.ThirdPartyAV = $av
}

Invoke-Step "Security.Firewall" {
    $Report.Facts.Security.Firewall = @(Get-NetFirewallProfile -All -ErrorAction Stop | ForEach-Object { [ordered]@{ Profile = "$($_.Name)"; Enabled = "$($_.Enabled)" } })
}

$bl = @(Invoke-TimedStep "Security.BitLocker" -RequiresAdmin {
    Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -ErrorAction Stop | Select-Object DriveLetter, ProtectionStatus
} -TimeoutSec 30)
$Report.Facts.Security.BitLocker = @($bl | ForEach-Object { [ordered]@{ Drive = "$($_.DriveLetter)"; Protected = ([int]$_.ProtectionStatus -eq 1) } })

$tpmRes = @(Invoke-TimedStep "Security.TpmSecureBoot" -RequiresAdmin {
    $t = $null; $sb = 'N/A'
    try { $t = Get-Tpm -ErrorAction Stop | Select-Object TpmPresent, TpmReady } catch { }
    try { $sb = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { }
    [pscustomobject]@{ TpmPresent = if ($t) { [bool]$t.TpmPresent } else { $null }; TpmReady = if ($t) { [bool]$t.TpmReady } else { $null }; SecureBoot = $sb }
} -TimeoutSec 20)
if ($tpmRes.Count -gt 0) {
    $Report.Facts.Security.Tpm = [ordered]@{ Present = $tpmRes[0].TpmPresent; Ready = $tpmRes[0].TpmReady }
    $Report.Facts.Security.SecureBoot = $tpmRes[0].SecureBoot
}

if ($ExtendedMode) {
    Write-Host "    [Extended] janela de amostragem 3/3..." -ForegroundColor Gray
    Invoke-Step "PerfWindow3" { $PerfWindows.Add((Get-PerfWindow -Seconds $SampleSeconds -Cores $LogicalCores -Label 'W3')) }
}

# ==========================================================================
# 10. MOTOR HEURISTICO, CORRELACAO, HISTORICO E RELATORIO
# ==========================================================================
Show-Step "A avaliar regras, correlacionar suspeitos e gerar relatorio..."
$F = $Report.Facts

# --------------------------------------------------------------------------
# 10.1 Contexto e cobertura de privilegios
# --------------------------------------------------------------------------
Invoke-Step "Rules.Context" -Internal {
    if (-not $IsAdmin) {
        Add-Finding "Windows" "Info" 1.0 "Executado sem privilegios de administrador" `
            "Resultados parciais: sensores ACPI, contadores de fiabilidade de disco, SMART, DISM, SFC, BitLocker, TPM e TRIM nao foram avaliados." `
            "Voltar a executar numa consola PowerShell elevada (Executar como administrador)." 1
    }
    if ($IsVM) {
        Add-Finding "Hardware" "Info" 1.0 "Maquina virtual detetada" `
            "Modelo: $($F.System.Manufacturer) $($F.System.Model). Regras de temperatura, bateria e SMART podem nao se aplicar." `
            "Interpretar os resultados de hardware com cautela (os discos e a CPU sao virtualizados)." 1
    }
    $up = $F.System.UptimeDays
    if ($up -ge 30) {
        $fs = if ($FastStartup) { " Com o Fast Startup ativo, 'Encerrar' nao reinicia o kernel: usar 'Reiniciar'." } else { "" }
        Add-Finding "Windows" "Info" 0.6 "Uptime Prolongado" "Sistema ligado ha $up dias sem reiniciar.$fs" "Reiniciar (nao apenas encerrar) para aplicar atualizacoes e limpar estados acumulados." 1
    }
    if ($F.System.RebootPending) {
        $sev = if ($script:RebootStrong) { "Warning" } else { "Info" }
        Add-Finding "Windows" $sev 0.9 "Reinicio Pendente" "Motivo(s): $($F.System.RebootReasons)." "Reiniciar o equipamento para concluir operacoes pendentes." 1
    }
}

# --------------------------------------------------------------------------
# 10.2 Desempenho: CPU, throttling, DPC/Interrupt, disco, paginacao
# --------------------------------------------------------------------------
Invoke-Step "Rules.Performance" -Internal {
    $W = @($PerfWindows)
    $CpuVals = @($W | ForEach-Object { $_.CpuAvg } | Where-Object { $null -ne $_ })
    $CpuTotal = if ($CpuVals.Count -gt 0) { [int][math]::Round(($CpuVals | Measure-Object -Average).Average, 0) } else { [int]$CpuCim.LoadPercentage }
    $HighWin = @($CpuVals | Where-Object { $_ -ge 85 }).Count
    $HogWin = $W | Sort-Object CpuAvg -Descending | Select-Object -First 1
    $Hogs = if ($HogWin) { @($HogWin.TopHogs) } else { @() }
    $PerfAvg = Get-Avg ($W | ForEach-Object { $_.PerfPctAvg })
    $DpcAvg = Get-Avg ($W | ForEach-Object { $_.DpcAvg })
    $IntAvg = Get-Avg ($W | ForEach-Object { $_.InterruptAvg })
    $PgAvg = Get-Avg ($W | ForEach-Object { $_.PagesInputAvg })

    $F.Performance = [ordered]@{
        Mode = if ($W.Count -ge 3) { 'Extended (3 janelas)' } else { 'Standard (1 janela)' }
        CpuAvgPct = $CpuTotal; CpuWindowsAbove85 = $HighWin; PerformancePctAvg = $PerfAvg
        DpcPctAvg = $DpcAvg; InterruptPctAvg = $IntAvg; PagesInputPerSecAvg = $PgAvg
        Windows = @($W | ForEach-Object { [ordered]@{ Label = $_.Label; Seconds = $_.Seconds; CpuAvgPct = $_.CpuAvg; ProcessSumPct = $_.ProcSumPct; PagesInputPerSec = $_.PagesInputAvg; Disks = $_.Disks } })
    }
    $F.TopRealTimeCPU = $Hogs

    if ($HighWin -ge 1) {
        $hog = $Hogs | Select-Object -First 1
        $hogTxt = if ($hog) { " Processo topo: $($hog.ProcessName) ($($hog.InstantCPU)%)." } else { " Sem processo dominante (possivel atividade de kernel/driver)." }
        $act = if ($hog) { "Investigar o processo $($hog.ProcessName) (PID $($hog.Id), $($hog.Path)) e confirmar se e legitimo antes de o terminar." } else { "Repetir a medicao e, se persistir, analisar drivers e interrupcoes (ex.: LatencyMon)." }
        if ($W.Count -ge 3 -and $HighWin -lt 2) {
            Add-Finding "Hardware" "Info" 0.5 "Pico Transitorio de CPU" "CPU >= 85% em 1 de $($W.Count) janelas (media global $CpuTotal%).$hogTxt" $act 1
        } else {
            $conf = if ($W.Count -ge 3) { 0.8 } else { 0.7 }
            $lbl = if ($W.Count -ge 3) { "Carga de CPU Sustentada" } else { "Utilizacao de CPU Elevada" }
            Add-Finding "Hardware" "Warning" $conf $lbl "CPU >= 85% em $HighWin de $($W.Count) janela(s); media $CpuTotal%.$hogTxt" $act 2
            if ($hog) { Add-Suspect "Software/Aplicacao" 1.5 "Processo $($hog.ProcessName) com CPU dominante" }
        }
    }
    if ($null -ne $PerfAvg -and $PerfAvg -lt 60 -and $CpuTotal -ge 50) {
        Add-Finding "Hardware" "Warning" 0.6 "CPU a Correr Abaixo da Frequencia Base sob Carga" "PercentProcessorPerformance medio $PerfAvg% com carga de $CpuTotal%." "Verificar plano de energia, limites termicos/PL1 e firmware (BIOS)." 1
        Add-Suspect "Arrefecimento" 1.5 "CPU abaixo da frequencia base sob carga"
    }
    $dpcInt = ([double]$DpcAvg + [double]$IntAvg)
    if ($dpcInt -ge 30) {
        Add-Finding "Hardware" "Critical" 0.7 "Tempo de DPC/Interrupt Muito Elevado" "DPC $DpcAvg% + Interrupt $IntAvg% = $([math]::Round($dpcInt,1))% do CPU." "Identificar o driver causador (LatencyMon/xperf); atualizar drivers de rede, audio e storage." 2
        Add-Suspect "Drivers" 2.5 "DPC+Interrupt muito elevados"
    } elseif ($dpcInt -ge 15) {
        Add-Finding "Hardware" "Warning" 0.65 "Tempo de DPC/Interrupt Elevado" "DPC $DpcAvg% + Interrupt $IntAvg% = $([math]::Round($dpcInt,1))% do CPU." "Identificar o driver causador (LatencyMon) e atualizar drivers." 1
        Add-Suspect "Drivers" 1.5 "DPC+Interrupt elevados"
    }
    if ($F.Context.IsVirtualMachine -eq $false -and [int]$F.Performance.Windows.Count -gt 0) { }

    # Disco: latencia e fila por disco fisico
    $samples = @($W | ForEach-Object { $_.Disks } | Where-Object { $_ })
    foreach ($grp in ($samples | Group-Object DiskIndex)) {
        $media = (@($F.PhysicalDisks) | Where-Object { $_.DeviceId -eq $grp.Name } | Select-Object -First 1).MediaType
        $isHdd = ($media -eq 'HDD')
        $warnMs = if ($isHdd) { 40 } else { 25 }
        $critMs = if ($isHdd) { 120 } else { 100 }
        $rd = Get-Max ($grp.Group | Where-Object { $_.ReadOps -ge 10 } | ForEach-Object { $_.ReadMs })
        $wr = Get-Max ($grp.Group | Where-Object { $_.WriteOps -ge 10 } | ForEach-Object { $_.WriteMs })
        $worst = Get-Max @($rd, $wr)
        $q = Get-Avg ($grp.Group | ForEach-Object { $_.QueueAvg })
        $busy = Get-Avg ($grp.Group | ForEach-Object { $_.BusyPct })
        if ($null -ne $worst -and $worst -ge $critMs) {
            Add-Finding "Storage" "Critical" 0.8 "Latencia de Disco Muito Elevada" "Disco $($grp.Name) ($media): latencia maxima $worst ms (leitura $rd / escrita $wr)." "Verificar saude do disco (SMART), cabos/controlador e processos com I/O intenso." 2
            Add-Suspect "Armazenamento" 2 "Latencia de disco $worst ms"
        } elseif ($null -ne $worst -and $worst -ge $warnMs) {
            Add-Finding "Storage" "Warning" 0.7 "Latencia de Disco Elevada" "Disco $($grp.Name) ($media): latencia maxima $worst ms (leitura $rd / escrita $wr)." "Verificar I/O em segundo plano, antivirus, indexacao e saude do disco." 1
            Add-Suspect "Armazenamento" 1 "Latencia de disco $worst ms"
        }
        if ($null -ne $q -and $q -ge 2 -and $null -ne $busy -and $busy -ge 90) {
            Add-Finding "Storage" "Warning" 0.65 "Disco Saturado (fila e ocupacao altas)" "Disco $($grp.Name): fila media $q, ocupacao $busy%." "Identificar processos com I/O intenso (Monitor de Recursos > Disco)." 1
        }
    }

    # Paginacao intensiva
    $availPct = $F.Memory.AvailableRAM_Pct
    if ($null -ne $PgAvg -and $PgAvg -ge 100 -and $availPct -lt 25) {
        $sev = if ($PgAvg -ge 500) { "Critical" } else { "Warning" }
        Add-Finding "Memory" $sev 0.7 "Paginacao Intensiva (hard faults)" "Pages Input/s medio $PgAvg com $availPct% de RAM disponivel." "Reduzir carga de memoria, fechar aplicacoes pesadas ou expandir RAM; mover pagefile para SSD." 2
        Add-Suspect "RAM insuficiente" 2.5 "Paginacao intensiva ($PgAvg pag/s)"
    }
}

# --------------------------------------------------------------------------
# 10.3 Memoria
# --------------------------------------------------------------------------
Invoke-Step "Rules.Memory" -Internal {
    $m = $F.Memory
    if ($m.AvailableRAM_MB -lt 1024 -and $m.AvailableRAM_Pct -lt 15) {
        Add-Finding "Memory" "Critical" 0.9 "Memoria Fisica Disponivel Muito Baixa" "Apenas $($m.AvailableRAM_MB) MB disponiveis ($($m.AvailableRAM_Pct)% de $($m.TotalRAM_MB) MB)." "Verificar processos com fuga de memoria ou considerar expansao de RAM." 2
        Add-Suspect "RAM insuficiente" 1.5 "Memoria disponivel muito baixa"
    }
    if ($m.CommitUtilization -gt 85) {
        Add-Finding "Memory" "Warning" 0.85 "Commit Limit Sob Pressao" "Memoria comprometida em $($m.CommitUtilization)% do limite." "Garantir pagefile adequado gerido pelo sistema." 1
    }
    if ($null -ne $m.PageFilePeakPct -and $m.PageFilePeakPct -ge 85) {
        Add-Finding "Memory" "Warning" 0.7 "Pagefile Quase Cheio no Pico" "Pico de utilizacao do pagefile em $($m.PageFilePeakPct)% ($($m.PageFilePeak_MB) de $($m.PageFileAllocated_MB) MB)." "Aumentar o pagefile (gerido pelo sistema) e verificar fugas de memoria." 1
    }
    $resEx = $F.AggregatedEvents.ResourceExhaustion_Count
    if ($resEx -gt 0) {
        Add-Finding "Memory" "Critical" 0.9 "Esgotamento de Recursos Recente (Event 2004)" "$resEx evento(s) de Resource-Exhaustion nos ultimos $EffEventDays dias." "Verificar memoria virtual e processos com consumo excessivo." 2
    }
    # Fuga de memoria / handles
    $tp = $F.TopProcesses
    $totalMB = [double]$m.TotalRAM_MB
    $topMem = $tp.ByPrivateMemory | Select-Object -First 1
    $topHnd = $tp.ByHandles | Select-Object -First 1
    if ($topMem -and $totalMB -gt 0 -and ($topMem.PrivateMB / $totalMB) -ge 0.4) {
        Add-Finding "Memory" "Warning" 0.7 "Processo com Consumo de Memoria Dominante" "$($topMem.Name) (PID $($topMem.Id)) usa $($topMem.PrivateMB) MB privados ($([math]::Round(100*$topMem.PrivateMB/$totalMB,0))% da RAM)." "Verificar se $($topMem.Name) tem fuga de memoria; atualizar/reiniciar a aplicacao." 1
        if ($m.CommitUtilization -gt 85 -or $resEx -gt 0) { Add-Suspect "Fuga de memoria: $($topMem.Name)" 3 "Commit/Resource-Exhaustion + processo dominante" }
    }
    if ($topHnd -and $topHnd.Handles -ge 20000) {
        Add-Finding "Memory" "Warning" 0.6 "Numero de Handles Muito Elevado" "$($topHnd.Name) (PID $($topHnd.Id)) com $($topHnd.Handles) handles." "Suspeita de fuga de handles: atualizar ou reiniciar $($topHnd.Name)." 1
        Add-Suspect "Fuga de memoria: $($topHnd.Name)" 1.5 "Handles elevados ($($topHnd.Handles))"
    }
    # Modulos
    $pm = $F.PhysicalMemory
    if ($pm -and -not $IsVM) {
        if ($pm.MismatchedCapacity -or $pm.MismatchedSpeed) {
            Add-Finding "Memory" "Info" 0.6 "Modulos de RAM Desemparelhados" "Capacidades/velocidades diferentes entre modulos (capacidade: $($pm.MismatchedCapacity), velocidade: $($pm.MismatchedSpeed))." "Preferir modulos identicos para dual-channel estavel." 1
        }
        if ($pm.SingleChannelPossible) {
            Add-Finding "Memory" "Info" 0.6 "Possivel Single-Channel" "$($pm.ModuleCount) modulo(s) em $($pm.SlotCount) slots." "Adicionar um segundo modulo identico para dual-channel (melhor desempenho, sobretudo com GPU integrada)." 1
        }
        if ($pm.XmpPossiblyOff) {
            Add-Finding "Memory" "Info" 0.5 "RAM Abaixo da Velocidade Nominal (XMP/EXPO?)" "A velocidade configurada e inferior a 90% da nominal dos modulos." "Ativar XMP/EXPO na BIOS se o equipamento o suportar." 1
        }
    }
    # Windows Memory Diagnostic
    $md = $F.AggregatedEvents.MemoryDiagnostics
    if ($md.RunsWithErrors -gt 0) {
        Add-Finding "Memory" "Critical" 0.95 "Windows Memory Diagnostic Detetou Erros" "$($md.RunsWithErrors) execucao(oes) com erros nos ultimos 90 dias (ultimo evento: $($md.LastEvent))." "Testar modulos individualmente (MemTest86) e substituir o modulo defeituoso." 2
        Add-Suspect "RAM" 4 "Windows Memory Diagnostic reportou erros"
    }
}

# --------------------------------------------------------------------------
# 10.4 Hardware: temperatura, throttling, WHEA, bateria, GPU, Kernel-Power
# --------------------------------------------------------------------------
Invoke-Step "Rules.Hardware" -Internal {
    $tz = $F.System.ThermalZone_ACPI_C
    if ($tz -and $tz -ge 88 -and -not $IsVM) {
        Add-Finding "Hardware" "Warning" 0.5 "Temperatura Termica ACPI Elevada" "Sonda ACPI reportou $tz C (indicativo: a sonda ACPI nem sempre corresponde ao CPU)." "Confirmar com HWiNFO/Core Temp e inspecionar ventoinhas, saidas de ar e pasta termica." 1
        Add-Suspect "Arrefecimento" 2 "Sonda ACPI a $tz C"
    }
    $thr = $F.AggregatedEvents.CpuThrottlingEvents
    if ($thr -gt 0 -and -not $IsVM) {
        Add-Finding "Hardware" "Warning" 0.7 "CPU Limitado pelo Firmware (Throttling)" "$thr evento(s) Kernel-Processor-Power 37 nos ultimos $EffEventDays dias." "Verificar temperaturas, limpeza/pasta termica, plano de energia e atualizacao de BIOS." 2
        Add-Suspect "Arrefecimento" 2 "Eventos de throttling ($thr)"
    }
    # WHEA
    $wf = @($F.AggregatedEvents.WHEA_Fatal)
    if ($wf.Count -gt 0) {
        $nm = ($wf | ForEach-Object { "ID $($_.Name) (x$($_.Count))" }) -join ", "
        Add-Finding "Hardware" "Critical" 0.95 "Erros Fatais de Hardware (WHEA)" "Eventos WHEA de nivel Erro/Critico: $nm." "Inspecionar CPU, RAM e barramento PCIe (teste de memoria, BIOS, overclock/undervolt)." 2
        Add-Suspect "CPU/Hardware" 3 "WHEA fatal"
        Add-Suspect "RAM" 1 "WHEA fatal pode indicar RAM"
    }
    $wc = @($F.AggregatedEvents.WHEA_Corrected)
    if ($wc.Count -gt 0) {
        $tot = ($wc | Measure-Object -Property Count -Sum).Sum
        $nm = ($wc | ForEach-Object { "ID $($_.Name) (x$($_.Count))" }) -join ", "
        $sev = if ($tot -ge 20) { "Warning" } else { "Info" }
        Add-Finding "Hardware" $sev 0.6 "Erros de Hardware Corrigidos (WHEA)" "Eventos WHEA corrigidos: $nm." "Se frequentes, atualizar BIOS/drivers de chipset e verificar PCIe/RAM." 1
    }
    # Bateria
    $bt = $F.Battery
    if ($bt -and $bt.Present -and $null -ne $bt.WearPct -and -not $IsVM) {
        if ($bt.WearPct -ge 60) {
            Add-Finding "Hardware" "Critical" 0.8 "Bateria Muito Desgastada" "Desgaste de $($bt.WearPct)% (capacidade atual $($bt.FullChargeCapacityMWh) de $($bt.DesignCapacityMWh) mWh; ciclos: $($bt.CycleCount))." "Substituir a bateria." 1
            Add-Suspect "Bateria" 3 "Desgaste $($bt.WearPct)%"
        } elseif ($bt.WearPct -ge 40) {
            Add-Finding "Hardware" "Warning" 0.75 "Bateria Desgastada" "Desgaste de $($bt.WearPct)% (ciclos: $($bt.CycleCount))." "Planear a substituicao da bateria." 1
            Add-Suspect "Bateria" 1.5 "Desgaste $($bt.WearPct)%"
        }
        if ($null -ne $bt.CycleCount -and $bt.CycleCount -ge 800) {
            Add-Finding "Hardware" "Info" 0.5 "Elevado Numero de Ciclos de Bateria" "$($bt.CycleCount) ciclos." "Esperar menor autonomia; considerar substituicao." 1
        }
    }
    # GPU
    foreach ($g in @($F.Gpu)) {
        if ($g.Name -like 'Microsoft Basic Display*') {
            Add-Finding "Hardware" "Warning" 0.7 "Driver Grafico Generico em Uso" "Adaptador: $($g.Name)." "Instalar o driver do fabricante da GPU." 1
            Add-Suspect "GPU" 1.5 "Driver grafico generico"
        } elseif ($null -ne $g.DriverAgeDays -and $g.DriverAgeDays -ge 730) {
            Add-Finding "Hardware" "Info" 0.5 "Driver Grafico Antigo" "$($g.Name): driver de $($g.DriverDate) (~$([int]($g.DriverAgeDays/365)) anos)." "Atualizar o driver grafico." 1
        }
        if ($g.ConfigErrorCode -and $g.ConfigErrorCode -ne 0) {
            Add-Finding "Hardware" "Warning" 0.8 "Adaptador Grafico com Erro no Gestor de Dispositivos" "$($g.Name): codigo $($g.ConfigErrorCode)." "Reinstalar o driver grafico." 1
            Add-Suspect "GPU" 2 "Erro PnP no adaptador grafico"
        }
    }
    $tdr = $F.AggregatedEvents.DisplayTDR_Count
    if ($tdr -gt 0) {
        $sev = if ($tdr -ge 3) { "Critical" } else { "Warning" }
        Add-Finding "Hardware" $sev 0.85 "Resets do Driver Grafico (TDR - Display 4101)" "$tdr evento(s) nos ultimos $EffEventDays dias." "Reinstalar driver grafico (DDU), verificar temperaturas da GPU e alimentacao." 2
        Add-Suspect "GPU" 3 "Eventos TDR ($tdr)"
    }
    # Kernel-Power
    $kp = $F.AggregatedEvents.KernelPower41
    if ($kp.CrashesWithBugcheck -gt 0) {
        Add-Finding "Hardware" "Critical" 0.9 "Reinicios por Ecra Azul (BugCheck) Detetados" "$($kp.CrashesWithBugcheck) falha(s) com BugCheck no Kernel-Power." "Analisar a classificacao dos BugChecks abaixo e os minidumps." 2
    }
    if ($kp.DirtyPowerLosses -ge 2) {
        Add-Finding "Hardware" "Warning" 0.7 "Desligamentos Abruptos / Perda de Energia" "$($kp.DirtyPowerLosses) reinicios sem BugCheck (corte eletrico, bloqueio total ou botao de energia; nao distinguivel apenas por este evento)." "Testar PSU, bateria e alimentacao; verificar bloqueios totais e temperaturas." 1
        Add-Suspect "Alimentacao/PSU" 2.5 "Desligamentos abruptos repetidos ($($kp.DirtyPowerLosses))"
    } elseif ($kp.DirtyPowerLosses -eq 1) {
        Add-Finding "Hardware" "Info" 0.5 "Um Desligamento Abrupto Registado" "1 reinicio sem BugCheck nos ultimos $EffEventDays dias." "Monitorizar; investigar se se repetir." 1
    }
}

# --------------------------------------------------------------------------
# 10.5 Armazenamento
# --------------------------------------------------------------------------
Invoke-Step "Rules.Storage" -Internal {
    foreach ($dk in @($F.PhysicalDisks)) {
        $dn = "$($dk.FriendlyName) (disco $($dk.DeviceId))"
        switch ($dk.HealthStatus) {
            "Unhealthy" { Add-Finding "Storage" "Critical" 0.95 "Disco Reportado como Nao Saudavel" "$dn : HealthStatus=Unhealthy; OperationalStatus=$($dk.OperationalStatus)." "Copia de seguranca imediata e substituicao/diagnostico do disco $dn." 2; Add-Suspect "Armazenamento" 4 "HealthStatus Unhealthy em $dn" }
            "Warning"   { Add-Finding "Storage" "Warning" 0.85 "Disco com Aviso de Saude" "$dn : HealthStatus=Warning; OperationalStatus=$($dk.OperationalStatus)." "Verificar SMART do disco $dn e garantir copia de seguranca." 2; Add-Suspect "Armazenamento" 2.5 "HealthStatus Warning em $dn" }
        }
        if ($dk.OperationalStatus -and $dk.OperationalStatus -ne "OK" -and $dk.HealthStatus -eq "Healthy") {
            Add-Finding "Storage" "Warning" 0.6 "Estado Operacional Anormal do Disco" "$dn : OperationalStatus=$($dk.OperationalStatus)." "Verificar o disco $dn no Gestor de Discos e nos registos de sistema." 1
        }
        if ($null -ne $dk.WearPercentage) {
            if ($dk.WearPercentage -ge 90) { Add-Finding "Storage" "Critical" 0.9 "Desgaste de SSD Muito Elevado" "$dn : desgaste $($dk.WearPercentage)%." "Planear substituicao do SSD $dn." 2; Add-Suspect "Armazenamento" 2.5 "Desgaste SSD $($dk.WearPercentage)%" }
            elseif ($dk.WearPercentage -ge 80) { Add-Finding "Storage" "Warning" 0.8 "Desgaste de SSD Elevado" "$dn : desgaste $($dk.WearPercentage)%." "Monitorizar e planear substituicao do SSD $dn." 1 }
        }
        $un = 0
        if ($null -ne $dk.ReadErrorsUncorrected)  { $un += [int64]$dk.ReadErrorsUncorrected }
        if ($null -ne $dk.WriteErrorsUncorrected) { $un += [int64]$dk.WriteErrorsUncorrected }
        if ($un -gt 0) { Add-Finding "Storage" "Warning" 0.75 "Erros de I/O Nao Corrigidos no Disco" "$dn : $un erros nao corrigidos acumulados." "Verificar SMART e integridade do disco $dn; garantir copia de seguranca." 2; Add-Suspect "Armazenamento" 2 "Erros nao corrigidos em $dn" }
        if ($null -ne $dk.TemperatureC -and $dk.TemperatureC -ge 70) {
            Add-Finding "Storage" "Warning" 0.7 "Temperatura de Disco Elevada" "$dn : $($dk.TemperatureC) C." "Melhorar a ventilacao do equipamento/disco." 1
        }
        if ($dk.MediaType -eq 'HDD') {
            if ($null -ne $dk.PowerOnHours -and $dk.PowerOnHours -ge 35000) {
                Add-Finding "Storage" "Info" 0.6 "HDD com Muitas Horas de Funcionamento" "$dn : $($dk.PowerOnHours) horas ligado (~$([int]($dk.PowerOnHours/8760)) anos)." "Considerar substituir/migrar para SSD; manter copias de seguranca." 1
            }
            if ($dk.LoadUnloadCycleCountMax -and $dk.LoadUnloadCycleCount -and ($dk.LoadUnloadCycleCount / $dk.LoadUnloadCycleCountMax) -ge 0.8) {
                Add-Finding "Storage" "Warning" 0.7 "Ciclos Load/Unload do HDD Proximos do Limite" "$dn : $($dk.LoadUnloadCycleCount) de $($dk.LoadUnloadCycleCountMax)." "Planear substituicao do HDD." 1
            }
        }
    }
    $sp = $F.SmartPredictFailure
    if ($sp -and $sp.Count -gt 0) {
        Add-Finding "Storage" "Critical" 0.95 "SMART Preve Falha Iminente de Disco" "$($sp.Count) dispositivo(s) com PredictFailure=True ($($sp.Instances -join ', '))." "Copia de seguranca IMEDIATA e substituicao do disco." 2
        Add-Suspect "Armazenamento" 4 "SMART PredictFailure"
    }
    # Volumes
    foreach ($vol in @($F.Volumes)) {
        if (($vol.FreePct -lt 10 -and $vol.FreeGB -lt 50) -or $vol.FreeGB -lt 5) {
            Add-Finding "Storage" "Critical" 0.98 "Volume $($vol.DriveLetter): em Esgotamento Critico" "Apenas $($vol.FreeGB) GB disponiveis ($($vol.FreePct)% livres)." "Libertar espaco no volume $($vol.DriveLetter): de imediato." 2
        } elseif ($vol.FreePct -lt 15 -and $vol.FreeGB -lt 100) {
            Add-Finding "Storage" "Warning" 0.85 "Volume $($vol.DriveLetter): com Espaco Reduzido" "Volume com $($vol.FreePct)% de espaco livre ($($vol.FreeGB) GB)." "Executar limpeza de disco (cleanmgr) e remover ficheiros temporarios." 1
        }
        if ($vol.DirtyBit -eq $true) {
            Add-Finding "Storage" "Warning" 0.85 "Dirty Bit Ativo no Volume $($vol.DriveLetter):" "O volume esta marcado como 'sujo' (encerramento anormal ou corrupcao)." "Executar chkdsk $($vol.DriveLetter): /f (agendar para o proximo arranque)." 1
            Add-Suspect "Armazenamento" 1.5 "Dirty bit em $($vol.DriveLetter):"
        }
    }
    if ($F.Trim -and $F.Trim.NtfsDisableDeleteNotify -eq '1' -and @($F.PhysicalDisks | Where-Object { $_.MediaType -eq 'SSD' }).Count -gt 0) {
        Add-Finding "Storage" "Warning" 0.6 "TRIM Desativado com SSD Presente" "DisableDeleteNotify=1 (NTFS)." "Ativar TRIM: fsutil behavior set DisableDeleteNotify 0." 1
    }
    # Eventos
    $ae = $F.AggregatedEvents
    $physErr = @($ae.PhysicalStorageErrors); $physWarn = @($ae.PhysicalStorageWarnings)
    $critHit = @(@($physErr) + @($physWarn) | Where-Object { $CriticalStorageIds -contains $_.Key })
    if ($physErr.Count -gt 0 -or $critHit.Count -gt 0) {
        $all = @(@($physErr) + @($critHit) | Select-Object -Unique)
        Add-Finding "Storage" "Critical" 0.9 "Erros no Barramento ou Controlador de Armazenamento" "Ultimos $EffEventDays dias: $(Format-EventSummary $all)." "Verificar SMART, cabos/ligacoes e estado do disco; fazer copia de seguranca." 2
        Add-Suspect "Armazenamento" 3 "Eventos de storage criticos"
    }
    $warnOnly = @($physWarn | Where-Object { $CriticalStorageIds -notcontains $_.Key })
    if ($warnOnly.Count -gt 0) {
        Add-Finding "Storage" "Warning" 0.55 "Avisos de I/O no Armazenamento" "Ultimos $EffEventDays dias: $(Format-EventSummary $warnOnly) (retries sao comuns em dispositivos USB/externos)." "Confirmar se os avisos se referem a um disco interno; se sim, verificar SMART e cabos." 1
        Add-Suspect "Armazenamento" 0.5 "Avisos de I/O"
    }
    $lg = @($ae.LogicalFilesystemErrors)
    if ($lg.Count -gt 0) {
        Add-Finding "Storage" "Warning" 0.8 "Erros Logicos no Sistema de Ficheiros (NTFS/volmgr)" "Eventos: $(Format-EventSummary $lg)." "Agendar chkdsk no volume correspondente para verificar metadados NTFS." 1
        Add-Suspect "Armazenamento" 1.5 "Erros NTFS/volmgr"
    }
}

# --------------------------------------------------------------------------
# 10.6 Crashes: BugChecks, minidumps, aplicacoes
# --------------------------------------------------------------------------
Invoke-Step "Rules.Crashes" -Internal {
    $bcs = @($F.CrashDumps.BugcheckAnalysis)
    $catPoints = @{ 'Drivers' = 'Drivers'; 'RAM' = 'RAM'; 'Armazenamento' = 'Armazenamento'; 'GPU' = 'GPU'; 'CPU/Hardware' = 'CPU/Hardware'; 'Software/Sistema' = 'Software/Aplicacao' }
    if ($bcs.Count -gt 0) {
        $txt = ($bcs | ForEach-Object { "$($_.Code) $($_.Name) [$($_.Category)] x$($_.Occurrences)" }) -join "; "
        Add-Finding "Windows" "Warning" 0.85 "BugChecks Classificados" $txt "Tratar a categoria dominante: Drivers (atualizar/reverter), RAM (MemTest86), Armazenamento (SMART/chkdsk), GPU (DDU + temperaturas), CPU/Hardware (BIOS, arrefecimento, alimentacao)." 1
        foreach ($b in $bcs) {
            $sn = $catPoints[$b.Category]
            if ($sn) { Add-Suspect $sn (1.5 + [math]::Min(2.0, [double]$b.Occurrences * 0.5)) "BugCheck $($b.Code) $($b.Name)" }
            if ($b.Code -eq '0x9F') { Add-Suspect "Alimentacao/PSU" 1 "BugCheck 0x9F (estado de energia)" }
        }
    }
    $dc = $F.CrashDumps.MinidumpCount
    if ($dc -gt 0) {
        $recent = $script:LatestDumpDt -and ($script:LatestDumpDt -gt (Get-Date).AddDays(-30))
        $sev = if ($recent) { "Warning" } else { "Info" }
        Add-Finding "Windows" $sev 0.85 "Historico de Crash Dumps Presente" "$dc minidump(s). O mais recente: $($F.CrashDumps.LatestMinidumpDate)." "Examinar com WinDbg ou BlueScreenView se houver queixas de instabilidade." 1
    }
    $ds = $F.CrashDumps.DumpSettings
    if ($ds -and $ds.DebugInfoType -eq 0 -and ($F.AggregatedEvents.KernelPower41.CrashesWithBugcheck -gt 0 -or $dc -eq 0 -and $F.AggregatedEvents.KernelPower41.TotalCount -gt 0)) {
        Add-Finding "Windows" "Info" 0.6 "Crash Dumps Desativados" "DebugInfoType=0: um BSOD nao deixa rasto para analise." "Ativar 'Despejo de memoria automatico' em Propriedades do Sistema > Arranque e Recuperacao." 1
    }
    $si = $F.CrashDumps.SystemStabilityIndex
    if ($null -ne $si -and $si -lt 5) {
        Add-Finding "Windows" "Warning" 0.7 "Indice de Fiabilidade Baixo" "SystemStabilityIndex = $si (escala 1-10)." "Abrir o Monitor de Fiabilidade (perfmon /rel) e identificar as falhas recorrentes." 1
    }
    # Aplicacoes
    $ac = $F.AppCrashes
    $topApp = @($ac.TopApps) | Select-Object -First 1
    if ($topApp -and $topApp.Crashes -ge 3) {
        Add-Finding "Windows" "Warning" 0.7 "Aplicacao com Crashes Repetidos" "$($topApp.App): $($topApp.Crashes) crash(es), modulo $($topApp.TopFaultingModule), hangs: $($topApp.Hangs)." "Atualizar/reinstalar $($topApp.App); se o modulo for de terceiros, atualizar o componente (ou desativar extensoes)." 1
        if ($topApp.Crashes -ge 5) { Add-Suspect "Software: $($topApp.App)" 3 "$($topApp.Crashes) crashes (modulo $($topApp.TopFaultingModule))" }
    }
    if ($ac.DistinctCrashingApps -ge 4 -and $ac.Crashes1000 -ge 8) {
        Add-Finding "Windows" "Warning" 0.7 "Instabilidade Generalizada de Aplicacoes" "$($ac.Crashes1000) crashes em $($ac.DistinctCrashingApps) aplicacoes diferentes." "Suspeitar de RAM, drivers ou corrupcao do sistema (testar memoria, DISM/SFC)." 2
        Add-Suspect "RAM" 1.5 "Crashes em muitas aplicacoes"
        Add-Suspect "Drivers" 1 "Crashes em muitas aplicacoes"
    }
}

# --------------------------------------------------------------------------
# 10.7 Rede
# --------------------------------------------------------------------------
Invoke-Step "Rules.Network" -Internal {
    $N = $F.Network
    if ($N.AdapterActive -eq "Nenhum") {
        Add-Finding "Network" "Critical" 1.0 "Sem Adaptadores de Rede com Link Ativo" "Nao existem placas Ethernet ou Wi-Fi ativas." "Verificar ligacao fisica de rede ou comutador de radio Wi-Fi." 2
        Add-Suspect "Rede" 3 "Sem adaptador ativo"
        return
    }
    if ($N.IsApipa) {
        Add-Finding "Network" "Critical" 0.95 "Endereco APIPA (169.254.x.x): Sem DHCP" "IPv4: $($N.IPv4 -join ', ')." "Verificar o servidor DHCP/router; renovar com ipconfig /renew; testar outro cabo/porta." 2
        Add-Suspect "Rede" 3 "APIPA (sem DHCP)"
    }
    if (-not $N.GatewayIP) {
        Add-Finding "Network" "Warning" 0.8 "Adaptador Ativo sem Rota por Defeito" "Adaptador $($N.AdapterActive) ativo mas sem gateway por defeito." "Verificar DHCP/configuracao IP (ipconfig /all)." 1
    } else {
        if (-not $N.DNSResolution -and $N.InternetTcp443) {
            Add-Finding "Network" "Critical" 0.9 "Falha na Resolucao de Nomes DNS" "Ligacao TCP direta por IP funciona, mas a resolucao de nomes falhou." "Limpar cache DNS (ipconfig /flushdns) ou definir servidores DNS (1.1.1.1 / 8.8.8.8)." 2
            Add-Suspect "Rede" 3 "DNS falha com ligacao por IP OK"
        } elseif (-not $N.DNSResolution -and -not $N.InternetTcp443) {
            if ($N.GatewayPing) {
                Add-Finding "Network" "Critical" 0.85 "Gateway Responde mas Sem Acesso a Internet" "Gateway $($N.GatewayIP) responde; DNS e TCP 443 falharam." "Verificar router/modem e ligacao do operador." 2
            } else {
                Add-Finding "Network" "Critical" 0.85 "Sem Conectividade Alem do Adaptador" "Gateway $($N.GatewayIP) nao responde; DNS e TCP 443 falharam." "Verificar Wi-Fi/cabo, router e configuracao IP." 2
            }
            Add-Suspect "Rede" 3 "Sem acesso a Internet"
        } elseif ($N.DNSResolution -and -not $N.InternetTcp443) {
            Add-Finding "Network" "Warning" 0.6 "Acesso TCP 443 Externo Falhou" "DNS OK, mas a ligacao TCP 443 a 1.1.1.1 falhou (pode ser bloqueio especifico)." "Verificar firewall, proxy ou filtragem no router." 1
        } elseif (-not $N.GatewayPing -and $N.GatewayIP -ne '0.0.0.0') {
            Add-Finding "Network" "Info" 0.5 "Gateway Nao Responde a ICMP" "Internet funciona; o gateway $($N.GatewayIP) provavelmente bloqueia ping." "Sem acao necessaria." 1
        }
    }
    # Latencia, jitter e perda
    foreach ($pair in @(@('Gateway', $N.Latency.Gateway, 50, 20), @('Internet', $N.Latency.Internet, 150, 40))) {
        $lbl = $pair[0]; $lt = $pair[1]
        if (-not $lt -or $lt.Sent -eq 0) { continue }
        if ($lbl -eq 'Gateway' -and $lt.Received -eq 0) { continue }
        if ($lt.LossPct -ge 20) {
            Add-Finding "Network" "Critical" 0.85 "Perda de Pacotes Elevada ($lbl)" "$($lt.LossPct)% de perda ($($lt.Received)/$($lt.Sent)); media $($lt.AvgMs) ms, jitter $($lt.JitterMs) ms." "Verificar cabo/Wi-Fi/router; testar outro ponto de acesso ou porta." 2
            Add-Suspect "Rede" 2.5 "Perda de pacotes $lbl $($lt.LossPct)%"
        } elseif ($lt.LossPct -ge 5) {
            Add-Finding "Network" "Warning" 0.75 "Perda de Pacotes ($lbl)" "$($lt.LossPct)% de perda; media $($lt.AvgMs) ms, jitter $($lt.JitterMs) ms." "Verificar qualidade do sinal/cabo e interferencias." 1
            Add-Suspect "Rede" 1.5 "Perda de pacotes $lbl $($lt.LossPct)%"
        }
        if ($null -ne $lt.JitterMs -and $lt.JitterMs -ge $pair[3]) {
            Add-Finding "Network" "Warning" 0.65 "Jitter Elevado ($lbl)" "Jitter $($lt.JitterMs) ms (media $($lt.AvgMs) ms, max $($lt.MaxMs) ms)." "Verificar congestionamento, Wi-Fi (canal/banda) e QoS do router." 1
        }
        if ($null -ne $lt.AvgMs -and $lt.AvgMs -ge $pair[2]) {
            Add-Finding "Network" "Warning" 0.6 "Latencia Elevada ($lbl)" "Latencia media $($lt.AvgMs) ms." "Verificar ligacao local (Wi-Fi/cabo) e o operador." 1
        }
    }
    # DNS por servidor
    $dt = @($N.DnsServerTests)
    $dfail = @($dt | Where-Object { -not $_.Ok })
    if ($dfail.Count -gt 0 -and $dfail.Count -lt $dt.Count) {
        Add-Finding "Network" "Warning" 0.7 "Servidor DNS Nao Responde" "Falharam: $(($dfail | ForEach-Object { $_.Server }) -join ', '); os restantes respondem." "Remover/trocar o servidor DNS que falha." 1
    }
    $dslow = @($dt | Where-Object { $_.Ok -and $_.Ms -ge 200 })
    if ($dslow.Count -gt 0) {
        Add-Finding "Network" "Warning" 0.6 "Resolucao DNS Lenta" "$(($dslow | ForEach-Object { "$($_.Server) ($($_.Ms) ms)" }) -join ', ')." "Usar servidores DNS mais rapidos (1.1.1.1 / 8.8.8.8 / do operador)." 1
    }
    # Estatisticas do adaptador
    $s = $N.Statistics
    if ($s) {
        $errs = [int64]$s.ReceivedPacketErrors + [int64]$s.OutboundPacketErrors + [int64]$s.ReceivedDiscardedPackets + [int64]$s.OutboundDiscardedPackets
        $pk = [int64]$s.ReceivedUnicastPackets + [int64]$s.SentUnicastPackets
        if ($errs -gt 100 -and $pk -gt 0 -and (100.0 * $errs / $pk) -ge 0.1) {
            Add-Finding "Network" "Warning" 0.65 "Erros/Descartes no Adaptador de Rede" "$errs erros/descartes em $pk pacotes ($([math]::Round(100.0*$errs/$pk,2))%)." "Verificar cabo/porta, driver e duplex; atualizar o driver da placa de rede." 1
            Add-Suspect "Rede" 1.5 "Erros no adaptador"
            Add-Suspect "Drivers" 0.5 "Erros no adaptador de rede"
        }
    }
    # Velocidade negociada
    if ($N.PhysicalMedia -match '802\.3' -and $null -ne $N.LinkSpeedMbps -and $N.LinkSpeedMbps -gt 0) {
        if ($N.LinkSpeedMbps -le 10) {
            Add-Finding "Network" "Warning" 0.8 "Link Ethernet a 10 Mbps" "Velocidade negociada: $($N.LinkSpeedMbps) Mbps." "Substituir o cabo/verificar o porto do switch." 1
            Add-Suspect "Rede" 2 "Link a 10 Mbps"
        } elseif ($N.LinkSpeedMbps -le 100) {
            Add-Finding "Network" "Info" 0.6 "Link Ethernet a 100 Mbps" "Velocidade negociada: $($N.LinkSpeedMbps) Mbps (um porto gigabit costuma indicar cabo/conector degradado)." "Testar outro cabo Cat5e/6 e outro porto." 1
        }
    }
    # Wi-Fi
    $wf = $N.WiFiDetails
    if ($wf) {
        if ($null -ne $wf.SignalPct -and $wf.SignalPct -lt 50) {
            $sev = if ($wf.SignalPct -lt 30) { "Critical" } else { "Warning" }
            Add-Finding "Network" $sev 0.75 "Sinal Wi-Fi Fraco" "SSID $($wf.SSID): sinal $($wf.SignalPct)% (canal $($wf.Channel), $($wf.Band))." "Aproximar do router, usar 5 GHz/mesh ou escolher um canal menos congestionado." 1
            Add-Suspect "Rede" 1.5 "Sinal Wi-Fi $($wf.SignalPct)%"
        }
        if ($wf.Band -match '2\.4' -and $null -ne $wf.SignalPct -and $wf.SignalPct -ge 50) {
            Add-Finding "Network" "Info" 0.4 "Ligado a 2.4 GHz" "SSID $($wf.SSID), canal $($wf.Channel)." "Preferir 5 GHz quando disponivel (mais rapido e menos interferencia)." 1
        }
    }
}

# --------------------------------------------------------------------------
# 10.8 Windows: servicos, drivers, arranque, atualizacoes, integridade
# --------------------------------------------------------------------------
Invoke-Step "Rules.Windows" -Internal {
    if ($F.ComponentStoreHealth -eq "Corrompido (Reparavel)") {
        Add-Finding "Windows" "Critical" 0.9 "Corrupcao no Component Store do Windows" "DISM CheckHealth: imagem reparavel." "Executar: DISM /Online /Cleanup-Image /RestoreHealth e depois sfc /scannow." 2
        Add-Suspect "Sistema Windows (integridade)" 3 "Component store corrompido"
    } elseif ($F.ComponentStoreHealth -eq "Corrompido (Nao reparavel)") {
        Add-Finding "Windows" "Critical" 0.95 "Component Store do Windows Nao Reparavel" "DISM CheckHealth: imagem nao reparavel." "Considerar reparacao in-place (setup.exe com a mesma versao) ou reinstalacao." 2
        Add-Suspect "Sistema Windows (integridade)" 4 "Component store nao reparavel"
    }
    if ($F.SFC_Status -eq "Violacoes Encontradas") {
        Add-Finding "Windows" "Warning" 0.8 "SFC Reporta Violacoes de Integridade" "sfc /verifyonly encontrou ficheiros de sistema alterados/danificados." "Executar sfc /scannow (apos DISM /RestoreHealth)." 1
        Add-Suspect "Sistema Windows (integridade)" 2 "SFC com violacoes"
    }
    # Servicos
    $sv = @($F.FaultedServices)
    if ($sv.Count -gt 0) {
        Add-Finding "Windows" "Info" 0.5 "Servicos Automaticos Parados com Erro" "$($sv.Count) servico(s): $(($sv | Select-Object -First 5 | ForEach-Object { "$($_.Name) (exit $($_.ExitCode))" }) -join ', ')." "Rever os servicos em services.msc e no Event Log." 1
    }
    $scm = @($F.ServiceControlManagerEvents)
    $scmBad = @($scm | Where-Object { $_.Count -ge 3 -or $_.Event -match '^(7000|7001|7009|7011|7023)\|' })
    if ($scmBad.Count -gt 0) {
        Add-Finding "Windows" "Warning" 0.65 "Falhas Recorrentes de Servicos (SCM)" (($scmBad | Select-Object -First 5 | ForEach-Object { "$($_.Event) x$($_.Count)" }) -join '; ') "Investigar os servicos indicados (IDs 7031/7034 = crash; 7000/7001/7009 = falha de arranque/timeout)." 1
        Add-Suspect "Software/Aplicacao" 1 "Falhas de servicos (SCM)"
    }
    # Drivers e PnP
    $dr = $F.Drivers
    if ($dr.UnsignedCount -gt 0) {
        Add-Finding "Windows" "Warning" 0.6 "Drivers Nao Assinados" "$($dr.UnsignedCount) driver(s): $(($dr.Unsigned | Select-Object -First 4 | ForEach-Object { $_.Device }) -join ', ')." "Substituir por drivers assinados do fabricante." 1
        Add-Suspect "Drivers" 1 "Drivers nao assinados"
    }
    if (@($dr.OldCriticalDrivers).Count -gt 0) {
        Add-Finding "Windows" "Info" 0.5 "Drivers Criticos Antigos (> 4 anos)" (($dr.OldCriticalDrivers | Select-Object -First 4 | ForEach-Object { "$($_.Device) ($($_.Date))" }) -join '; ') "Atualizar drivers de grafica, rede, storage, Bluetooth e audio." 1
    }
    if ($F.PnPErrorCount -gt 0) {
        Add-Finding "Windows" "Warning" 0.75 "Dispositivos com Erro no Gestor de Dispositivos" "$($F.PnPErrorCount) dispositivo(s): $(($F.PnPErrors | Select-Object -First 4 | ForEach-Object { "$($_.Name) [cod. $($_.Code): $($_.Meaning)]" }) -join '; ')." "Reinstalar/atualizar os drivers dos dispositivos listados." 1
        Add-Suspect "Drivers" 2 "Dispositivos PnP com erro ($($F.PnPErrorCount))"
    }
    # Arranque
    $bt = $F.Boot
    if ($bt -and $bt.BootsAnalyzed -gt 0) {
        if ($bt.AvgBootSeconds -ge 120) {
            Add-Finding "Windows" "Warning" 0.7 "Arranque Muito Lento" "Media de $($bt.AvgBootSeconds) s em $($bt.BootsAnalyzed) arranque(s) ($($bt.SlowBoots) acima de 120 s)." "Reduzir itens de arranque, verificar saude do disco (migrar HDD para SSD) e drivers." 1
            Add-Suspect "Software/Arranque" 1.5 "Arranque lento ($($bt.AvgBootSeconds) s)"
        } elseif ($bt.AvgBootSeconds -ge 75) {
            Add-Finding "Windows" "Info" 0.5 "Arranque Moderadamente Lento" "Media de $($bt.AvgBootSeconds) s." "Rever itens de arranque." 1
        }
        $dg = @($bt.DegradingItems) | Where-Object { $_.Count -ge 3 } | Select-Object -First 1
        if ($dg) {
            Add-Finding "Windows" "Warning" 0.6 "Componente que Degrada o Arranque" "$($dg.Item) degradou o arranque $($dg.Count) vezes." "Atualizar, reconfigurar ou remover do arranque o componente indicado." 1
            Add-Suspect "Software/Arranque" 1 "Degradacao recorrente: $($dg.Item)"
        }
    }
    # Itens de arranque
    $si = @($F.StartupItems)
    $susp = @($si | Where-Object { $_.SuspiciousPath -and $_.Signature -ne 'Valid' })
    if ($susp.Count -gt 0) {
        Add-Finding "Windows" "Warning" 0.6 "Itens de Arranque Suspeitos (caminho invulgar e sem assinatura valida)" (($susp | Select-Object -First 4 | ForEach-Object { "$($_.Name): $($_.Executable) [$($_.Signature)]" }) -join '; ') "Verificar a origem dos itens (VirusTotal/Autoruns) e remover os indesejados." 1
        Add-Suspect "Seguranca/Malware" 2.5 "Arranque suspeito ($($susp.Count))"
    }
    $dangling = @($si | Where-Object { $_.Executable -and -not $_.Exists })
    if ($dangling.Count -gt 0) {
        Add-Finding "Windows" "Info" 0.4 "Itens de Arranque com Ficheiro em Falta" (($dangling | Select-Object -First 4 | ForEach-Object { $_.Name }) -join ', ') "Remover entradas de arranque orfas (Autoruns)." 1
    }
    # Atualizacoes
    $up = $F.Updates
    if ($up) {
        if ($up.FailureEvents30d -gt 0) {
            Add-Finding "Windows" "Warning" 0.7 "Falhas do Windows Update" "$($up.FailureEvents30d) evento(s) de falha (IDs 20/25/31) nos ultimos 30 dias." "Executar o Resolucao de Problemas do Windows Update; reparar com DISM/SFC; limpar SoftwareDistribution." 1
            Add-Suspect "Sistema Windows (integridade)" 1 "Falhas do Windows Update"
        }
        if ($null -ne $up.DaysSinceLastInstall -and $up.DaysSinceLastInstall -ge 90) {
            $sev = if ($up.DaysSinceLastInstall -ge 180) { "Warning" } else { "Info" }
            Add-Finding "Windows" $sev 0.6 "Sistema sem Atualizacoes Recentes" "Ultima instalacao ha $($up.DaysSinceLastInstall) dias ($($up.LastSuccessfulInstall))." "Verificar o Windows Update e instalar as atualizacoes pendentes." 1
        }
    }
    # Fim de suporte
    $os = $F.OsSupport
    if ($os -and $os.OutOfSupport) {
        Add-Finding "Windows" "Warning" 0.8 "Versao do Windows Fora de Suporte" "$($os.Label) ($($os.Edition)): suporte terminou em $($os.EndOfSupport) (tabela interna; validar na Microsoft; Windows 10 pode ter ESU)." "Atualizar para uma versao suportada (ou ativar ESU)." 2
    } elseif ($os -and $null -ne $os.DaysToEnd -and $os.DaysToEnd -ge 0 -and $os.DaysToEnd -le 90) {
        Add-Finding "Windows" "Info" 0.6 "Fim de Suporte do Windows Proximo" "$($os.Label): suporte termina em $($os.EndOfSupport) (daqui a $($os.DaysToEnd) dias)." "Planear a atualizacao da versao do Windows." 1
    }
}

# --------------------------------------------------------------------------
# 10.9 Seguranca
# --------------------------------------------------------------------------
Invoke-Step "Rules.Security" -Internal {
    $sc = $F.Security
    $def = $sc.Defender
    $tp = @($sc.ThirdPartyAV | Where-Object { $_.Name -notmatch 'Windows Defender|Microsoft Defender' })
    $tpActive = @($tp | Where-Object { $_.Enabled })
    $defActive = ($def -and $def.RealTimeProtection)
    if (-not $defActive -and $tpActive.Count -eq 0 -and ($def -or $tp.Count -gt 0)) {
        Add-Finding "Windows" "Critical" 0.85 "Sem Antivirus Ativo" "Defender sem protecao em tempo real e nenhum antivirus de terceiros ativo." "Ativar o Microsoft Defender ou o antivirus instalado." 2
        Add-Suspect "Seguranca/Malware" 2 "Sem antivirus ativo"
    }
    if ($defActive) {
        if ($null -ne $def.SignatureAgeDays -and $def.SignatureAgeDays -ge 7) {
            $sev = if ($def.SignatureAgeDays -ge 30) { "Critical" } else { "Warning" }
            Add-Finding "Windows" $sev 0.8 "Assinaturas do Defender Desatualizadas" "Assinaturas com $($def.SignatureAgeDays) dias." "Atualizar as definicoes (Update-MpSignature) e verificar o Windows Update." 1
        }
        if ($null -ne $def.QuickScanAgeDays -and $def.QuickScanAgeDays -ge 30 -and $def.QuickScanAgeDays -lt 4000) {
            Add-Finding "Windows" "Info" 0.4 "Sem Analise Rapida Recente" "Ultima analise rapida ha $($def.QuickScanAgeDays) dias." "Executar uma analise rapida/completa." 1
        }
    }
    foreach ($t in @($tp | Where-Object { $_.Enabled -and -not $_.UpToDate })) {
        Add-Finding "Windows" "Warning" 0.7 "Antivirus de Terceiros Desatualizado" "$($t.Name) reporta definicoes desatualizadas." "Atualizar as definicoes do antivirus." 1
    }
    foreach ($fw in @($sc.Firewall)) {
        if ($fw.Enabled -eq 'False') {
            $sev = if ($fw.Profile -eq 'Public') { "Critical" } else { "Warning" }
            Add-Finding "Windows" $sev 0.7 "Firewall do Windows Desativada ($($fw.Profile))" "Perfil $($fw.Profile) com a firewall desligada (pode haver firewall de terceiros)." "Ativar a firewall do Windows ou confirmar a firewall de terceiros." 1
        }
    }
    $osVol = @($sc.BitLocker | Where-Object { $_.Drive -like 'C*' } | Select-Object -First 1)
    if ($osVol.Count -gt 0 -and $IsLaptop -and -not $osVol[0].Protected) {
        Add-Finding "Windows" "Info" 0.5 "Portatil sem BitLocker no Disco do Sistema" "Volume C: sem protecao BitLocker." "Considerar ativar BitLocker/encriptacao de dispositivo (guardar a chave de recuperacao)." 1
    }
    if ($sc.SecureBoot -eq $false) {
        Add-Finding "Windows" "Info" 0.5 "Secure Boot Desativado" "Secure Boot esta desligado." "Ativar na BIOS/UEFI se o sistema o suportar." 1
    }
    if ($sc.Tpm -and $sc.Tpm.Present -eq $false -and [int]$OS.BuildNumber -ge 22000) {
        Add-Finding "Windows" "Info" 0.5 "Windows 11 sem TPM Detetado" "TPM ausente/desativado." "Ativar TPM/fTPM na BIOS se disponivel." 1
    }
}

# --------------------------------------------------------------------------
# 10.10 Correlacao composta
# --------------------------------------------------------------------------
Invoke-Step "Rules.Correlation" -Internal {
    $kp = $F.AggregatedEvents.KernelPower41
    if ($script:Suspects.Contains('Armazenamento') -and $kp.TotalCount -ge 1) {
        Add-Suspect "Armazenamento" 1.5 "Reinicios inesperados coexistem com sinais de armazenamento"
    }
    if ($script:Suspects.Contains('GPU') -and $F.AggregatedEvents.DisplayTDR_Count -gt 0 -and @($F.CrashDumps.BugcheckAnalysis | Where-Object { $_.Category -eq 'GPU' }).Count -gt 0) {
        Add-Suspect "GPU" 2 "TDR coincide com BugCheck grafico"
    }
    if ($script:Suspects.Contains('Arrefecimento') -and $script:Suspects.Contains('CPU/Hardware')) {
        Add-Suspect "Arrefecimento" 1 "Sinais termicos coexistem com erros de CPU/hardware"
    }
    if ($kp.DirtyPowerLosses -ge 2 -and $F.Battery.Present -and $F.Battery.WearPct -ge 40) {
        Add-Suspect "Bateria" 1.5 "Desligamentos abruptos com bateria degradada"
    }
    $ranked = @($script:Suspects.Values | Sort-Object { $_.Points } -Descending)
    $Report.Suspects = @($ranked | ForEach-Object { [ordered]@{ Name = $_.Name; Points = [math]::Round($_.Points, 1); Reasons = $_.Reasons } })
    $top = $ranked | Select-Object -First 1
    if ($top -and $top.Points -ge 3.0) {
        $Report.PrimarySuspect = [ordered]@{ Name = $top.Name; Points = [math]::Round($top.Points, 1); Reasons = $top.Reasons }
    }
}

# --------------------------------------------------------------------------
# 10.11 Historico (comparacao com o JSON anterior)
# --------------------------------------------------------------------------
Invoke-Step "History" -Internal {
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
                    Add-Finding "Storage" "Warning" 0.6 "Espaco Livre a Diminuir ($($r.Metric))" "De $($r.Previous) para $($r.Current) GB ($($r.Delta) GB) em $days dias." "Investigar o que esta a consumir espaco (WizTree/TreeSize) e libertar espaco." 1
                }
            }
            'DiskWear:*' { if ($r.Delta -ge 3) { Add-Finding "Storage" "Warning" 0.7 "Desgaste de Disco a Aumentar Depressa" "$($r.Metric): de $($r.Previous)% para $($r.Current)% em $days dias." "Rever cargas de escrita e planear substituicao." 1 } }
            'DiskErr:*'  { if ($r.Delta -gt 0) { Add-Finding "Storage" "Warning" 0.75 "Novos Erros de I/O Nao Corrigidos" "$($r.Metric): +$($r.Delta) desde a ultima analise." "Verificar SMART e fazer copia de seguranca." 2; Add-Suspect "Armazenamento" 1.5 "Erros de I/O a aumentar" } }
            'Stability'  { if ($r.Delta -le -2) { Add-Finding "Windows" "Warning" 0.6 "Indice de Fiabilidade a Descer" "De $($r.Previous) para $($r.Current)." "Rever o Monitor de Fiabilidade (perfmon /rel)." 1 } }
            'Minidumps'  { if ($r.Delta -gt 0) { Add-Finding "Windows" "Warning" 0.7 "Novos Minidumps desde a Ultima Analise" "+$($r.Delta) minidump(s)." "Analisar os novos crashes." 1 } }
            'BatteryWear'{ if ($r.Delta -ge 5) { Add-Finding "Hardware" "Info" 0.6 "Desgaste da Bateria a Aumentar" "De $($r.Previous)% para $($r.Current)% em $days dias." "Planear substituicao." 1 } }
            'BootSec'    { if ($r.Previous -gt 0 -and $r.Delta -ge 15 -and ($r.Delta / $r.Previous) -ge 0.3) { Add-Finding "Windows" "Info" 0.5 "Arranque Mais Lento que Antes" "De $($r.Previous) s para $($r.Current) s." "Rever itens de arranque e atualizacoes recentes." 1 } }
            'Score'      { if ($r.Delta -le -15) { Add-Finding "Windows" "Info" 0.5 "HealthScore Piorou Bastante" "De $($r.Previous) para $($r.Current) desde a ultima analise." "Rever os findings novos." 1 } }
        }
    }
}

# --------------------------------------------------------------------------
# Cobertura de dados
# --------------------------------------------------------------------------
$cov = @($script:Coverage)
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
if ($covLevel -ne 'Alta') {
    Add-Finding "Windows" "Info" 1.0 "Cobertura de Dados $covLevel ($covPct%)" "$covSkip passo(s) ignorado(s), $covFail com falha, $covTo com timeout. O score pode estar otimista." "Executar como administrador e rever Facts.CollectionErrors / DataCoverage no JSON." 1
}

$Watch.Stop()
$Report.Metadata.DurationSeconds = [math]::Round($Watch.Elapsed.TotalSeconds, 2)
$Report.Facts.CollectionErrors = @($script:DiagErrors)

# =========================================================================
# APRESENTACAO NO TERMINAL E EXPORTACAO
# =========================================================================
$SortedFindings = @($Report.Findings | Sort-Object @{ Expression = { switch ($_.Severity) { 'Critical' { 0 } 'Warning' { 1 } default { 2 } } } }, @{ Expression = { if ($_.RelevantToIssue) { 0 } else { 1 } } })

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         PARECER CLINICO DO ECG (TRIAGEM LOCAL)           " -ForegroundColor Cyan
Write-Host "   Schema: v$($Report.SchemaVersion) | Tempo: $($Report.Metadata.DurationSeconds)s | Queixa: $Issue" -ForegroundColor Gray
if ($IssueProfiles.Count -gt 0) { Write-Host "   Perfis da queixa: $($IssueProfiles -join ', ') | Foco: $($script:FocusCategories -join ', ')" -ForegroundColor Gray }
Write-Host "==========================================================" -ForegroundColor Cyan

Write-Host "`nPONTUACAO DE SAUDE PONDERADA (0-100):" -ForegroundColor White
$ScoreColor = if ($Report.HealthScore.Overall -ge 80) { "Green" } elseif ($Report.HealthScore.Overall -ge 50) { "Yellow" } else { "Red" }
Write-Host "  GLOBAL   : $($Report.HealthScore.Overall)/100   (cobertura de dados: $covPct% - confianca $covLevel)" -ForegroundColor $ScoreColor
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
    if ($script:FocusCategories.Count -gt 0) { Write-Host "  (* = relevante para a queixa reportada)" -ForegroundColor DarkGray }
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

# Gravacao dos ficheiros (UTF-8)
$TimeStampStr = (Get-Date).ToString('yyyyMMdd_HHmmss')
$BaseName = "ECG_v23_$($env:COMPUTERNAME)_$TimeStampStr"
$JsonPath = Join-Path $OutputDir "$BaseName.json"
$TxtPath  = Join-Path $OutputDir "$BaseName.txt"

$FindingsText = if ($SortedFindings.Count -eq 0) { "Nenhuma anomalia identificada." } else {
    ($SortedFindings | ForEach-Object {
        "[$($_.Severity)] ($($_.Category)) $($_.Finding)$(if ($_.RelevantToIssue) { ' *' })`n  Evidencia: $($_.Evidence)`n  Acao     : $($_.RecommendedAction)"
    }) -join "`n`n"
}
$ActionsText = ($Report.RecommendedActions | ForEach-Object { "- $_" }) -join "`n"
$ErrorsText  = if ($script:DiagErrors.Count -gt 0) { ($script:DiagErrors | ForEach-Object { "- $_" }) -join "`n" } else { "(nenhum)" }
$SuspectsText = if (@($Report.Suspects).Count -gt 0) {
    (@($Report.Suspects) | Select-Object -First 5 | ForEach-Object { "- $($_.Name) ($($_.Points) pts): $($_.Reasons -join '; ')" }) -join "`n"
} else { "(sem suspeitos)" }
$PrimaryText = if ($Report.PrimarySuspect) { "$($Report.PrimarySuspect.Name) ($($Report.PrimarySuspect.Points) pts)" } else { "(nenhum acima do limiar)" }
$TrendText = if ($Report.Trend) {
    "Anterior: $($Report.Trend.PreviousFile) (ha $($Report.Trend.DaysSincePrevious) dias)`n" +
    ((@($Report.Trend.Rows) | ForEach-Object { "- $($_.Metric): $($_.Previous) -> $($_.Current) $($_.Unit)$(if ($_.Worse) { '  [PIOR]' })" }) -join "`n")
} else { "(sem analise anterior para comparar)" }

$ReportText = @"
==================================================================
RELATORIO CLINICO DE TRIAGEM (ECG v$ScriptVersion)
Computador : $($env:COMPUTERNAME)
Data/Hora  : $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
Queixa     : $Issue
Perfis     : $($IssueProfiles -join ', ')
Admin      : $IsAdmin | Extended: $ExtendedMode
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
Cobertura de dados: $covPct% (confianca $covLevel)

SUSPEITO PRINCIPAL: $PrimaryText
$SuspectsText

FINDINGS ($($SortedFindings.Count)):
$FindingsText

TENDENCIA:
$TrendText

PLANO DE ACAO RECOMENDADO:
$ActionsText

AVISOS DE RECOLHA:
$ErrorsText
==================================================================
"@

try {
    $Report | ConvertTo-Json -Depth 10 | Out-File -FilePath $JsonPath -Encoding UTF8 -ErrorAction Stop
    $ReportText | Out-File -FilePath $TxtPath -Encoding UTF8 -ErrorAction Stop
    Write-Host "`nRelatorio de texto gravado em : $TxtPath" -ForegroundColor Cyan
    Write-Host "Payload JSON para o Agente    : $JsonPath`n" -ForegroundColor Cyan
} catch {
    Write-Host "`nERRO ao gravar relatorios em '$OutputDir': $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Use -OutputDir para indicar uma pasta com permissoes de escrita.`n" -ForegroundColor Red
}
