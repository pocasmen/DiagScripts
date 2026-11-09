# Step execution and progress tracking for ECG Diagnostic
# Provides Invoke-Step, Invoke-TimedStep, Show-Step functions

# Show step progress
function Show-Step {
    param([string]$Text)
    $script:StepNo++
    if (-not $Silent) {
        Write-Host " [$($script:StepNo)/${StepTotal}] $Text" -ForegroundColor Gray
    }
    Write-DiagLog -Message "Step $($script:StepNo)/${StepTotal}: $Text" -Level "Info" -Component "Progress"
}

# Execute a step with error handling
function Invoke-Step {
    param([string]$Name, [scriptblock]$Block, [switch]$RequiresAdmin, [switch]$Internal)
    $entry = [ordered]@{ Name = $Name; Status = 'Ok'; Seconds = 0; Error = $null }
    if ($RequiresAdmin -and -not $script:IsAdmin) {
        $entry.Status = 'Skipped'; $entry.Error = 'requer admin'
        $script:Coverage.Add([pscustomobject]$entry)
        Write-DiagLog -Message "Step ${Name}: Skipped (requer admin)" -Level "Warning" -Component "Step"
        return $null
    }
    Write-DiagLog -Message "Iniciando step: $Name" -Level "Debug" -Component "Step"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try { 
        & $Block 
        Write-DiagLog -Message "Step ${Name}: Concluido com sucesso" -Level "Debug" -Component "Step"
    }
    catch {
        $entry.Status = 'Failed'; $entry.Error = $_.Exception.Message
        $script:DiagErrors.Add("Step[${Name}]: $($_.Exception.Message)")
        Write-DiagLog -Message "Step ${Name}: Failed - $($_.Exception.Message)" -Level "Error" -Component "Step"
    }
    $sw.Stop()
    $entry.Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    if (-not $Internal -or $entry.Status -ne 'Ok') { 
        $script:Coverage.Add([pscustomobject]$entry)
    }
}

# Execute a step with timeout (for slow WMI/CIM calls)
function Invoke-TimedStep {
    param(
        [string]$Name, 
        [scriptblock]$Block, 
        [object[]]$ArgumentList = @(), 
        [int]$TimeoutSec = 60, 
        [switch]$RequiresAdmin
    )
    
    # Use global timeout if not specified
    if ($TimeoutSec -eq 60 -and $WmiTimeout -ne 60) {
        $TimeoutSec = $WmiTimeout
    }
    
    $entry = [ordered]@{ Name = $Name; Status = 'Ok'; Seconds = 0; Error = $null }
    if ($RequiresAdmin -and -not $script:IsAdmin) {
        $entry.Status = 'Skipped'; $entry.Error = 'requer admin'
        $script:Coverage.Add([pscustomobject]$entry)
        Write-DiagLog -Message "TimedStep ${Name}: Skipped (requer admin)" -Level "Warning" -Component "Step"
        return $null
    }
    
    Write-DiagLog -Message "Iniciando TimedStep: $Name (timeout: $TimeoutSec s)" -Level "Debug" -Component "Step"
    
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
                Write-DiagLog -Message "TimedStep ${Name}: Failed - $($ps.Streams.Error[0])" -Level "Error" -Component "Step"
            }
            $ps.Dispose()
        } else {
            $entry.Status = 'Timeout'; $entry.Error = "excedeu $TimeoutSec s"
            Write-DiagLog -Message "TimedStep ${Name}: Timeout apos $TimeoutSec s" -Level "Warning" -Component "Step"
            [void]$ps.BeginStop($null, $null)
        }
    } catch {
        $entry.Status = 'Failed'; $entry.Error = $_.Exception.Message
        $script:DiagErrors.Add("TimedStep[${Name}]: $($entry.Status) $($entry.Error)")
        Write-DiagLog -Message "TimedStep ${Name}: Exception - $($_.Exception.Message)" -Level "Error" -Component "Step"
    }
    $sw.Stop()
    $entry.Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    $script:Coverage.Add([pscustomobject]$entry)
    if ($entry.Status -in 'Timeout', 'Failed') { 
        $script:DiagErrors.Add("TimedStep[${Name}]: $($entry.Status) $($entry.Error)")
    }
    return $result
}

# Safe event log retrieval with error handling
function Get-EventsSafe {
    param([hashtable]$Filter, [string]$Label, [int]$MaxEvents = 500)
    try {
        Get-WinEvent -FilterHashtable $Filter -MaxEvents $MaxEvents -ErrorAction Stop
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            $script:DiagErrors.Add("EventLog[${Label}]: $($_.Exception.Message)")
        }
        @()
    }
}

# Extract event data map from event record
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

# Group events by provider and ID
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

# Format event summary for display
function Format-EventSummary {
    param($Items, [int]$Max = 5)
    $parts = @($Items) | Select-Object -First $Max | ForEach-Object {
        if ($_.Description) { "$($_.Key) x$($_.Count) ($($_.Description))" } else { "$($_.Key) x$($_.Count)" }
    }
    return ($parts -join "; ")
}

# Event trend analysis - detect if events are accelerating
function Get-EventTrendIncrease {
    param($Events, [int]$TotalDays = 30)
    if ($Events.Count -lt 5 -or $TotalDays -le 7) { return 0 }
    $recentCut = (Get-Date).AddDays(-7)
    $recentCount = @($Events | Where-Object { $_.TimeCreated -ge $recentCut }).Count
    $olderCount = $Events.Count - $recentCount
    $olderDays = $TotalDays - 7
    if ($olderDays -le 0 -or $olderCount -eq 0) { return 0 }
    $recentRate = $recentCount / 7.0
    $olderRate = $olderCount / $olderDays
    if ($recentRate -gt ($olderRate * 1.5) -and $recentCount -ge 3) {
        return [math]::Round((($recentRate / $olderRate) - 1) * 100, 0)
    }
    return 0
}