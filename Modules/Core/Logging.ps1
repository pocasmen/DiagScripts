# Logging module for ECG Diagnostic
# Provides structured logging with console and file output

function Write-DiagLog {
    param(
        [string]$Message,
        [ValidateSet('Debug', 'Info', 'Warning', 'Error', 'Critical')]
        [string]$Level = 'Info',
        [string]$Component = 'General'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$timestamp] [$Level] [$Component] $Message"
    
    # Write to file
    try {
        Add-Content -Path $LogPath -Value $logEntry -Encoding UTF8 -ErrorAction Stop
    } catch {
        # If fails, try to create the directory
        $logDir = Split-Path $LogPath -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            Add-Content -Path $LogPath -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    }
    
    # Write to console (if not silent)
    if (-not $Silent) {
        $consoleColor = switch ($Level) {
            'Critical' { 'Red' }
            'Error' { 'Red' }
            'Warning' { 'Yellow' }
            'Info' { 'White' }
            'Debug' { 'Gray' }
            default { 'White' }
        }
        Write-Host "[$timestamp] [$Level] [$Component] $Message" -ForegroundColor $consoleColor
    }
}

# Initialize logging
function Initialize-Logging {
    param(
        [string]$LogPathParam,
        [switch]$SilentParam
    )
    
    $global:LogPath = $LogPathParam
    $global:Silent = $SilentParam
    
    # Ensure log directory exists
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
    
    # Log initialization
    Write-DiagLog -Message "Iniciando ECG-Diagnostic v$ScriptVersion" -Level "Info" -Component "System"
    Write-DiagLog -Message "PowerShell Version: $($PSVersionTable.PSVersion.ToString())" -Level "Info" -Component "System"
    Write-DiagLog -Message "Executando como administrador: $IsAdmin" -Level "Info" -Component "System"
    Write-DiagLog -Message "Modo silencioso: $Silent" -Level "Info" -Component "System"
}