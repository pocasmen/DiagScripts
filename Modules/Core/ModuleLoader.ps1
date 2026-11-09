# Module loader for ECG Diagnostic
# Loads all modules and sets up global variables

# Load all modules
$ModulePaths = @(
    "$PSScriptRoot\..\Core\Logging.ps1",
    "$PSScriptRoot\..\Core\Utilities.ps1",
    "$PSScriptRoot\..\Core\StepExecution.ps1",
    "$PSScriptRoot\..\Collection\Hardware.ps1",
    "$PSScriptRoot\..\Collection\Memory.ps1",
    "$PSScriptRoot\..\Collection\Storage.ps1",
    "$PSScriptRoot\..\Collection\Network.ps1",
    "$PSScriptRoot\..\Collection\Events.ps1",
    "$PSScriptRoot\..\Collection\Services.ps1",
    "$PSScriptRoot\..\Analysis\Performance.ps1",
    "$PSScriptRoot\..\Analysis\MemoryRules.ps1",
    "$PSScriptRoot\..\Analysis\HardwareRules.ps1",
    "$PSScriptRoot\..\Analysis\StorageRules.ps1",
    "$PSScriptRoot\..\Analysis\CrashesRules.ps1",
    "$PSScriptRoot\..\Analysis\NetworkRules.ps1",
    "$PSScriptRoot\..\Analysis\WindowsRules.ps1",
    "$PSScriptRoot\..\Analysis\SecurityRules.ps1",
    "$PSScriptRoot\..\Analysis\Correlation.ps1",
    "$PSScriptRoot\..\Analysis\History.ps1",
    "$PSScriptRoot\..\Reporting\HtmlReport.ps1",
    "$PSScriptRoot\..\Reporting\TextReport.ps1",
    "$PSScriptRoot\..\Reporting\ConsoleOutput.ps1"
)

foreach ($modPath in $ModulePaths) {
    if (Test-Path -LiteralPath $modPath) {
        . $modPath
    } else {
        Write-Warning "Module not found: $modPath"
    }
}

# Set up global variables
$script:DiagErrors = New-Object System.Collections.Generic.List[string]
$script:Coverage = New-Object System.Collections.Generic.List[psobject]
$script:Suspects = [ordered]@{}
$script:FocusCategories = @()
$script:StepNo = 0
