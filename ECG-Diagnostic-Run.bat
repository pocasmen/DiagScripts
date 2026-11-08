@echo off
:: ============================================
:: ECG-Diagnostic Runner v3.1
:: Executar script de diagnostico com permissoes
:: ============================================

setlocal

:: Verifica se PowerShell existe
where powershell >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERRO] PowerShell nao encontrado no sistema!
    echo Este script requer PowerShell 5.1 ou superior.
    pause
    exit /b 1
)

:: Verifica versao do PowerShell
for /f "tokens=3" %%v in ('powershell -Command "$PSVersionTable.PSVersion.ToString()" 2^>nul') do set "PSVERSION=%%v"

:: Extrai versao major
for /f "tokens=1 delims=." %%m in ("%PSVERSION%") do set "PSMAJOR=%%m"

if %PSMAJOR% LSS 5 (
    echo [ERRO] PowerShell versao %PSVERSION% detectada.
    echo Este script requer PowerShell 5.1 ou superior.
    pause
    exit /b 1
)

:: Caminho para o script
set "SCRIPT_PATH=%~dp0ECG-Diagnostic-v3.1.ps1"

:: Verifica se o script existe
if not exist "%SCRIPT_PATH%" (
    echo [ERRO] Script nao encontrado: %SCRIPT_PATH%
    echo Verifique se o ficheiro ECG-Diagnostic-v3.1.ps1 esta na mesma pasta.
    pause
    exit /b 1
)

:: Mensagem inicial
echo.
echo ============================================
echo  ECG-Diagnostic v3.1 - Iniciando...
echo ============================================
echo.
echo A abrir PowerShell com permissoes de administrador...
echo.

:: Executa em novo processo com admin
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_PATH%"' -Verb RunAs"

endlocal
