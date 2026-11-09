@echo off
:: ============================================
:: ECG-Diagnostic Runner v3.1 (Orchestrator)
:: Executar script de diagnostico modular
:: ============================================

setlocal

:: Verifica se PowerShell existe
powershell -Command "exit 0" >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERRO] PowerShell nao esta instalado no sistema!
    echo Este script requer o PowerShell da Microsoft.
    echo.
    echo Para instalar:
    echo  - Windows 7/10/11: Ative o PowerShell nas funcionalidades do Windows
    echo  - Ou baixe em: https://aka.ms/install-powershell
    pause
    exit /b 1
)

:: Caminho para o script orquestrador
set "SCRIPT_PATH=%~dp0ECG-Diagnostic-Orchestrator.ps1"

:: Verifica se o script existe
if not exist "%SCRIPT_PATH%" (
    echo [ERRO] Script nao encontrado: %SCRIPT_PATH%
    echo Verifique se o ficheiro ECG-Diagnostic-Orchestrator.ps1 esta na mesma pasta.
    pause
    exit /b 1
)

:: Mensagem inicial
echo.
echo ============================================
echo  ECG-Diagnostic v3.1 - Orquestrador Modular
echo ============================================
echo.

:: Verifica se ja estamos como admin usando PowerShell (evita falha do 'net session' se o servico Server estiver desativado)
for /f "usebackq" %%i in (`powershell -NoProfile -Command "[int]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"`) do set "IS_ADMIN=%%i"

if "%IS_ADMIN%"=="1" (
    echo Executando com permissoes de administrador...
    echo.
    echo A janela ficara aberta no final. Pressione CTRL+C para fechar.
    echo.
    powershell -NoProfile -ExecutionPolicy Bypass -NoExit -File "%SCRIPT_PATH%"
) else (
    echo A abrir PowerShell com permissoes de administrador...
    echo.
    echo A janela ficara aberta no final. Pressione CTRL+C para fechar.
    echo.
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -File \"%~dp0ECG-Diagnostic-Orchestrator.ps1\"' -WorkingDirectory '%~dp0' -Verb RunAs"
)

endlocal
