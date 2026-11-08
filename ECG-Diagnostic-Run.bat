@echo off
:: ============================================
:: ECG-Diagnostic Runner v3.1
:: Executar script de diagnostico
:: ============================================

setlocal

:: Verifica se PowerShell existe (metodo robusto)
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

:: Verifica se ja estamos como admin (para evitar loop)
net session >nul 2>nul
if %ERRORLEVEL% equ 0 (
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
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -File "%SCRIPT_PATH%"' -Verb RunAs"
)

endlocal
