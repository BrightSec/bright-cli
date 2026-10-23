@echo off

setlocal enableDelayedExpansion

set "ErrorActionPreference=Stop"

:: Check for existence of PowerShell
echo Checking for existence of powershell.exe
where.exe powershell.exe >nul 2>nul || (
    echo Error: PowerShell not found.
    exit /b 1
)

:: Check for admin rights
net session >nul 2>&1
if %errorLevel% == 0 (
  echo Running with administrative privileges...
) else (
  echo Relaunching script with administrative privileges...
  echo Please grant administrative access when prompted.
  pause
  cd /d "%~dp0"
  cmd.exe /k "%~dpnx0" %*
  exit /b
)

:: Expected environment variables
set "VENDOR=bright"
set "PRODUCT_NAME=%VENDOR%-cli"
set "INSTALL_DIR=%ProgramFiles%\%PRODUCT_NAME%"
set "DOWNLOAD_URL=https://github.com/BrightSec/%PRODUCT_NAME%/releases/latest/download/%PRODUCT_NAME%-win-x64.exe"

:: Create an installation folder if not exist
if not exist "%INSTALL_DIR%" (
    echo Creating %INSTALL_DIR% folder
    mkdir "%INSTALL_DIR%"
)

:: Remove the original executable if exists
if exist "%INSTALL_DIR%\%PRODUCT_NAME%.exe" (
    echo %PRODUCT_NAME% already exists in %INSTALL_DIR%. Removing the existing version.
    del /f "%INSTALL_DIR%\%PRODUCT_NAME%.exe"
)

echo Installing %PRODUCT_NAME% to %INSTALL_DIR%...
powershell -Command "$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%INSTALL_DIR%\%PRODUCT_NAME%.exe'" || exit /b 1

:: Add installation directory to the system's PATH environment variable
echo Patching PATH env variable...
echo %PATH%|find /i "%INSTALL_DIR%">nul || setx PATH "%INSTALL_DIR%;%PATH%" /M>nul

endlocal
