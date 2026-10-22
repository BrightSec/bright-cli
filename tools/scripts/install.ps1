$ErrorActionPreference = "Stop"

# Check for admin rights
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "You need to run this script as an administrator. Please right-click the script and select `"Run as administrator`"."
    pause
    exit
}

# Expected environment variables
$VENDOR = "bright"
$PRODUCT_NAME = "$VENDOR-cli"
$INSTALL_DIR = Join-Path "$env:ProgramFiles" $VENDOR
$DOWNLOAD_URL = "https://github.com/BrightSec/$PRODUCT_NAME/releases/latest/download/$PRODUCT_NAME-win-x64.exe"

# Create an installation folder if not exist
if (-not (Test-Path $INSTALL_DIR)) {
    Write-Host "Creating $INSTALL_DIR folder"
    New-Item -ItemType Directory -Path $INSTALL_DIR | Out-Null
}

# Remove the original executable if exists
if (Test-Path "$INSTALL_DIR\$PRODUCT_NAME.exe") {
    Write-Host "$PRODUCT_NAME already exists in $INSTALL_DIR. Removing the existing version."
    Remove-Item "$INSTALL_DIR\$PRODUCT_NAME.exe" -Force
}

Write-Host "Installing $PRODUCT_NAME to $INSTALL_DIR..."
Invoke-WebRequest -Uri $DOWNLOAD_URL -OutFile "$INSTALL_DIR\$PRODUCT_NAME.exe"

Write-Host "Patching PATH env variable..."
# Add installation directory to the system's PATH environment variable
if (!$env:Path.Contains($INSTALL_DIR)) {
    [Environment]::SetEnvironmentVariable("PATH", "$INSTALL_DIR;$env:Path", "Machine")
}
