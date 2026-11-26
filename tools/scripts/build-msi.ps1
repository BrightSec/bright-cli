param (
    [string]$SOURCE_DIR = ".\tools\msi",            # Default path for the Wix files
    [string]$OUTPUT_DIR = ".\bin"                   # Default output path for the MSI
)

# Prepare dependencies.
# In the release pipeline roots.exe is already staged (and code signed) in
# $OUTPUT_DIR, so the copy is skipped to avoid overwriting the signed binary.
if (Test-Path "$OUTPUT_DIR\roots.exe") {
    Write-Host "Using the existing roots.exe from $OUTPUT_DIR"
} else {
    Write-Host "Copying the roots.exe from win-ca package"
    Copy-Item ".\node_modules\win-ca\lib\roots.exe" -Destination "$OUTPUT_DIR\roots.exe"
}

# Install WiX
Write-Host "Installing the wix.exe"
Invoke-WebRequest -Uri "https://github.com/wixtoolset/wix3/releases/download/wix3111rtm/wix311.exe" -OutFile ".\wix311.exe"
Start-Process -FilePath ".\wix311.exe" -ArgumentList "/install", "/quiet", "/norestart" -Wait
if ($LASTEXITCODE) {
    Write-Host "wix311.exe installation failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

# Get package version number
Write-Host "Parsing the package verion"
$VERSION = (Get-Content "package.json" | ConvertFrom-Json).version
$VERSION = $VERSION -replace '([A-Za-z-.])+','.'

# Find the latest version of candle.exe and light.exe and use them
Write-Host "Compiling WiX source files"
$CANDLETOOL = Get-ChildItem -Path "C:\Program Files (x86)\WiX Toolset*" -Recurse -Include 'candle.exe' | Sort-Object LastWriteTime | Select-Object -Last 1 -ExpandProperty FullName
Write-Host "Found candle.exe at $CANDLETOOL"
& $CANDLETOOL -arch x64 -dProductVersion="$VERSION" -dSourceDir="$OUTPUT_DIR" -dRepoDir="." $SOURCE_DIR\product.wxs -o $OUTPUT_DIR\ -ext WixUtilExtension
if ($LASTEXITCODE) {
    Write-Host "candle.exe failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "Processing .wixobj files to build a MSI"
$LIGHTTOOL = Get-ChildItem -Path "C:\Program Files (x86)\WiX Toolset*" -Recurse -Include 'light.exe' | Sort-Object LastWriteTime | Select-Object -Last 1 -ExpandProperty FullName
Write-Host "Found light.exe at $CANDLETOOL"
& $LIGHTTOOL -o $OUTPUT_DIR\bright-cli.msi $OUTPUT_DIR\*.wixobj -ext WixUtilExtension -ext WixUIExtension
if ($LASTEXITCODE) {
    Write-Host "light.exe failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}
