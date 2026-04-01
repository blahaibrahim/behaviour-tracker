# Must be run as Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Run this script as an Administrator."
    exit
}

$RepoRoot = (Get-Item $PSScriptRoot).Parent.FullName

Write-Host "1. Installing Sysmon" -ForegroundColor Cyan
cd $RepoRoot\configs
 first
if (Test-Path "sysmon64.exe") {
    .\sysmon64.exe -accepteula -i sysmonconfig-export.xml
    Write-Host "Sysmon Installed." -ForegroundColor Green
} else {
    Write-Host "Download sysmon64.exe into the configs folder first." -ForegroundColor Yellow
}

Write-Host "`n2. Configuring Winlogbeat" -ForegroundColor Cyan
$WinlogPath = "C:\Program Files\Winlogbeat"
if (Test-Path $WinlogPath) {
    Copy-Item -Path "$RepoRoot\configs\winlogbeat.yml" -Destination "$WinlogPath\winlogbeat.yml" -Force
    Restart-Service winlogbeat
    Write-Host "Winlogbeat Configured and Started." -ForegroundColor Green
} else {
    Write-Host "Winlogbeat not found at $WinlogPath. Install it first." -ForegroundColor Red
}

Write-Host "`n3. Configuring Packetbeat" -ForegroundColor Cyan
$PacketPath = "C:\Program Files\Elastic\Packetbeat"
if (Test-Path $PacketPath) {
    Copy-Item -Path "$RepoRoot\configs\packetbeat.yml" -Destination "$PacketPath\packetbeat.yml" -Force
    Restart-Service packetbeat
    Write-Host "Packetbeat Configured and Started." -ForegroundColor Green
} else {
    Write-Host "Packetbeat not found at $PacketPath. Install it first." -ForegroundColor Red
}

Write-Host "`nSetup Complete" -ForegroundColor Green
Write-Host "You must manually update the network card number in C:\Program Files\Elastic\Packetbeat\packetbeat.yml" -ForegroundColor Yellow