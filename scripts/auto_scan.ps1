# Auto-scan helper for Windows
# Usage: .\scripts\auto_scan.ps1 [-Target 127.0.0.1] [-WinChecks]
param(
    [string]$Target = "127.0.0.1",
    [switch]$WinChecks
)

# Get listening TCP ports (unique)
$ports = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort | Sort-Object -Unique
if (-not $ports) {
    Write-Host "No listening TCP ports found or Get-NetTCPConnection unavailable."
    exit 1
}

$portlist = ($ports -join ',')
Write-Host "Detected listening ports:`n $portlist"

# Build python command
$cmd = "echo y | python -m aegis_scan.cli --target $Target --ports $portlist --timeout 1.0"
if ($WinChecks) { $cmd += " --win-checks" }

Write-Host "Running: $cmd"
Invoke-Expression $cmd
