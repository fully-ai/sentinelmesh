$ErrorActionPreference = "Stop"
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
  Write-Error "Go 1.24+ is required in PATH."
  exit 1
}
Set-Location (Join-Path $PSScriptRoot "..")
go mod download
& (Join-Path $PSScriptRoot "build.ps1")
Write-Host "SentinelMesh installed into .\bin\"
