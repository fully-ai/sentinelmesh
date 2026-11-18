$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
if (-not (Test-Path "bin\sentinelmesh-server.exe")) {
  & (Join-Path $PSScriptRoot "build.ps1")
}
$addr = if ($env:SENTINELMESH_ADDR) { $env:SENTINELMESH_ADDR } else { "127.0.0.1:8440" }
$db = if ($env:SENTINELMESH_DB) { $env:SENTINELMESH_DB } else { "data\sentinelmesh.db" }
& ".\bin\sentinelmesh-server.exe" -addr $addr -db $db
