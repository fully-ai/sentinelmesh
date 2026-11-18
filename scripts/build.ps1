$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
New-Item -ItemType Directory -Force -Path "bin" | Out-Null
go build -trimpath -o "bin\sentinelmesh-server.exe" ".\cmd\sentinelmesh-server"
go build -trimpath -o "bin\sentinelmesh-agent.exe" ".\cmd\sentinelmesh-agent"
go build -trimpath -o "bin\sentinelmesh.exe" ".\cmd\sentinelmesh"
Write-Host "Built binaries in .\bin\"
