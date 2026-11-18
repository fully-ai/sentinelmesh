$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
go vet ./...
go test ./internal/domain ./internal/crypto ./internal/detection ./internal/netmon ./internal/threatintel
go build -o "bin\sentinelmesh-agent.exe" ".\cmd\sentinelmesh-agent"
