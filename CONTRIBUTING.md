# Contributing to SentinelMesh

1. Fork `github.com/fully-ai/sentinelmesh` and create a topic branch.
2. Run `gofmt -w .`, `go vet ./...`, and `go test -race ./...` before opening a PR.
3. All parser additions must include regression tests and fuzz seeds where applicable.
4. Security-sensitive changes require threat-model notes in the PR description.
