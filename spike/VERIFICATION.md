# Local verification — 2026-10-21

Environment: Go 1.27.0, Windows amd64; Claude Code 2.1.175.

- `gofmt -l main.go main_test.go`: empty output.
- `go build -o hook-spike.exe .`: passed.
- `go vet ./...`: passed.
- `go test -race -timeout 30s ./...`: passed, including concurrent capture and
  malformed/oversized payload cases.
- `go test -run=^$ -fuzz=FuzzCapture -fuzztime=3s`: passed after the final change
  (38,393 executions in that run).
- Synthetic PreToolUse executable check: exit 0, valid ask JSON, raw file captured.
- Executable with stdin held open: exited 0 after its internal deadline, empty
  stdout and timeout diagnostic on stderr.
- `claude plugin validate ./spike` and `claude plugin validate --strict ./spike`:
  both passed.

Initial tests failed with rename access errors in the sandbox-provided Windows
temp directory. The passing race run used workspace-local temporary files and a
workspace-local Go cache (both ignored by Git):

```powershell
cd spike
New-Item -ItemType Directory -Force -Path .test-tmp,.go-cache | Out-Null
$env:TMP = Join-Path (Get-Location) '.test-tmp'
$env:TEMP = $env:TMP
$env:GOCACHE = Join-Path (Get-Location) '.go-cache'
go vet ./...
go test -race -timeout 30s ./...
```

These checks do not establish live Claude hook behavior, POSIX permission
enforcement, macOS/Linux runtime compatibility, or the <50 ms performance target.
Those are not yet measured. No real session payloads were captured by this agent.
