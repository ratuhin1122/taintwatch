# Release stabilization baseline

Measured 2026-10-23 at `00d6b76`, Linux/amd64 (WSL), Go 1.27.3.

Before product changes:

- `make lint test`: exit 0. Vet, gofmt check, and all race tests passed.
- `make build VERSION=stabilize`: exit 0.
- `./build/taintwatch eval run`: exit 1. One unexpected mismatch:
  `benign-13-mcp-code-read/step-02` expects allow but receives TW009 ask
  because a normal source path appears in an MCP search result.
- Attack catch rate: 17/17 eligible synthetic scenarios. Three declared
  known misses are excluded; two are already guarded. Their labels are stale.

The eval command is a CI gate and reproduces a reason main can be red.
This run does not establish failures on Go 1.22 or macOS. Failing GitHub
Actions logs have not been supplied, so the remote failure cause remains
unverified. There is no local evidence of a Go-version, vet, formatting, or
test failure.

Full baseline outputs are in ignored local scratch logs
`.local-tmp/stabilize-step0-{checks,eval}.log`.
