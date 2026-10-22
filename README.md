# Taintwatch

Taintwatch is a defense-in-depth plugin for Claude Code, using coarse
session-level taint tracking and an audit trail. It does not solve prompt
injection. Content detectors are telemetry only and will not independently block
actions.

**Current state: pre/post hooks, policy loading, audit inspection, and plugin packaging.**
See [installation and doctor](docs/install.md) for local plugin and standalone setup.
The hook payload spike remains isolated in its own Go module under `spike/`.
`internal/hookio` now decodes the documented input envelopes and writes verified
structured outputs. Real payload confirmation and real-capture golden tests remain
pending; tool-specific input and response schemas stay opaque JSON.

## Development

Go 1.22+, Make, and a POSIX shell are required. Race tests require a supported C
toolchain. Product targets are macOS and Linux (amd64, arm64). Windows is
best-effort through WSL; native Windows is not a supported product target.

```sh
make build test lint
./build/taintwatch version
make build VERSION=0.1.0
./build/taintwatch version
make fuzz
make clean
```

Direct `go build` and default Make builds print `dev`; Make injects `VERSION` with
`-ldflags`. Root targets cover the product module only, not the disposable spike.
CI runs build, vet, formatting, and race tests on Ubuntu/macOS with Go 1.22 and
the latest stable Go. Hook latency is not yet measured.

## CLI contract

```text
taintwatch hook <pre|post|prompt|session-start> [--help]
taintwatch hook post [--profile balanced|paranoid] [--fail-mode open|closed]
taintwatch explain [--session ID] [--last N] [--json]
taintwatch status [--session ID]
taintwatch policy check [file]
taintwatch policy show
taintwatch version [--help]
taintwatch install
taintwatch uninstall
taintwatch doctor
taintwatch allow <domain HOST|path FILE> [--yes]
taintwatch disallow <domain HOST|path FILE> [--yes]
taintwatch clear [--session ID] --reason TEXT
taintwatch --help
```

Each command and hook handler accepts `--help` or `-h`. `version` prints the build
version. `hook post` consumes stdin, tracks source taint, writes a minimal redacted
audit record and emits factual additional context for untrusted sources. `hook pre`
checks the built-in risk rules and returns ask for applicable actions; see
[rule behavior](docs/RULES.md). Prompt/session-start remain stubs. `explain` and
`status` inspect audit history and current state; see [audit logging](docs/AUDIT.md).
No hooks are installed automatically.

Permanent user-policy exceptions require a displayed diff and terminal `[y/N]`
confirmation (or explicit `--yes`). Clear requires a reason and records the OS
identity. Both ask through TW006 when called from Claude's Bash tool. See
[approvals, clearing, and fail modes](docs/approvals.md). Native permission
approvals are not cached: the documented hooks do not prove which human approved
an individual ask, so risky actions ask again while tainted.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Success, version, help, or handled post-hook error |
| 1 | Unimplemented command or failed operation |
| 2 | Invalid CLI usage, unknown command, or invalid arguments |

These are **CLI** exit codes. Claude Code interprets hook exit 2 as blocking;
`hook post` always returns 0 and never emits a blocking decision. Open errors log a
diagnostic; closed errors add advisory confirmation context because PostToolUse
cannot undo execution or return a PreToolUse ask. No hook-format assumptions are added
outside [the existing verification ledger](docs/ASSUMPTIONS.md).

The `hookio` decoder accepts one object of at most 8 MiB, ignores unknown envelope
fields, tolerates missing optional metadata, and preserves raw tool input/result
JSON. Use its typed decoders and `Result` constructors instead of building hook
JSON in other packages. `Result.Write` returns exit 0 on success, even for deny,
and an error with exit 1 on an output failure. The post-hook entry point handles
those errors, applies its fail mode and bounds process lifetime with a watchdog.

Secure session persistence is implemented in `internal/state`; see
[state storage](docs/STATE.md) for paths, locking, expiration, and API behavior.
The post hook uses state and minimal redacted audit storage. See [source policy and
post-hook behavior](docs/TAINT.md) for defaults, shell-matching gaps, audit limits,
and error semantics. Policy layering and project anti-loosening protections are
documented in [policy.md](docs/policy.md). Approval/clear commands remain future
work. Audit rotation and inspection are documented in [AUDIT.md](docs/AUDIT.md).
Default policy actions ask; deny will
require explicit policy. This repository is licensed under MIT.
