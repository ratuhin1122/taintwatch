# Taintwatch

Taintwatch is a planned defense-in-depth plugin for Claude Code, using coarse
session-level taint tracking and an audit trail. It does not solve prompt
injection. Content detectors are telemetry only and will not independently block
actions.

**Current state: scaffold only. There is no security enforcement yet.**
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
taintwatch explain [--help]
taintwatch status [--help]
taintwatch version [--help]
taintwatch --help
```

Each command and hook handler accepts `--help` or `-h`. `version` prints the build
version. All other commands are explicit stubs: they write a diagnostic to stderr
and exit 1. Hooks do not consume stdin, emit decisions, or enforce policy.
Do not wire this scaffold binary into a live session as protection.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Success, version, or help |
| 1 | Unimplemented command or failed operation |
| 2 | Invalid CLI usage, unknown command, or invalid arguments |

These are **CLI** exit codes. Claude Code interprets hook exit 2 as blocking;
future hook adapters must map internal errors to the configured open/closed fail
mode instead of forwarding CLI usage errors. No hook-format assumptions are added
outside [the existing verification ledger](docs/ASSUMPTIONS.md).

The `hookio` decoder accepts one object of at most 8 MiB, ignores unknown envelope
fields, tolerates missing optional metadata, and preserves raw tool input/result
JSON. Use its typed decoders and `Result` constructors instead of building hook
JSON in other packages. `Result.Write` returns exit 0 on success, even for deny,
and an error with exit 1 on an output failure. The hook entry point will own failure
policy and elapsed-time limits; these are not implemented by the current CLI stubs.

Secure session persistence is implemented in `internal/state`; see
[state storage](docs/STATE.md) for paths, locking, expiration, and API behavior.
The CLI does not yet use it. Policy layering, self-protection, redacted audit logs,
and rule decisions remain future work. Default policy actions will ask; deny will
require explicit policy. This repository is licensed under MIT.
