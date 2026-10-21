# Evaluation

`make test` runs product-module tests with the race detector; `make fuzz` runs a
short fuzz campaigns for the CLI dispatcher and hook input decoders. `make lint`
checks vet and Go formatting. Hook golden outputs and documented-envelope input
fixtures are documentation-derived; real capture goldens remain pending.
State tests cover lifecycle operations, expiry, permissions, hostile IDs, symlinks,
FIFOs, atomic readers, and concurrent goroutine/subprocess writers on macOS/Linux.
`make fuzz` also exercises state JSON decoding and session ID sanitization.
Source tests cover MCP names/allowlists, reader prefixes, balanced/paranoid Reads,
symlinks, symlink-before-`..` escapes, dependency aliases, and temporary paths.
Post tests cover state/context/audit integration and successful exit on errors.
The rules matrix contains more than 80 source cases, each evaluated clean and
tainted, including quoting, substitutions, wrappers, destination trust and dynamic
commands. Pre integration tests cover state, audit, ask/abstention, fail modes and
deadlines. `make fuzz` exercises Bash AST parsing as well as source classification.
Fuzzing does not establish complete shell analysis. Source fixtures remain synthetic/documentation-derived.
Attack and benign corpus directories are placeholders; no attack-containment
results or benchmark numbers have been measured yet.

The throwaway spike has independent verification recorded in `spike/VERIFICATION.md`.

M1.6 adds explain text goldens and JSON checks, CLI session selection/count tests,
typed secret redaction checks, and Unix tests for redaction on disk, rotation,
symlink rejection and concurrent append. `make build test lint VERSION=m1.6`
passed on Windows with the native race detector; the state, audit, CLI and
explanation binaries also passed in Ubuntu WSL without the race detector.

M1.5 local verification (2026-10-21): `make build test lint VERSION=m1.5`
passed using Windows Go 1.27/GCC, including the native race detector. Cross-compiled
Linux test binaries for state, hooks, rules and audit passed in Ubuntu WSL; these
WSL runs did not use the race detector. Unix-only integration cases are skipped
by native Windows tests. A five-second parser fuzz campaign passed. Linux race
testing through Docker was unavailable because its API was unresponsive; the
Ubuntu/macOS Go 1.22/stable CI matrix remains the platform verification path.
