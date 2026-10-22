# Evaluation

`make test` runs product-module tests with the race detector; `make fuzz` runs a
short fuzz campaigns for the CLI dispatcher and hook input decoders. `make lint`
checks vet and Go formatting. Hook golden outputs and documented-envelope input
fixtures are documentation-derived; real capture goldens remain pending.
On Linux/macOS, `make test` also runs `hookio.TestBinarySessionFlow`: it builds
the actual command and checks the six-step M1 scenario using subprocess stdin,
stdout, temporary state, persisted audit records, status and explain. Run just
this test with `go test ./internal/hookio -run TestBinarySessionFlow -count=1 -v`.
The matching human-readable demo is `bash scripts/demo.sh`.

M2.1 adds strict YAML validation/fuzzing, per-value origins, list layering,
nearest-project discovery, explicit user opt-in, hostile-project non-loosening,
and regular-file policy checks. Unix integration tests exercise loaded sources,
rule actions/precedence, read globs, closed failures, audit destinations, retention
and policy self-protection. Invalid project documents are tested to retain the
last valid guards, including WebFetch taint tracking.
Local M2.1 verification on 2026-10-22: Make build/race-test/lint and a short YAML
parser fuzz campaign passed on Windows. Unix policy, storage and hook integration,
explain goldens, binary E2E and the demo passed in WSL using fresh cross-compiled
binaries. Those WSL runs did not use the race detector; the existing Linux/macOS
Go 1.22/stable CI matrix remains the full Unix race-testing path.

M1.7 local verification: Make build/race-test/lint targets passed on Windows;
Unix-only E2E coverage was separately run in Ubuntu WSL against a fresh
cross-compiled product executable using `TAINTWATCH_E2E_BINARY`. The demo also
passed there using `TAINTWATCH_DEMO_BINARY`. WSL has no Go SDK, so that run used
the prebuilt override; normal Linux/macOS CI builds inside the subprocess test.
This verifies documented-envelope behavior, not live Claude Code payload delivery.
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
