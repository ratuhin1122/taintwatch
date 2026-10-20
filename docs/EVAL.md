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
`make fuzz` includes the provisional shell-word scanner; this does not establish
full Bash parsing coverage. Source fixtures remain synthetic/documentation-derived.
Attack and benign corpus directories are placeholders; no attack-containment
results or benchmark numbers have been measured yet.

The throwaway spike has independent verification recorded in `spike/VERIFICATION.md`.
