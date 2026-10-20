# Evaluation

`make test` runs product-module tests with the race detector; `make fuzz` runs a
short fuzz campaigns for the CLI dispatcher and hook input decoders. `make lint`
checks vet and Go formatting. Hook golden outputs and documented-envelope input
fixtures are documentation-derived; real capture goldens remain pending.
Attack and benign corpus directories are placeholders; no attack-containment
results or benchmark numbers have been measured yet.

The throwaway spike has independent verification recorded in `spike/VERIFICATION.md`.
