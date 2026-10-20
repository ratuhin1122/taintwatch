# Evaluation

`make test` runs product-module tests with the race detector; `make fuzz` runs a
short CLI dispatcher fuzz campaign. `make lint` checks vet and Go formatting.
Attack and benign corpus directories are placeholders; no attack-containment
results or benchmark numbers have been measured yet.

The throwaway spike has independent verification recorded in `spike/VERIFICATION.md`.
