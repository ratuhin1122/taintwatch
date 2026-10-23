# Release stabilization verification

Date: 2026-10-23. Verified code/test tree: `519273f`.
Host: Linux/amd64 through Ubuntu WSL, Go 1.27.3, CGO enabled,
GOMAXPROCS=2. Checks ran from an identical source snapshot on the Linux
filesystem, excluding ignored caches/build outputs and Git metadata.

## Completed steps and commits

| Step | Commit | Result |
| --- | --- | --- |
| 0 â€” diagnose before code changes | `dd0e44a` | Local lint/race suite passed; eval reproduced the benign-13 TW009 mismatch. Supplied Actions logs confirmed the same gate failure on Go 1.22.x and stable. |
| 1 â€” eval gate | `92cd732` | Harmful-step known misses are expected failures, other mismatches fail, and fully caught known misses fail with a removal instruction. Known misses remain outside catch-rate metrics. |
| 2 â€” security regressions | `04d4c55` | Added regression coverage and fixed regex cost, recognized self-mutations, shell uncertainty/upload reads, and persistent lost-observation state. Follow-up bounds/recovery tests are included in Step 3. |
| 3 â€” false positives and sensitive provenance | `4bc065e` | Listed benign commands and ordinary MCP-supplied source reads allow; sensitive reuse still asks. Unknown status is reported as not found, and read-only CLI/plugin status/explain avoid approval. |
| 4 â€” docs | `418387f` | Qualified security claims, reordered binary setup, corrected stale references, and recorded deferred integration gaps. |
| 5 â€” credential fixture hygiene | `519273f` | Fake credentials are constructed at runtime; a source regression guards complete credential patterns. Dispatcher fuzz state is isolated from operator files. |

## Regressions and evidence

Tests were added and observed failing before the associated fixes. The original
long-regex decision took about 917 ms in a direct rules regression. The final
loaded-policy regression asserts ask in under 500 ms, including under `-race`;
it passed. This is a regression bound, not a general hook-latency benchmark.

- [Security rules regressions](../internal/rules/stabilization_test.go): in-place
  sed/perl/awk edits, writes after cd, launcher/binary writes, recognized renamed
  mutation signatures, unresolved globs/braces/wrappers, and curl upload files.
- [Hook regressions](../internal/hooks/stabilization_test.go): oversized/malformed
  post input, internal failures/panic/deadline, persisted degradation, retained
  taint under configured retention, MCP source reads, and loaded regex cost.
- [Friction/provenance tests](../internal/rules/friction_test.go): the requested
  rg/curl/nc/printf/git cases, direct and plugin status/explain, and sensitive
  egress/secret/protected-write/executable reuse.
- [CLI state tests](../cmd/taintwatch/stabilization_unix_test.go): unknown sessions
  and persisted degraded state in status/explain even without an audit append.
- [Eval tests](../internal/eval/run_test.go): expected failures, unexpected passes,
  gate counts, and rendering instructions. Attack-18 and attack-20 remain TW009
  asks; their stale labels were removed with explicit maintainer approval.
- [Credential source regression](../internal/audit/source_fixtures_test.go) and
  [compiled-binary privacy tests](../internal/hookio/hardening_unix_test.go): runtime
  fake credentials, omission/redaction, private modes, rotation, and hostile IDs.

The expanded corpus contains 74 scenarios (35 attack, 39 benign), 164 hook events
and 88 scored expectations. Results are synthetic maintainer-authored controls,
not real-world coverage or an independent benchmark.

## Final command outputs

| Command | Result | Full output |
| --- | --- | --- |
| `make lint test` | PASS, exit 0 | [lint/test](measurements/stabilization/lint-test.txt) |
| `go test -race ./...` | PASS, exit 0 | [race](measurements/stabilization/race.txt) |
| `taintwatch eval run` | PASS, exit 0; 34/34 eligible attacks, 0 benign asks, 1 expected miss | [eval](measurements/stabilization/eval.txt) |
| `make fuzz FUZZTIME=30s` | PASS, all 14 targets | [product fuzz](measurements/stabilization/fuzz.txt) |
| Spike `FuzzCapture`, 30 seconds | PASS | [spike fuzz](measurements/stabilization/spike-fuzz.txt) |

Fuzz commands use two workers. The additional nested-module target was run with:

```sh
(cd spike && go test -run='^$' -fuzz=FuzzCapture -fuzztime=30s -parallel=2)
```

[Environment](measurements/stabilization/environment.txt),
[corpus validation](measurements/stabilization/eval-validate.txt),
[JSON report](measurements/stabilization/eval.json), and
[documentation checks](measurements/stabilization/doc-checks.txt) are also retained.


The original benign-13 allow expectation was preserved. Attack-19 remains the
one declared harmful-step miss; it is visible and excluded from the catch rate.
The full generated report and reproducible command are in [EVAL.md](EVAL.md).
Changed-document checks verified 78 local links with exact filename case; external
link freshness and a live Claude install were not part of that check.

## Remaining and unverified

Explicitly deferred in [LIMITATIONS.md](LIMITATIONS.md): generic MCP action
adapters, trusted-MCP provenance, launcher relative-XDG cache handling and selected
executable exit handling, and Bash dependency-path reads not tainting on path
alone. General shell interpretation, renamed helpers without recognized
signatures, transformed values, and allowlisted-host ownership remain best-effort
gaps. Retention can remove inactive tainted/degraded state; successful results do
not clear it, and storage failure can prevent a degraded marker from persisting.

This stabilization run did not repeat the older large-state latency benchmark,
staticcheck, or vulnerability scans; dated evidence remains in
[HARDENING.md](HARDENING.md). Its earlier latency misses still need a release
policy decision or further optimization. Live Claude captures, an exact minimum
compatible version, macOS and Go 1.22 CI verification, a real demo GIF, and the
maintainer's SECURITY.md contact remain release checks.

These commits were not pushed by this task. Local gates passing does not certify
GitHub main is green. The Dependabot follow-up remains deferred until main's
GitHub CI is green, as requested; no claim about that PR's current result is made.