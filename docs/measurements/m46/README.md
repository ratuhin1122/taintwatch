# M4.6 evidence

Collected 2026-10-23 on Linux amd64 / WSL2, Go 1.27.3. Interpretation and
reproduction commands are in [HARDENING.md](../../HARDENING.md).

- `race.log`: full root-module race suite; `state-launcher.log`: final affected
  packages after reverting the sixteen-worker experiment.
- `fuzz.tsv`: package, target, exit status, total elapsed seconds. Every target
  ran with `-fuzztime=60s`; elapsed includes setup/compilation. The extra final
  matcher run is in `fuzz-valuematch-final.log`.
- `govulncheck.txt`: successful v1.9.0 output, not the earlier v1.1.4 scanner crash.
- `eval.md`: actual final CLI output; its exit status is **1**, intentionally.
- `latency-before.json`: before matcher/cleanup/platform-detection performance
  changes. `latency-after.json`: final four-worker cleanup and one-call launcher.
- `latency-trial-four.json`: intermediate four-worker build with the old
  two-call launcher. `latency-trial-sixteen.json`: sixteen-worker experiment
  with the one-call launcher. All samples are retained to expose run variance.
- `retention-benchmark.txt`: final isolated 10,000-file cleanup microbenchmark.

Latency JSON stores all samples in milliseconds, binary/launcher hashes and
fixture metadata. It contains only synthetic inputs/measurements. Source bodies,
credentials and actual user sessions were not collected. No macOS/arm64 or
live Claude hook-delivery result is implied.
