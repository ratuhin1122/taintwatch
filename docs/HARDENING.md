# Pre-v1.0 hardening report

Date: 2026-10-23. Reviewed base: `c2a0a59`, plus the changes accompanying this
report. Test host: Linux amd64 under WSL2 on Windows; Go 1.27.3, CGO enabled.
This is a local engineering review, not an independent security audit.

**Recommendation: publish a v0.9.0 preview before v1.0.** The eval gate has an
unresolved benign expectation failure, three latency medians exceed the target,
real Claude session captures are pending, and the complete minimum compatible
Claude Code version is not established.
See [the release checklist](V1-RELEASE-CHECKLIST.md).

## Checks and reproduction

Run on a supported Linux/macOS host with Go, a C compiler, Python 3, Staticcheck
and govulncheck available. All hook inputs in the automated tests are synthetic
documented envelopes, not newly collected live Claude payloads.

```sh
go test -race -count=1 -timeout=8m ./...
go vet ./...
staticcheck ./...
govulncheck ./...
make fuzz FUZZTIME=60s FUZZWORKERS=2
go build -trimpath -ldflags '-X main.version=m4.6' -o /tmp/taintwatch ./cmd/taintwatch
/tmp/taintwatch eval run --markdown
```

| Check | Result |
| --- | --- |
| Full root module `-race`, uncached | PASS; compiled-binary privacy and multiprocess state tests included |
| Large-directory retention regression under `-race` | PASS; 300 mixed-age files, active/boundary/foreign files preserved |
| `go vet ./...` | PASS |
| Staticcheck 2026.2.2 | PASS; three unused adapters removed |
| 14 fuzz targets, 60 seconds each, two workers | PASS; optimized valuematch rerun for another full minute |
| Govulncheck v1.9.0 | PASS: “No vulnerabilities found.” |
| Shellcheck 0.11.0 / throwaway spike `-race` / release-helper tests | PASS |
| Installed Claude 2.1.175 plugin and marketplace manifest validation | PASS |
| Eval expectation gate | FAIL: one unexpected benign TW009 ask |

Race output, fuzz target status, eval output, vulnerability output and raw latency
samples are retained in [measurements/m46/](measurements/m46/). Fuzz elapsed values
include compile/setup overhead; each target used `-fuzztime=60s`. Targets cover
encoded, hidden, pasted and decode/run detectors; hook decoding; shell parsing;
taint command words; policy; eval; replay; dispatcher; state JSON/IDs; valuematch.
The final large-directory regression was added after the full suite and rerun
under `-race` for the affected state package.

Govulncheck v1.1.4 initially panicked in its old SSA builder under Go 1.27.3.
That was a scanner failure, not a clean scan. The successful replacement is
v1.9.0 and CI's advisory scanner pin was updated accordingly. Scanner results
are time-, database- and toolchain-specific; macOS/arm64 and Go 1.22 were not
rerun on this local WSL host.

The eval command exits **1**: 50 scenarios, 20 attacks, 30 benign sessions,
116 hook events and 64 assertions. Eligible attack scenarios are guarded 17/17;
two of three declared known misses are now guarded and one remains an expected
harmful-step failure. There is one unexpected benign ask in 34 benign tool calls
(0.0333 asks/session; 2.9412 asks/100 calls). `benign-13-mcp-code-read/step-02`
expects allow but receives TW009 ask for a path supplied by MCP. These synthetic
results describe known patterns, not real-world attack coverage. Expectations
were not weakened to hide the failure.

## Performance method and changes

The reproducible driver is [benchmark-hooks.py](../scripts/benchmark-hooks.py).
It invokes fresh processes, validates their decisions, includes startup, stdin,
storage and completion, and excludes fixture resets. It uses user and project
policy layers, 10,001 sessions, 20 retained taint events (about 184 KiB active
session), a 32 MiB JSONL log and a 32 KiB WebFetch response. Storage is a private
local Linux filesystem; each case has ten warmups and 200 measured samples.
The launcher is copied to that filesystem to avoid charging Windows-mounted
script access only to one measurement. p99 is the nearest-rank sample percentile.
These are warm filesystem measurements with fresh hook processes, not cold boot,
release-download or bootstrap-cache checksum timings. Launcher measurements use
a bundled executable; a cached downloaded binary has an additional hash check.

```sh
python3 scripts/benchmark-hooks.py --binary /tmp/taintwatch \
  --launcher bin/taintwatch-launcher --sessions 10000 --audit-mib 32 \
  --samples 200 --work-dir /var/tmp --output /tmp/taintwatch-latency.json
```

Final fresh-process results (milliseconds; lower is better):

| Hook case | Before median | Before p99 | Final median | Final p99 | Median ≤50 ms |
| --- | ---: | ---: | ---: | ---: | --- |
| Pre: benign Bash | 67.886 | 186.468 | 42.403 | 88.931 | Yes |
| Pre: secret Read ask | 61.144 | 144.568 | 57.876 | 86.639 | **No** |
| Post: 32 KiB web response | 185.573 | 355.763 | 147.766 | 255.226 | **No** |
| Prompt: pasted log | 23.433 | 71.371 | 22.665 | 55.894 | Yes |
| Bundled launcher → benign pre | 123.933 | 185.817 | 73.141 | 131.653 | **No** |

**The 50 ms median acceptance target is not met.** These fixes improve the
measured paths but do not make this tree v1.0-ready. A standalone retention
benchmark takes 49.377 ms/op for 10,000 files on this host, before startup and
durable session/audit writes. Syncs and exhaustive retention were retained.
Further work needs filesystem/IO profiling and an explicit decision about any
amortized cleanup design; this report does not silently substitute a smaller
fixture, a memory filesystem or weaker persistence.

Raw before/final JSON includes all 200 samples per case, hashes and fixture
metadata. `latency-trial-four.json` and `latency-trial-sixteen.json` retain the
intermediate trials: sixteen workers showed no convincing end-to-end benefit,
so four were retained. Host variance is visible (one earlier secret-read median
was 44.883 ms); do not interpret a single run as a latency guarantee or a precise
causal speedup. Launcher platform detection now uses one `uname -sm` invocation.

```sh
GOMAXPROCS=8 TMPDIR=/var/tmp go test ./internal/state -run '^$' \
  -bench BenchmarkRetentionLargeDirectory -benchtime=2s -count=1
```

Profiling identified map allocation during provenance matcher compilation and
serial retention metadata lookups. The matcher now stores bounded byte edges
in flat slices. Cleanup still checks all eligible session files on every write,
under the same store lock, with four bounded metadata workers for large dirs.
No retention interval, rule, size cap or fail mode was relaxed.

The retained-indicator microbenchmark fell from 22.412 to 3.449 ms/op and from
24,409 to 15 allocations/op on this host. Those exploratory runs overlapped other
checks and explain the optimization; use the end-to-end measurements for hook
latency. Reproduce the microbenchmark with:

```sh
go test ./internal/valuematch -run '^$' -bench BenchmarkCompileRetainedIndicators -benchmem
```

## Filesystem, injection and privacy review

| Area reviewed | Confirmed behavior / remaining boundary |
| --- | --- |
| State paths and IDs | Only bounded ASCII IDs are filenames; other IDs become SHA-256 names. Hostile `../../` IDs cannot escape. Managed directories are 0700, files 0600. |
| Managed endpoints | Unix opens reject symlinks, nonregular files and now hard-link aliases before chmod/write. New tests cover session, lock, audit and rotation names, preserving the outside victim's bytes/mode. Parent-directory replacement and same-user hostile processes are not sandboxed. |
| State writes / cleanup | Persistent advisory lock, private temp, file sync, atomic rename and directory sync. Retention validates filenames and skips the active session. Bounded concurrent cleanup holds the store lock until workers finish. |
| Audit / rotation | Bounded JSON records, escaped newlines/control characters, one append write, sync, partial-tail repair and private rotation files. Separate homes must not share one custom audit path: their locks differ. |
| Policy loading / editing | Bounded strict YAML, no-follow regular input, anti-loosening project layer; user-only confirmed edits, conflict detection, private backups and atomic replacement. Configured homes/parents are trusted operator inputs. |
| Installer / doctor | Owned hook merge/receipt/backup and shell-quoted executable path; unrelated hooks preserved. Doctor invokes a fixed version check with context. Concurrent unrelated settings editors remain outside its cooperating lock. |
| Replay / eval | Bounded regular-file input and isolated eval state; tool command strings are parsed, never executed. Same-user path replacement is not an adversarial filesystem sandbox. |
| Hook input | JSON decoding is bounded; transcript/scratchpad paths are not opened as instructions. Unknown fields are ignored. Shell syntax is analyzed without execution. |
| Launcher | Checksums are verified before downloaded execution; bootstrap is explicit. Release checksums are not independently authenticated by automatic cosign verification. Local plugin binaries and PATH are trusted. Launcher time precedes the Go watchdog. |
| Audit privacy | Recognized secret shapes are redacted; bodies/full arguments are omitted. Detector excerpts are safe structural hints. Arbitrary unknown secrets in metadata or operator reasons can remain. Indicators/variants in private state are not redacted. |

`TestBinaryAuditSecretsAndModes` builds the actual CLI, uses a hostile session ID,
feeds AWS/GitHub/bearer/password/private-key canaries through web content and Bash
arguments, exercises prompt telemetry and explicit clear, and inspects retained
logs after each invocation and across rotation. No tested canary reaches those
audit logs; directories/files are checked as 0700/0600. This is evidence for the
tested paths, not a proof that every imaginable secret is recognized. In
particular, an unlabeled opaque secret in an explicit clear reason is not
reliably redacted; never put secrets in free-form metadata.

## Claude Code and documentation review

Official hooks, plugin manifest, marketplace reference and upstream changelog
were reread. Upstream's latest entry was **2.1.308**; the installed CLI is
**2.1.175**. Existing output contracts remain documented. New provenance and
optional output features are not claimed as implemented. See the dated entries
and source URLs in [ASSUMPTIONS.md](ASSUMPTIONS.md).

Live captures and a minimum version remain unverified. Current MCP trusted-server
exceptions match names rather than provenance source, with no trusted servers by
default. SessionStart is still a stub. README and LIMITATIONS now distinguish
synthetic evaluation, pattern-based redaction, private indicator storage, the
Go-only watchdog boundary, same-user tampering and name-based trust exceptions.
An ask still depends on the user's decision; this does not replace permissions
or sandboxing.
