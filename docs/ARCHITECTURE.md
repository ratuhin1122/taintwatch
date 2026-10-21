# Architecture

The scaffold separates the command dispatcher from packages for hook transport,
policy, state, source classification, shell parsing, rules, audit, explanations,
telemetry detectors, tainted-value matching, installation, and evaluation.

Only `internal/hookio` knows Claude Code payload formats. The post command uses
`taint` source classification, `state` snapshots and `audit` records. The pre
command uses `shellparse` and the data table in `rules`. Prompt and session-start
remain stubs. `spike/` is an independent throwaway module, excluded from root
Go package discovery. The root depends on mvdan.cc/sh/v3/syntax.

`internal/state` implements protected session snapshots, bounded Unix advisory
locking, and lazy expiration. Its JSON is a private storage format, not a Claude
Code hook payload. The store also protects atomic JSONL audit writes. See
[STATE.md](STATE.md) and [TAINT.md](TAINT.md) for storage and post-hook behavior.

The planned boundary is policy plus session state plus attempted action. Content
detection is telemetry only. This is defense-in-depth, not a prompt-injection
solution; coarse session-level taint loses fine-grained provenance.
