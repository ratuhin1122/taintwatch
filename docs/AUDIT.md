# Audit history and inspection

Hooks append compact JSONL at `<state home>/audit.jsonl` (0600 inside a 0700
directory). A shared advisory lock serializes rotation and each single `O_APPEND`
write, including concurrent processes. Records are fsynced; short writes attempt
rollback and report an error. This is not a promise of crash-proof atomicity on
every filesystem. Incomplete trailing records are reported, not overwritten.

The default threshold is 10 MiB, retaining three backups (`audit.jsonl.1` through
`.3`) in addition to the active file. Rotation happens before a record would cross
the threshold. A record larger than a custom threshold occupies its own file;
individual records remain capped at 64 KiB. Configure store options
`AuditMaxBytes`/`AuditKeep`, or set `TAINTWATCH_AUDIT_MAX_BYTES` and
`TAINTWATCH_AUDIT_KEEP` (1–20 backups). Explicit nonzero options override environment
values. YAML log.path/log.rotation and state retention settings are documented in
[policy.md](policy.md). Rotation discards the oldest
backup, so ask counts describe retained history, not lifetime totals.

Metadata redaction runs before JSON serialization: AWS access IDs (AKIA/ASIA),
GitHub token forms, private-key blocks (including incomplete blocks), bearer
credentials, API tokens and assignments to names containing password, secret,
token or key become `[REDACTED:<type>]`. Named assignments are redacted even when
low entropy, conservatively. Tool input/result bodies and full file contents are
not logged. Metadata fields are truncated after redaction. Patterns are best-effort,
not universal secret detection; input omission is the primary defense. Readers
also redact older metadata before displaying it. Old files are not retroactively
rewritten. Terminal control characters are escaped in text output.

Untrusted post-hook responses can add a `hidden` report: scanned byte count,
truncation status, and aggregated presentation hints (type/count/short excerpt).
Excerpts use codepoints or structural/style hints, never hidden bodies, whole
words, or link targets. They receive the same audit redaction and visible-control
rendering. These hints appear in `explain` and never change decisions. See
[HIDDEN-CONTENT.md](HIDDEN-CONTENT.md) for coverage and limits.

UserPromptSubmit writes `decision: "observe"` and `rule: "prompt.telemetry"`.
Its `hidden` report covers presentation hints; `pasted` contains fenced-block
and log-like-line counters plus a long-log flag and prefix bounds. These records
do not imply an allow/ask decision or a session taint snapshot. They never change
session files or approval counts. Prompt contents are omitted. See
[PROMPT-TELEMETRY.md](PROMPT-TELEMETRY.md).

```sh
taintwatch explain
taintwatch explain --session ID --last 20
taintwatch explain --session ID --last 20 --json
taintwatch status
taintwatch status --session ID
```

Explain defaults to the session with the newest retained audit timestamp and
shows ten decisions (1–1000 configurable), newest first in text. JSON includes
the session, recent records in chronological order and retained ask count.
Reasons, rule IDs, historical taint/source information and suggested next steps
are shown. Approval remains Claude Code's one-time approval UI. Policy allowlist
overrides are available; a clear-taint CLI remains future work.

Status uses current persisted state for that session. Missing state is unknown
when selecting from audit history. An explicitly requested missing session follows
the state API's clean-session semantics. Without audit history, status falls back
to the most recently updated saved session. Expiry and rotation can remove one
side of this information. Status reports the files loaded for the current cwd.
Inspection never refreshes session expiry. Audit reads capture open
handles and file sizes under the lock, then scan those prefixes outside the lock;
concurrent append and rotation cannot extend those snapshots. Default-session
selection and history collection are separate snapshots.

Malformed history/state or unavailable storage returns exit 1; invalid flags/counts
return exit 2; success/help returns exit 0. Native Windows storage remains
unsupported; use WSL as documented for the project.
