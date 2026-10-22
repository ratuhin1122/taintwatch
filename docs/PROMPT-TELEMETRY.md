# Prompt telemetry

The plugin and standalone installer wire `UserPromptSubmit` to
`taintwatch hook prompt`, without a matcher. Existing standalone installations
can rerun `taintwatch install` after upgrading; unrelated hooks are preserved.
`taintwatch explain` shows prompt observations and `--json` includes the counters.
Disable this optional observation through Claude's hook controls if unwanted.

The handler reuses `internal/detect/hidden` and runs `internal/detect/pasted`.
Both examine at most the first 1 MiB; the envelope retains the 8 MiB hook cap.
Hidden-text findings follow [HIDDEN-CONTENT.md](HIDDEN-CONTENT.md). Pasted hints
contain counters only:

- `fenced_blocks`: Markdown-like opening fences with three or more backticks or
  tildes and up to three leading spaces. Matching closing fences do not add a
  block; an unclosed opening still counts as a hint.
- `log_lines`: nonblank lines beginning with common severity, date/time, stack
  frame, or Go source-location shapes.
- `long_log`: at least 4 KiB scanned, at least 40 log-like lines, and at least half
  of the nonblank lines matching those shapes.
- `bytes_scanned` and `truncated`: bounds for interpreting these counters.

This is a heuristic, not a content boundary detector. A single prompt blob cannot
reliably separate the user's instruction from pasted content. Long authored text
can look pasted, and a real paste can miss every hint. Optional pasted-content
wrappers described by Claude Code are not treated as authenticated provenance.
No prompt rewriting, context injection, taint updates, approval changes, policy
edits, or rule evaluation takes place. Only audit storage and its usual rotation
can change. Session files are never created, touched, loaded, or cleared by this
handler. Audit metadata marks the observation `prompt.telemetry` / `observe`,
not a permission decision. No prompt bodies or log lines are stored.

On a normal hook invocation **stdout is empty and exit status is always 0**,
including malformed/oversized input, bad policy, inaccessible storage, recovered
panic, and timeout. Unlike enforcement hooks, a configured closed fail mode
cannot make this observer block or add context. Fixed diagnostics may go to
stderr; they contain no prompt text. The process watchdog bounds execution to
two seconds. A failed/timed-out observation can lose telemetry. `--help` is a
CLI help invocation, not a normal hook invocation.

The [official hook reference](https://code.claude.com/docs/en/hooks#userpromptsubmit-decision-control)
documents that prompt-hook stdout can add context and that exit 2 can reject a
prompt. Both output channels are deliberately unused. Live delivery of the
documented envelope remains unverified pending real captures.
