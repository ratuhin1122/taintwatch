# Replay historical decisions

```sh
taintwatch replay --log audit.jsonl --policy new.yaml
```

Replay is read-only: it does not activate the candidate, execute tools, read the
original files, or change session state. The candidate is strictly validated and
applied over built-in defaults only; ambient user/project policies and environment
overrides are not loaded. Include all relevant custom settings in the candidate.
Use the policy schema's `replace:` / `append:` list syntax. `policy show` is a
human-readable reference with origins, not an importable candidate file.

The report groups changes by the new winning rule; changes to allow are grouped
under the previous rule. Each row includes the log line, session, timestamp,
old/new action and old/new rule. Rule-only changes are counted separately.
Unreplayable records are listed with their cause; they are never counted as
unchanged. Non-decision events are ignored.

For example, changing `rules.TW002.action` from `ask` to `deny`, or disabling
TW003, can be evaluated from complete snapshots. Disabling a rule does not
necessarily allow the action: another matching rule may still ask or deny.

## Recorded facts and supported changes

New successful PreToolUse audit records include an optional compact snapshot:

```json
{"replay":{"version":1,"match_policy_sha256":"<64 hex characters>","matches":["TW001","TW002"]}}
```

The vector contains every matched rule, including disabled rules, using the
historical session's taint eligibility. An empty `[]` is complete; missing/null
matches are not. The digest identifies matching configuration and matcher schema.
Only rule IDs and a digest are added; commands, URLs, paths, tool bodies and full
file contents are not added to the log.

Replay freezes those historical matches and recorded taint, then applies candidate
rule actions/enabled flags with the production rule order and deny/ask/allow
precedence. It treats the candidate as replacement policy content at the original
installation's policy/state locations, rather than moving those locations.

## Limits

- Older logs contain only the chosen rule and redacted summaries. They cannot
  reveal all competing matches, so their decisions are unreplayable. Replay never
  infers tool input from reason or evidence text.
- Changes to matching/source configuration, including allowlist domains, secret
  paths, protected writes, extra match patterns, profile, MCP trust, reader
  commands, log path or retention, invalidate the fingerprint. The omitted raw
  inputs cannot be reconstructed to evaluate those changes. Equivalent lists
  with different representations/order or platform-derived defaults may also
  conservatively invalidate it.
- This is a projection of individual recorded decisions, not a simulation of a
  changed workflow. It does not propagate alternate decisions through later
  events, reconstruct source history, inspect filesystem/symlinks, reparse shell
  commands, or model Claude Code permissions or user approvals.
- Error/fail-mode outcomes, unknown state, incomplete snapshots and unsupported
  matcher versions cannot be replayed. Future matcher changes must increment the
  snapshot schema version. Changing fail mode is not an error-path simulation.
- Logs and hashes are not authenticated or tamper-proof. Results depend on the
  recorded facts being accurate. Rotation may already have discarded history.

Only the selected file's open prefix is analyzed; rotated backups are not loaded
automatically. Limits are 64 MiB per log, 100,000 records and 64 KiB per JSONL
line. Inputs must be regular non-symlink files. Malformed, oversized or truncated
logs fail without a partial report; a valid final record must end with a newline.
Concurrent appends do not extend the selected prefix.

Exit codes: 0 for a completed report (including changes or unreplayable entries),
1 for input/validation/output errors, and 2 for usage errors. Unlike hook storage,
this read-only command also runs on native Windows.
