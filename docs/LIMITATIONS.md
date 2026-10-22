# Limitations

Taintwatch adds policy checks around observable Claude Code tool actions. It does
not establish that a session, command, document or destination is safe.

- **Synthetic evaluation.** The corpus is synthetic and written by the
  maintainers. Results show behavior on known patterns, not real-world coverage,
  attack prevalence, or a general false-positive rate. It is not an independent
  or held-out benchmark. Measured tables, date, build version, corpus hashes and
  the reproduction command are in [EVAL.md](EVAL.md#measured-results). No
  comparative results against other projects have been measured here.
- **Coarse session taint.** Untrusted content taints the session rather than
  tracking which instruction or value caused each later action. Unrelated work
  can therefore ask for confirmation. Individually harmless actions can combine
  into harmful behavior that the rules do not infer. Clear is an explicit user
  action; a reassuring tool response does not automatically clear taint.
  Retention may remove old session state, so history is not permanent.
- **Shell analysis is best-effort.** Parsing Bash syntax does not resolve all
  variables, aliases, functions, sourced files, executable contents, interpreter
  programs, wrapper options or runtime filesystem behavior. Heredoc bodies are
  not generally interpreted as executable programs. File access extractors cannot
  enumerate every program's reads and writes. Tainted unresolved expansions ask,
  but an absence of findings is not proof of safety. This is not a shell sandbox.
  Decode-and-run analysis has bounded traversal and literal expansion; its
  Python/Node scanner is not a full language parser. Dynamic imports, reflection,
  cross-command write/execute flows and control-flow joins can evade analysis.
- **Value provenance gaps.** TW009 matches exact indicators and a bounded set of
  encoded forms. Paraphrased, split or otherwise transformed values, nested
  encodings, unsupported formats and data beyond the retention/scan budgets can
  evade it. Matches can also cause benign asks, including source files named by
  an MCP search. Base64 interior cores can collide. This does not recover semantic
  equivalence or infer an application's eventual behavior. See
  [VALUEMATCH.md](VALUEMATCH.md).
- **Allowlisted destinations can exfiltrate.** Host trust does not establish
  repository ownership, account identity, URL-path trust or upload intent.
  Attacker-controlled resources on an allowed host can evade egress checks unless
  another rule catches the action. Git remotes, SSH aliases, HTTP redirects and
  DNS are not resolved. Symlink targets can change after a path check.
- **Confirmation depends on the user.** A user who approves everything can
  authorize the harmful actions that an ask is intended to interrupt. An ask is
  not containment. Native approvals are not cached because no authenticated
  per-ask approval signal has been verified; see [approvals.md](approvals.md).
  Policy exceptions and explicit clear can also weaken future protection.
- **Hook visibility and compatibility.** Hooks see only the tool events Claude
  Code routes through the configured hooks. Actions outside that route, disabled
  or miswired hooks, and tools whose behavior the rules do not understand are
  coverage gaps. Changes to Claude Code event delivery, payloads, tool names,
  decision handling or exit-code semantics can break these assumptions. Official
  formats are recorded in [ASSUMPTIONS.md](ASSUMPTIONS.md); real sanitized
  Read/WebFetch/Bash/MCP captures remain pending. Synthetic documented-envelope
  tests do not verify live hook delivery or future compatibility.
- **Errors and completed calls.** Open fail mode can let an action continue when
  enforcement fails; closed mode asks for confirmation and still depends on the
  user. PostToolUse runs after completion and cannot undo the tool call. A
  deadline or successful hook exit is not evidence that every check completed.
- **Content heuristics are telemetry.** Hidden-text detection uses bounded
  presentation heuristics, not rendered layout or complete Unicode/Markdown
  analysis. It never changes a decision by itself. A single prompt blob cannot
  reliably separate the user's instruction from pasted content; prompt telemetry
  never blocks, rewrites the prompt, changes taint or grants approval. See
  [HIDDEN-CONTENT.md](HIDDEN-CONTENT.md) and
  [PROMPT-TELEMETRY.md](PROMPT-TELEMETRY.md).
- **Encoded-content hints are also telemetry.** Only one level of bounded
  contiguous base64/hex is decoded. Short, wrapped, nested, encrypted, binary or
  oversized data and known-shape exclusions can hide instructions. Lexical hints
  can flag harmless encoded discussions. They never modify decisions, model
  context or value provenance. The benign corpus is not a labeled collection of
  encoded negative controls, so its response-level flag rate is weak evidence
  about encoded-data false positives. See [ENCODED-CONTENT.md](ENCODED-CONTENT.md) and the measured
  counters in [EVAL.md](EVAL.md#measured-results).
- **Storage and privacy.** Product storage targets local Unix filesystems on
  Linux/macOS; native Windows storage is unsupported, so use WSL. Advisory locks
  and atomic replacement are not a universal crash-durability guarantee. Audit
  rotation and retention discard history; counts describe retained records.
  Secret redaction is best-effort and logs are not authenticated or tamper-proof.
  Tool bodies are omitted. See [HARDENING.md](HARDENING.md) for measured hook
  latency and the exact fixture; one WSL host is not a platform latency guarantee.
  Unknown secrets in free-form metadata or operator clear reasons can escape
  pattern-based redaction. Do not paste secrets into those reasons. Stored taint
  indicators and their encoded variants are private state, not redacted audit data.
  Managed file endpoints reject symlinks and hard links; parent-directory races
  and another process running as the same user remain outside the boundary.
  Give each state home its own audit path: separate homes do not share a rotation
  lock merely because they point at the same custom log file.
  See [AUDIT.md](AUDIT.md).
- **Trust exceptions and deadlines.** MCP trusted-server exceptions currently
  match names, not the newer hook provenance source; keep the list empty unless
  server names and their configuration are controlled. The Go hook deadline starts
  after binary entry. Launcher filesystem checks and OS scheduling are outside
  that deadline; it is not a universal wall-clock guarantee.
- **Audit replay cannot recover omitted facts.** Replay freezes historical taint
  and complete rule-match snapshots to compare rule actions/enabled flags. Legacy
  records and changed matching/source criteria are unreplayable; it does not
  reconstruct inputs or simulate downstream workflow changes. Missing information
  is reported as unreplayable, never unchanged. See [REPLAY.md](REPLAY.md).
