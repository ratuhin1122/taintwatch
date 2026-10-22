# Limitations

- Pre-tool enforcement implements layered policy, action overrides and
  self-protection. Explicit clear is implemented; native approvals are not cached
  because no authenticated per-ask signal is documented. See [approvals.md](approvals.md).
- Real Claude Code payloads and exact product transport structs remain unconfirmed.
- Session-level taint tracking is coarse; content classifiers are telemetry only.
- Product platforms: macOS/Linux amd64/arm64. Windows is best-effort through WSL.
- Hook performance is not yet measured; the eventual typical target is under 50 ms.
- State writes serialize through a bounded store lock and scan for expiry. State
  must live on a local Unix filesystem; native Windows storage is unsupported.
- Shell analysis is best-effort. Bash syntax is parsed, but variables, aliases,
  functions, executable contents, sourced scripts, interpreter programs, wrapper
  option dialects and runtime filesystem behavior are not fully resolved. Tainted
  unresolved expansions ask; this is not a shell sandbox. Literal shell scripts
  are inspected to a bounded depth. Heredoc bodies are retained, not generally
  interpreted as executable programs. TW007 follows connected AST flows rather
  than associating unrelated pipeline groups. Its tracked shell-variable map is
  capped at 128 names, expanded literals at 64 KiB, traversal at depth 32 / 20,000
  visits, and foreign-expression scanning at 16,000 tokens. Unsupported/exhausted
  analyses report `Incomplete`; absence of a TW007 match is not proof of safety.
- TW007's Python/Node inline-code scanner is not a full language parser. Dynamic
  imports/aliases, reflection, template-string expressions, function definitions
  and invocation, arbitrary filters/commands, cross-command file write/execute
  sequences, descriptor aliases and control-flow joins are not fully modeled.
  False-positive rates on a real benign corpus will be measured in M3; unit
  near-misses are not a substitute for that measurement.
- File access extractors cannot enumerate every program's reads and writes.
  Symlink targets can change after checking. Git remotes, tracked status, SSH
  aliases, HTTP redirects and DNS are not looked up. Unknown network destinations
  ask; package manifests and truncate targets receive conservative treatment.
- Closed mode in PostToolUse is advisory only; a completed call cannot be undone.
- Audit rotation discards older history; ask counts cover retained logs only.
  Redaction is best-effort; tool contents are omitted. See [AUDIT.md](AUDIT.md).
