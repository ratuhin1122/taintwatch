# Limitations

- Pre-tool enforcement implements layered policy, action overrides and
  self-protection. Approval reuse and a clear-taint CLI remain future work.
- Real Claude Code payloads and exact product transport structs remain unconfirmed.
- Future session-level taint tracking is coarse; content detectors are telemetry only.
- Product platforms: macOS/Linux amd64/arm64. Windows is best-effort through WSL.
- Hook performance is not yet measured; the eventual typical target is under 50 ms.
- State writes serialize through a bounded store lock and scan for expiry. State
  must live on a local Unix filesystem; native Windows storage is unsupported.
- Shell analysis is best-effort. Bash syntax is parsed, but variables, aliases,
  functions, executable contents, sourced scripts, interpreter programs, wrapper
  option dialects and runtime filesystem behavior are not fully resolved. Tainted
  unresolved expansions ask; this is not a shell sandbox. Literal shell scripts
  are inspected to a bounded depth. Heredoc bodies are retained, not generally
  interpreted as executable programs. Pipeline risk matching is conservative and
  may associate commands across separate pipeline groups.
- File access extractors cannot enumerate every program's reads and writes.
  Symlink targets can change after checking. Git remotes, tracked status, SSH
  aliases, HTTP redirects and DNS are not looked up. Unknown network destinations
  ask; package manifests and truncate targets receive conservative treatment.
- Closed mode in PostToolUse is advisory only; a completed call cannot be undone.
- Audit rotation discards older history; ask counts cover retained logs only.
  Redaction is best-effort; tool contents are omitted. See [AUDIT.md](AUDIT.md).
