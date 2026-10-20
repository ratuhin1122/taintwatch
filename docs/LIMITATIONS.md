# Limitations

- The post hook tracks source taint, adds context, and writes minimal audit logs.
  Pre-tool action enforcement and self-protection rules are not implemented yet.
- Real Claude Code payloads and exact product transport structs remain unconfirmed.
- Future session-level taint tracking is coarse; content detectors are telemetry only.
- Product platforms: macOS/Linux amd64/arm64. Windows is best-effort through WSL.
- Hook performance is not yet measured; the eventual typical target is under 50 ms.
- State writes serialize through a bounded store lock and scan for expiry. State
  must live on a local Unix filesystem; native Windows storage is unsupported.
- Shell reader recognition is provisional and can miss expansion, aliases, nested
  shells, and other complex syntax until shellparse is implemented.
- Closed mode in PostToolUse is advisory only; a completed call cannot be undone.
- Audit append currently rewrites a capped 16 MiB log; rotation is not implemented.
