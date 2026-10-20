# Limitations

- This scaffold has no live security enforcement or audit logging. Session state
  storage is implemented, but the CLI hook handlers do not yet use it.
- Real Claude Code payloads and exact product transport structs remain unconfirmed.
- Future session-level taint tracking is coarse; content detectors are telemetry only.
- Product platforms: macOS/Linux amd64/arm64. Windows is best-effort through WSL.
- Hook performance is not yet measured; the eventual typical target is under 50 ms.
- State writes serialize through a bounded store lock and scan for expiry. State
  must live on a local Unix filesystem; native Windows storage is unsupported.
