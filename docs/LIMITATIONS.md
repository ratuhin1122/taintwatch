# Limitations

- This scaffold has no security enforcement, state persistence, or audit logging.
- Real Claude Code payloads and exact product transport structs remain unconfirmed.
- Future session-level taint tracking is coarse; content detectors are telemetry only.
- Product platforms: macOS/Linux amd64/arm64. Windows is best-effort through WSL.
- Hook performance is not yet measured; the eventual typical target is under 50 ms.
