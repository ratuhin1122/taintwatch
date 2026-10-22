# Session state

`state.New(state.Options{})` resolves the state home in this order:

1. `TAINTWATCH_HOME`, if set (relative paths are made absolute).
2. `$XDG_STATE_HOME/taintwatch`, if XDG_STATE_HOME is absolute.
3. `~/.local/state/taintwatch` on both Linux and macOS.

`Options.Home` overrides the environment. Relative XDG_STATE_HOME is ignored.
The managed home and `sessions/` directory are 0700. Session files and `.lock`
are 0600; existing managed endpoints with wider permissions are tightened.
Use a local filesystem with Unix ownership, permissions, flock, and atomic rename
semantics. Native Windows returns `ErrUnsupportedPlatform`; use WSL with state
on the Linux filesystem, not under `/mnt/c`.

## Files and IDs

One JSON file lives at `sessions/<sanitized-id>.json`. An ID with 1..64 ASCII
letters, digits, `_`, or `-` is used literally. Every other ID, including empty,
is encoded as `sha256-` plus a full 64-character lowercase SHA-256 digest. The
71-character hash namespace cannot collide with a permitted literal ID.
The original untrusted ID remains in the JSON and is checked when loading.
It is never passed to a shell or used as a path component without sanitizing.

Managed directory endpoints and files must not be symlinks. File opens use
`O_NOFOLLOW` and `O_NONBLOCK`, and require regular files, so FIFOs are rejected
without waiting for a writer. Ancestor directories are operator-controlled;
these protections do not isolate a malicious process running as the same OS user.
This is storage protection, not authentication of an agent or a user.

## Operations

Each operation takes a session ID and returns a Session plus an error:

- `Load(id)`: missing file returns a clean, unsaved session with timestamps set
  to the current UTC time. Does not create JSON, touch mtime, or run cleanup.
  Corrupt, mismatched, oversized, or inconsistent state returns an error.
- `MarkTainted(id, event)`: sets taint and appends time, tool, source (`web`, `mcp`,
  `bash`, `read`, or configured `tool`), reason, and extracted value strings. Zero event time defaults
  to now. Values remain available for the future valuematch layer.
- `AddApproval(id, approval)`: appends time, optional tool/rule ID, reason and who.
  Does not clear taint or grant tool permissions itself.
- `Clear(id, reason, who)`: clears taint, events and approvals. Preserves creation
  time and records the latest clear's reason, who and UTC time in `last_clear`.
- `Touch(id)`: persists or refreshes a session without changing its taint.

Reasons must be 1..512 bytes. Approvals and clears require `who`; these strings
are attribution supplied by the caller, not proof of authorization. Agent-driven
clears must still require approval in the future pre-hook/rule layer. No clear CLI
is exposed. M1.4 uses this store from the post hook. JSON snapshots are limited to 16 MiB,
and oversized updates fail instead of producing unreadable state.

## Locking, durability, and cleanup

One persistent `home/.lock` coordinates **all** cooperating readers, writers,
and cleanup with exclusive `syscall.Flock`. It is never removed during cleanup:
unlinking a lock file could leave different processes locking different inodes.
Nonblocking attempts poll for at most `Options.LockTimeout` (default 250 ms),
then return `ErrLockTimeout`. Storage syscalls themselves depend on filesystem
responsiveness; the hook entry point must also impose an overall process deadline.

A write holds that lock across load, modification, lazy cleanup, and publication.
Publication uses a 0600 temporary file in `sessions/`, syncs and closes it, renames
it over the destination, then syncs the directory. Readers outside the lock also
see complete old or new snapshots. No append or in-place JSON rewrite is used.
An error after rename (such as directory-sync failure) can occur after publication;
callers should inspect state before retrying a non-idempotent append operation.

Every successful mutation checks for expired regular session `.json` files using
their mtime. Strictly older than `Options.Retention` is expired (default seven
days); zero selects the default and negative durations are invalid. The active
session is preserved and refreshed, even if it was previously old. Unknown names,
directories, symlinks and temporary files are skipped. Cleanup runs under the same
lock, so it cannot race a cooperating process's refresh. Cleanup errors abort the
pending update; already removed expired files are not restored.

Cleanup scans the directory on every mutation and the store lock serializes
different sessions. Latency and scaling are not yet measured. Session-level
taint is coarse defense-in-depth, not a solution to prompt injection. Content
detectors remain telemetry only and do not independently select blocking.

`AppendAudit` uses the persistent lock and one append write per compact JSONL
record at `home/audit.jsonl`; rotation renames whole files under the same lock.
Audit schema/redaction belongs to `internal/audit`. See [AUDIT.md](AUDIT.md) for
retention settings, inspection commands and failure behavior.
