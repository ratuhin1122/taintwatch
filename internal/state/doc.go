// Package state persists coarse per-session taint state on macOS and Linux.
// Updates and lazy expiry share a bounded advisory flock, and files are replaced
// atomically in owner-only directories. Windows callers should run inside WSL.
// The package stores state; future hook callers must enforce authorization and
// apply their configured open/closed failure policy when operations return errors.
package state
