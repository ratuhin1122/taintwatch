package state

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// MaxSessionIDLength bounds session IDs used literally in filenames.
	MaxSessionIDLength = 64
	// DefaultRetention is the inactivity interval used for lazy cleanup.
	DefaultRetention = 7 * 24 * time.Hour
	// DefaultLockTimeout bounds time spent waiting for another process's lock.
	DefaultLockTimeout = 250 * time.Millisecond
	maxReasonBytes     = 512
)

var (
	// ErrLockTimeout indicates that the store lock could not be acquired promptly.
	ErrLockTimeout = errors.New("state lock timeout")
	// ErrUnsupportedPlatform indicates that secure state storage is unavailable.
	ErrUnsupportedPlatform = errors.New("state storage requires macOS or Linux; use WSL on Windows")
)

// SourceKind identifies where untrusted content entered a session.
type SourceKind string

const (
	SourceWeb  SourceKind = "web"
	SourceMCP  SourceKind = "mcp"
	SourceBash SourceKind = "bash"
	SourceRead SourceKind = "read"
)

// TaintEvent records provenance, not a content detector's blocking decision.
type TaintEvent struct {
	Time   time.Time  `json:"time"`
	Tool   string     `json:"tool"`
	Source SourceKind `json:"source"`
	Reason string     `json:"reason"`
	Values []string   `json:"values,omitempty"`
}

// Approval records an explicit approval supplied by a future trusted caller.
// This storage layer does not authenticate Who or grant tool permissions itself.
type Approval struct {
	Time   time.Time `json:"time"`
	Tool   string    `json:"tool,omitempty"`
	RuleID string    `json:"rule_id,omitempty"`
	Reason string    `json:"reason"`
	Who    string    `json:"who"`
}

// ClearRecord preserves attribution for the most recent explicit clear.
type ClearRecord struct {
	Time   time.Time `json:"time"`
	Reason string    `json:"reason"`
	Who    string    `json:"who"`
}

// Session is coarse session-level state. It does not track fine-grained flows.
type Session struct {
	ID          string       `json:"id"`
	Tainted     bool         `json:"tainted"`
	TaintEvents []TaintEvent `json:"taint_events,omitempty"`
	Approvals   []Approval   `json:"approvals,omitempty"`
	LastClear   *ClearRecord `json:"last_clear,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// Options configures a store. Zero retention/lock timeout selects the defaults;
// negative durations are invalid. Home overrides TAINTWATCH_HOME and XDG paths.
type Options struct {
	Home        string
	Retention   time.Duration
	LockTimeout time.Duration
}

// Store serializes reads, read-modify-write operations, and cleanup through one
// persistent advisory lock. A Store may be shared between goroutines.
type Store struct {
	home        string
	sessions    string
	retention   time.Duration
	lockTimeout time.Duration
	now         func() time.Time
}

// DefaultHome resolves TAINTWATCH_HOME, then XDG_STATE_HOME/taintwatch, then
// ~/.local/state/taintwatch. macOS uses the same XDG-style fallback as Linux.
func DefaultHome() (string, error) {
	if home := os.Getenv("TAINTWATCH_HOME"); home != "" {
		return filepath.Abs(home)
	}
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" && filepath.IsAbs(xdg) {
		return filepath.Join(xdg, "taintwatch"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	return filepath.Join(home, ".local", "state", "taintwatch"), nil
}

// New opens a secure state directory without creating any session JSON files.
// Parent directories are operator-controlled; managed directories must not be
// symlinks. Advisory locking coordinates cooperating Taintwatch processes only.
func New(opts Options) (*Store, error) {
	if opts.Retention < 0 || opts.LockTimeout < 0 {
		return nil, errors.New("state retention and lock timeout must not be negative")
	}
	if err := supportedPlatform(); err != nil {
		return nil, err
	}
	home := opts.Home
	var err error
	if home == "" {
		home, err = DefaultHome()
	} else {
		home, err = filepath.Abs(home)
	}
	if err != nil {
		return nil, fmt.Errorf("resolve state directory: %w", err)
	}
	if opts.Retention == 0 {
		opts.Retention = DefaultRetention
	}
	if opts.LockTimeout == 0 {
		opts.LockTimeout = DefaultLockTimeout
	}
	s := &Store{home: home, sessions: filepath.Join(home, "sessions"), retention: opts.Retention, lockTimeout: opts.LockTimeout, now: time.Now}
	if err := secureDir(s.home); err != nil {
		return nil, fmt.Errorf("prepare state home: %w", err)
	}
	if err := secureDir(s.sessions); err != nil {
		return nil, fmt.Errorf("prepare sessions: %w", err)
	}
	return s, nil
}

// Home returns the absolute managed state directory.
func (s *Store) Home() string { return s.home }

// SanitizeSessionID preserves 1..64 ASCII letters, digits, underscores and hyphens.
// Everything else, including empty IDs, is hashed. The 71-character hash namespace
// cannot collide with literal IDs, which are capped at 64 characters.
func SanitizeSessionID(id string) string {
	safe := len(id) > 0 && len(id) <= MaxSessionIDLength
	for i := 0; i < len(id) && safe; i++ {
		c := id[i]
		safe = c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-'
	}
	if safe {
		return id
	}
	digest := sha256.Sum256([]byte(id))
	return "sha256-" + hex.EncodeToString(digest[:])
}

func (s *Store) sessionPath(id string) string {
	return filepath.Join(s.sessions, SanitizeSessionID(id)+".json")
}

// Load returns a clean, unsaved session if no file exists. Corrupt state is an
// error, never silently converted to clean state. Load does not refresh expiry.
func (s *Store) Load(id string) (Session, error) {
	var result Session
	err := s.withLock(func() error { var err error; result, err = s.load(id, s.now().UTC()); return err })
	if err != nil {
		return Session{}, fmt.Errorf("load session: %w", err)
	}
	return result, nil
}

// MarkTainted appends provenance and sets the session tainted atomically.
// Event times default to now; source must be web, mcp, bash, or read.
func (s *Store) MarkTainted(id string, event TaintEvent) (Session, error) {
	return s.update(id, func(session *Session, now time.Time) error {
		if event.Tool == "" {
			return errors.New("taint event requires a tool")
		}
		switch event.Source {
		case SourceWeb, SourceMCP, SourceBash, SourceRead:
		default:
			return errors.New("invalid taint source kind")
		}
		if err := checkReason(event.Reason); err != nil {
			return err
		}
		if event.Time.IsZero() {
			event.Time = now
		} else {
			event.Time = event.Time.UTC()
		}
		event.Values = append([]string(nil), event.Values...)
		session.Tainted = true
		session.TaintEvents = append(session.TaintEvents, event)
		return nil
	})
}

// AddApproval appends an attributed approval without changing session taint.
func (s *Store) AddApproval(id string, approval Approval) (Session, error) {
	return s.update(id, func(session *Session, now time.Time) error {
		if approval.Who == "" {
			return errors.New("approval requires who")
		}
		if err := checkReason(approval.Reason); err != nil {
			return err
		}
		if approval.Time.IsZero() {
			approval.Time = now
		} else {
			approval.Time = approval.Time.UTC()
		}
		session.Approvals = append(session.Approvals, approval)
		return nil
	})
}

// Clear resets taint, events, and approvals while retaining creation time and
// attribution for the latest clear. Authorization belongs to the future caller;
// no CLI clear command is exposed by this package.
func (s *Store) Clear(id, reason, who string) (Session, error) {
	return s.update(id, func(session *Session, now time.Time) error {
		if who == "" {
			return errors.New("clear requires who")
		}
		if err := checkReason(reason); err != nil {
			return err
		}
		session.Tainted = false
		session.TaintEvents = nil
		session.Approvals = nil
		session.LastClear = &ClearRecord{Time: now, Reason: reason, Who: who}
		return nil
	})
}

// Touch persists a clean session if necessary and refreshes its update time/mtime.
func (s *Store) Touch(id string) (Session, error) {
	return s.update(id, func(*Session, time.Time) error { return nil })
}

func checkReason(reason string) error {
	if reason == "" || len(reason) > maxReasonBytes {
		return errors.New("reason must contain 1..512 bytes")
	}
	return nil
}
