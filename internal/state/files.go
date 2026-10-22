package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Keep on-disk reads bounded and never write a session this implementation cannot
// read. This is a storage limit, separate from the hook transport's input cap.
const maxStateBytes = 16 << 20

func secureDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("managed path must be a real directory")
	}
	if info.Mode().Perm() != 0700 {
		return os.Chmod(path, 0700)
	}
	return nil
}

func openRegular(path string, flags int) (*os.File, error) {
	f, err := openNoFollow(path, flags)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = errors.New("state path must be a regular file")
	}
	// A hard link can alias an unmanaged file even when O_NOFOLLOW succeeds.
	// Reject it before repairing permissions or reading/writing any contents.
	if err == nil && !singleLink(info) {
		err = errors.New("managed state file must have exactly one hard link")
	}
	if err == nil && info.Mode().Perm() != 0600 {
		err = f.Chmod(0600)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func (s *Store) load(id string, now time.Time) (Session, error) {
	f, err := openRegular(s.sessionPath(id), os.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return Session{ID: id, CreatedAt: now, UpdatedAt: now}, nil
	}
	if err != nil {
		return Session{}, fmt.Errorf("open session file: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if err != nil {
		return Session{}, fmt.Errorf("read session file: %w", err)
	}
	return decodeSession(b, id)
}

func decodeSession(b []byte, id string) (Session, error) {
	if len(b) > maxStateBytes {
		return Session{}, errors.New("state file exceeds 16 MiB")
	}
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return Session{}, errors.New("session state must be a JSON object")
	}
	var session Session
	if err := json.Unmarshal(b, &session); err != nil {
		return Session{}, fmt.Errorf("decode session state: %w", err)
	}
	if session.ID != id {
		return Session{}, errors.New("session state id mismatch")
	}
	if session.CreatedAt.IsZero() || session.UpdatedAt.IsZero() {
		return Session{}, errors.New("session state missing timestamps")
	}
	if !session.Tainted && len(session.TaintEvents) > 0 {
		return Session{}, errors.New("session state contains events without taint")
	}
	return session, nil
}

func (s *Store) update(id string, change func(*Session, time.Time) error) (Session, error) {
	var result Session
	err := s.withLock(func() error {
		now := s.now().UTC()
		session, err := s.load(id, now)
		if err != nil {
			return err
		}
		if err := change(&session, now); err != nil {
			return fmt.Errorf("modify session: %w", err)
		}
		session.UpdatedAt = now
		b, err := json.Marshal(session)
		if err != nil {
			return fmt.Errorf("encode session state: %w", err)
		}
		b = append(b, '\n')
		if len(b) > maxStateBytes {
			return errors.New("updated state exceeds 16 MiB")
		}
		path := s.sessionPath(id)
		if err := s.cleanup(now, filepath.Base(path)); err != nil {
			return fmt.Errorf("clean expired sessions: %w", err)
		}
		if err := atomicWrite(path, b); err != nil {
			return err
		}
		result = session
		return nil
	})
	if err != nil {
		return Session{}, fmt.Errorf("update session: %w", err)
	}
	return result, nil
}

func atomicWrite(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".session-*")
	if err != nil {
		return fmt.Errorf("create session temp: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return fmt.Errorf("protect session temp: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("write session temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync session temp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close session temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace session file: %w", err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open sessions directory for sync: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync sessions directory: %w", err)
	}
	return nil
}

// Cleanup shares the persistent store lock with every update, preventing stale
// scans from deleting a session another cooperating process just refreshed.
func (s *Store) cleanup(now time.Time, active string) error {
	entries, err := os.ReadDir(s.sessions)
	if err != nil {
		return err
	}
	cutoff := now.Add(-s.retention)
	inspect := func(entry os.DirEntry) error {
		name := entry.Name()
		info, err := entry.Info()
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || !info.ModTime().Before(cutoff) {
			return nil
		}
		if err := os.Remove(filepath.Join(s.sessions, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	// Keep the all-files-on-every-write retention contract. Bounded workers
	// overlap independent metadata lookups in large directories; the process
	// lock remains held, so cooperating writers cannot refresh a scanned file.
	if len(entries) < 256 {
		for _, entry := range entries {
			if entry.Name() != active && sessionFilename(entry.Name()) {
				if err := inspect(entry); err != nil {
					return err
				}
			}
		}
		return nil
	}
	jobs := make(chan os.DirEntry, 64)
	var workers sync.WaitGroup
	var errorMu sync.Mutex
	var firstErr error
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for entry := range jobs {
				if err := inspect(entry); err != nil {
					errorMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errorMu.Unlock()
				}
			}
		}()
	}
	for _, entry := range entries {
		if entry.Name() != active && sessionFilename(entry.Name()) {
			jobs <- entry
		}
	}
	close(jobs)
	workers.Wait()
	return firstErr
}

func sessionFilename(name string) bool {
	if !strings.HasSuffix(name, ".json") {
		return false
	}
	stem := strings.TrimSuffix(name, ".json")
	if strings.HasPrefix(stem, "sha256-") && len(stem) == 71 {
		for _, c := range stem[7:] {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
		return true
	}
	return len(stem) > 0 && len(stem) <= MaxSessionIDLength && SanitizeSessionID(stem) == stem
}
