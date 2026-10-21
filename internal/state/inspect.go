package state

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// LoadKey looks up an already sanitized filename key from audit metadata.
// The raw ID is recovered from the file and checked against that filename.
func (s *Store) LoadKey(key string) (session Session, found bool, err error) {
	safe := key == SanitizeSessionID(key)
	if strings.HasPrefix(key, "sha256-") && len(key) == 71 {
		safe = true
		for _, c := range key[7:] {
			if !strings.ContainsRune("0123456789abcdef", c) {
				safe = false
			}
		}
	}
	if !safe {
		return Session{}, false, nil
	}
	err = s.withLock(func() error {
		f, e := openRegular(filepath.Join(s.sessions, key+".json"), os.O_RDONLY)
		if errors.Is(e, os.ErrNotExist) {
			return nil
		}
		if e != nil {
			return e
		}
		b, e := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		var v Session
		if e = json.Unmarshal(b, &v); e != nil {
			return e
		}
		if SanitizeSessionID(v.ID) != key {
			return errors.New("session filename mismatch")
		}
		session, e = decodeSession(b, v.ID)
		found = e == nil
		return e
	})
	return
}

// Latest returns the most recently updated persisted session without touching it.
func (s *Store) Latest() (session Session, found bool, err error) {
	err = s.withLock(func() error {
		entries, e := os.ReadDir(s.sessions)
		if e != nil {
			return e
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			p := filepath.Join(s.sessions, entry.Name())
			f, e := openRegular(p, os.O_RDONLY)
			if e != nil {
				return e
			}
			b, e := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
			closeErr := f.Close()
			if e != nil {
				return e
			}
			if closeErr != nil {
				return closeErr
			}
			var raw Session
			if e = json.Unmarshal(b, &raw); e != nil {
				return e
			}
			if SanitizeSessionID(raw.ID)+".json" != entry.Name() {
				return errors.New("session filename mismatch")
			}
			v, e := decodeSession(b, raw.ID)
			if e != nil {
				return e
			}
			if !found || v.UpdatedAt.After(session.UpdatedAt) {
				session = v
				found = true
			}
		}
		return nil
	})
	return
}
