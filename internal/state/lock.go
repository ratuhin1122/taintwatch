package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var errLockBusy = errors.New("state lock busy")

func (s *Store) withLock(fn func() error) (err error) {
	// Recheck managed directory endpoints before each operation. Protecting against
	// a malicious process running as the same OS user is outside this boundary.
	if err := secureDir(s.home); err != nil {
		return fmt.Errorf("check state home: %w", err)
	}
	if err := secureDir(s.sessions); err != nil {
		return fmt.Errorf("check sessions directory: %w", err)
	}
	// Never unlink this file: doing so could split locks across different inodes.
	f, err := openRegular(filepath.Join(s.home, ".lock"), os.O_CREATE|os.O_RDWR)
	if err != nil {
		return fmt.Errorf("open state lock: %w", err)
	}
	defer f.Close()
	deadline := time.Now().Add(s.lockTimeout)
	for {
		lockErr := tryLock(f)
		if lockErr == nil {
			break
		}
		if !errors.Is(lockErr, errLockBusy) {
			return fmt.Errorf("lock state: %w", lockErr)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return ErrLockTimeout
		}
		time.Sleep(min(5*time.Millisecond, remaining))
	}
	defer func() {
		if unlockErr := unlock(f); unlockErr != nil {
			err = errors.Join(err, fmt.Errorf("unlock state: %w", unlockErr))
		}
	}()
	return fn()
}
