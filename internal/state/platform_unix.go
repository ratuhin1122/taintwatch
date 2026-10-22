//go:build linux || darwin

package state

import (
	"errors"
	"os"
	"syscall"
)

func supportedPlatform() error { return nil }

func singleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

func openNoFollow(path string, flags int) (*os.File, error) {
	// NONBLOCK avoids hanging on a FIFO before openRegular can reject its type.
	return os.OpenFile(path, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
}

func tryLock(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return errLockBusy
	}
	if errors.Is(err, syscall.EINTR) {
		return errLockBusy
	}
	return err
}

func unlock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
