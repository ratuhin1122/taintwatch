//go:build linux || darwin

package policy

import (
	"os"
	"syscall"
)

func openPolicy(file string) (*os.File, error) {
	return os.OpenFile(file, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
