package main

import (
	"io"
	"os"
	"syscall"
	"unsafe"
)

func terminalInput(in io.Reader) bool {
	f, ok := in.(*os.File)
	if !ok {
		return false
	}
	var term syscall.Termios
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCGETA), uintptr(unsafe.Pointer(&term)))
	return err == 0
}
