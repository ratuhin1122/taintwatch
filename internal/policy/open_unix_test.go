//go:build linux || darwin

package policy

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRejectSpecialPolicyFiles(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.yaml")
	put(t, target, "version: 1\n")
	link := filepath.Join(root, "link.yaml")
	if e := os.Symlink(target, link); e != nil {
		t.Fatal(e)
	}
	if e := Check(link); e == nil {
		t.Fatal("followed policy symlink")
	}
	fifo := filepath.Join(root, "fifo.yaml")
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	if e := Check(fifo); e == nil {
		t.Fatal("accepted FIFO")
	}
	if time.Since(start) > time.Second {
		t.Fatal("policy FIFO blocked")
	}
}
