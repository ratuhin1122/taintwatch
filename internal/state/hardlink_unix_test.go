//go:build linux || darwin

package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagedFilesRejectHardlinksBeforeChmod(t *testing.T) {
	for _, kind := range []string{"lock", "session", "audit", "rotation"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			victim := filepath.Join(t.TempDir(), "unmanaged")
			if err := os.WriteFile(victim, []byte("unchanged"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(victim, 0644); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.home, ".lock")
			switch kind {
			case "session":
				path = s.sessionPath("s")
			case "audit":
				path = s.auditPath(0)
			case "rotation":
				path = s.auditPath(1)
			}
			if err := os.Link(victim, path); err != nil {
				t.Fatal(err)
			}
			f, err := openRegular(path, os.O_RDWR)
			if err == nil {
				f.Close()
				t.Fatal("accepted an unmanaged hard-link alias")
			}
			data, err := os.ReadFile(victim)
			if err != nil || string(data) != "unchanged" {
				t.Fatal("unmanaged data changed", err)
			}
			info, err := os.Stat(victim)
			if err != nil || info.Mode().Perm() != 0644 {
				t.Fatal("unmanaged permissions changed", err)
			}
		})
	}
}
