//go:build linux || darwin

package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(Options{Home: filepath.Join(t.TempDir(), "state"), LockTimeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testEvent(reason string) TaintEvent {
	return TaintEvent{Tool: "Read", Source: SourceRead, Reason: reason, Values: []string{"https://example.com"}}
}

func TestOperations(t *testing.T) {
	s := testStore(t)
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	clean, err := s.Load("session")
	if err != nil || clean.Tainted || clean.ID != "session" || !clean.CreatedAt.Equal(now) {
		t.Fatalf("clean=%+v err=%v", clean, err)
	}
	if _, err := os.Stat(s.sessionPath("session")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load created state: %v", err)
	}
	for _, source := range []SourceKind{SourceWeb, SourceMCP, SourceBash, SourceRead} {
		event := testEvent("untrusted content")
		event.Source = source
		if _, err := s.MarkTainted("session", event); err != nil {
			t.Fatal(err)
		}
	}
	approved, err := s.AddApproval("session", Approval{Tool: "Bash", RuleID: "network", Reason: "approved by user", Who: "user"})
	if err != nil || !approved.Tainted || len(approved.TaintEvents) != 4 || len(approved.Approvals) != 1 {
		t.Fatalf("approved=%+v err=%v", approved, err)
	}
	if approved.TaintEvents[0].Time.IsZero() || approved.TaintEvents[0].Values[0] != "https://example.com" {
		t.Fatal("lost event details")
	}
	now = now.Add(time.Hour)
	touched, err := s.Touch("session")
	if err != nil || !touched.Tainted || !touched.UpdatedAt.Equal(now) || !touched.CreatedAt.Equal(clean.CreatedAt) {
		t.Fatalf("touch=%+v err=%v", touched, err)
	}
	cleared, err := s.Clear("session", "start clean work", "user")
	if err != nil || cleared.Tainted || len(cleared.TaintEvents) != 0 || len(cleared.Approvals) != 0 || cleared.LastClear == nil || cleared.LastClear.Who != "user" || cleared.LastClear.Reason != "start clean work" {
		t.Fatalf("clear=%+v err=%v", cleared, err)
	}
	loaded, err := s.Load("session")
	if err != nil || loaded.LastClear == nil || !loaded.CreatedAt.Equal(clean.CreatedAt) {
		t.Fatalf("load=%+v err=%v", loaded, err)
	}
}

func TestRejectInvalidMutation(t *testing.T) {
	s := testStore(t)
	for _, tc := range []struct {
		name  string
		write func() error
	}{
		{"source", func() error {
			e := testEvent("reason")
			e.Source = "unknown"
			_, err := s.MarkTainted("s", e)
			return err
		}},
		{"tool", func() error { e := testEvent("reason"); e.Tool = ""; _, err := s.MarkTainted("s", e); return err }},
		{"reason", func() error { _, err := s.MarkTainted("s", testEvent(strings.Repeat("x", 513))); return err }},
		{"clear who", func() error { _, err := s.Clear("s", "reason", ""); return err }},
		{"clear reason", func() error { _, err := s.Clear("s", "", "user"); return err }},
		{"approval who", func() error { _, err := s.AddApproval("s", Approval{Reason: "reason"}); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.write(); err == nil {
				t.Fatal("accepted invalid mutation")
			}
		})
	}
	if _, err := os.Stat(s.sessionPath("s")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid operation wrote state: %v", err)
	}
}

func TestPermissionsAndHostileID(t *testing.T) {
	s := testStore(t)
	for _, id := range []string{"../../etc/passwd", "/etc/passwd", `..\..\escape`, "a/b", "", strings.Repeat("x", 1024)} {
		t.Run(id, func(t *testing.T) {
			if _, err := s.MarkTainted(id, testEvent("untrusted source")); err != nil {
				t.Fatal(err)
			}
			path := s.sessionPath(id)
			rel, err := filepath.Rel(s.sessions, path)
			if err != nil || filepath.Base(rel) != rel || strings.HasPrefix(rel, "..") {
				t.Fatalf("escaped: %q err=%v", rel, err)
			}
			loaded, err := s.Load(id)
			if err != nil || loaded.ID != id || !loaded.Tainted {
				t.Fatalf("loaded=%+v err=%v", loaded, err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("permissions info=%v err=%v", info, err)
			}
		})
	}
	for _, path := range []string{s.home, s.sessions} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatalf("directory permissions: %v %v", info, err)
		}
	}
	lockPath := filepath.Join(s.home, ".lock")
	before, err := os.Stat(lockPath)
	if err != nil || before.Mode().Perm() != 0600 {
		t.Fatalf("lock=%v err=%v", before, err)
	}
	if _, err := s.Touch("another"); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(lockPath)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("lock inode changed")
	}
	entries, err := os.ReadDir(s.sessions)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".session-") {
			t.Fatal("temp file left after successful write")
		}
	}
}

func TestCleanup(t *testing.T) {
	for _, retention := range []time.Duration{DefaultRetention, time.Hour} {
		t.Run(retention.String(), func(t *testing.T) {
			s := testStore(t)
			s.retention = retention
			now := time.Now().UTC().Truncate(time.Second)
			s.now = func() time.Time { return now }
			for _, id := range []string{"expired", "boundary", "recent", "active"} {
				if _, err := s.MarkTainted(id, testEvent("old provenance")); err != nil {
					t.Fatal(err)
				}
			}
			for id, age := range map[string]time.Duration{"expired": retention + time.Second, "boundary": retention, "recent": retention - time.Second, "active": retention + time.Hour} {
				stamp := now.Add(-age)
				if err := os.Chtimes(s.sessionPath(id), stamp, stamp); err != nil {
					t.Fatal(err)
				}
			}
			foreign := filepath.Join(s.sessions, "notes.txt")
			// Exercise the bounded worker path as well as active/boundary rules.
			for i := 0; i < 300; i++ {
				path := s.sessionPath(fmt.Sprintf("bulk-%d", i))
				if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
				stamp := now
				if i%2 == 0 {
					stamp = now.Add(-retention - time.Second)
				}
				if err := os.Chtimes(path, stamp, stamp); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(foreign, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			old := now.Add(-retention - time.Hour)
			if err := os.Chtimes(foreign, old, old); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Load("recent"); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(s.sessionPath("expired")); err != nil {
				t.Fatal("read unexpectedly cleaned files")
			}
			active, err := s.Touch("active")
			if err != nil || !active.Tainted || len(active.TaintEvents) != 1 {
				t.Fatalf("active state lost: %+v %v", active, err)
			}
			if _, err := os.Stat(s.sessionPath("expired")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expired survives: %v", err)
			}
			for i := 0; i < 300; i++ {
				_, err := os.Stat(s.sessionPath(fmt.Sprintf("bulk-%d", i)))
				if i%2 == 0 && !errors.Is(err, os.ErrNotExist) || i%2 != 0 && err != nil {
					t.Fatalf("bulk retention %d: %v", i, err)
				}
			}
			for _, path := range []string{s.sessionPath("boundary"), s.sessionPath("recent"), s.sessionPath("active"), foreign} {
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("deleted live/foreign file: %s %v", path, err)
				}
			}
		})
	}
}

func TestCorruptState(t *testing.T) {
	s := testStore(t)
	for _, payload := range []string{"{", "null", `{"id":"wrong"}`, `{"id":"s"}`, strings.Repeat("x", maxStateBytes+1)} {
		if err := os.WriteFile(s.sessionPath("s"), []byte(payload), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Load("s"); err == nil {
			t.Fatal("corrupt state became clean")
		}
		if _, err := s.Touch("s"); err == nil {
			t.Fatal("corrupt state overwritten")
		}
		b, err := os.ReadFile(s.sessionPath("s"))
		if err != nil || string(b) != payload {
			t.Fatal("error mutated corrupt state")
		}
	}
}

func TestSymlinksAndFIFO(t *testing.T) {
	for _, kind := range []string{"home", "sessions", "session", "lock", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "home", "sessions":
				path := s.home
				if kind == "sessions" {
					path = s.sessions
				}
				if err := os.Rename(path, path+"-saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Dir(outside), path); err != nil {
					t.Fatal(err)
				}
			case "session":
				if err := os.Symlink(outside, s.sessionPath("s")); err != nil {
					t.Fatal(err)
				}
			case "lock":
				if err := os.Symlink(outside, filepath.Join(s.home, ".lock")); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(s.sessionPath("s"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.Touch("s"); err == nil {
				t.Fatal("accepted unsafe managed path")
			}
			b, err := os.ReadFile(outside)
			if err != nil || string(b) != "unchanged" {
				t.Fatal("changed symlink target")
			}
		})
	}
}

func TestLockTimeout(t *testing.T) {
	s := testStore(t)
	s.lockTimeout = 20 * time.Millisecond
	f, err := openRegular(filepath.Join(s.home, ".lock"), os.O_CREATE|os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := tryLock(f); err != nil {
		t.Fatal(err)
	}
	defer unlock(f)
	start := time.Now()
	_, err = s.Touch("s")
	if !errors.Is(err, ErrLockTimeout) || time.Since(start) > 2*time.Second {
		t.Fatalf("lock wait=%v err=%v", time.Since(start), err)
	}
}

func TestConcurrentGoroutines(t *testing.T) {
	s := testStore(t)
	const workers = 40
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				reason := fmt.Sprintf("worker %d event %d", i, j)
				if _, err := s.MarkTainted("same", testEvent(reason)); err != nil {
					t.Error(err)
					return
				}
				if _, err := s.AddApproval("same", Approval{Who: "user", Reason: reason}); err != nil {
					t.Error(err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	loaded, err := s.Load("same")
	if err != nil || !loaded.Tainted || len(loaded.TaintEvents) != workers*4 || len(loaded.Approvals) != workers*4 {
		t.Fatalf("lost updates: events=%d approvals=%d err=%v", len(loaded.TaintEvents), len(loaded.Approvals), err)
	}
	seen := map[string]bool{}
	for _, event := range loaded.TaintEvents {
		if seen[event.Reason] {
			t.Fatal("duplicated event")
		}
		seen[event.Reason] = true
	}
}

func TestAtomicReaders(t *testing.T) {
	s := testStore(t)
	if _, err := s.Touch("same"); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			b, err := os.ReadFile(s.sessionPath("same"))
			if err != nil || !json.Valid(b) {
				t.Errorf("partial state observed: %v", err)
				return
			}
		}
	}()
	for i := 0; i < 30; i++ {
		if _, err := s.MarkTainted("same", testEvent("atomic replacement")); err != nil {
			t.Error(err)
			break
		}
	}
	close(stop)
	<-done
}

func TestStateProcessHelper(t *testing.T) {
	if os.Getenv("TAINTWATCH_STATE_TEST_HELPER") != "1" {
		return
	}
	s, err := New(Options{LockTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		if _, err := s.MarkTainted("process-session", testEvent(os.Getenv("TAINTWATCH_STATE_TEST_TOKEN")+"-"+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
}

func TestConcurrentProcesses(t *testing.T) {
	s := testStore(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const workers = 6
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestStateProcessHelper$", "-test.count=1")
			cmd.Env = append(os.Environ(), "TAINTWATCH_HOME="+s.home, "TAINTWATCH_STATE_TEST_HELPER=1", "TAINTWATCH_STATE_TEST_TOKEN="+strconv.Itoa(i))
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("helper failed: %v %s", err, b)
			}
		}(i)
	}
	wg.Wait()
	loaded, err := s.Load("process-session")
	if err != nil || len(loaded.TaintEvents) != workers*12 {
		t.Fatalf("lost process updates: events=%d err=%v", len(loaded.TaintEvents), err)
	}
}
