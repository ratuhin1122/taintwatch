//go:build linux || darwin

package state

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentAudit(t *testing.T) {
	s := testStore(t)
	const workers = 24
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.AppendAudit([]byte(`{"decision":"allow"}`)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	f, err := os.Open(filepath.Join(s.home, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("mode=%v err=%v", info, err)
	}
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		count++
		if !json.Valid(scanner.Bytes()) {
			t.Fatal("partial audit record")
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != workers {
		t.Fatalf("lost audit records: %d", count)
	}
	for _, record := range []string{"null", "[]", "{", "{\n\"x\":1}"} {
		if err := s.AppendAudit([]byte(record)); err == nil {
			t.Fatalf("accepted %q", record)
		}
	}
}
