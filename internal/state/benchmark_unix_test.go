//go:build linux || darwin

package state

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func BenchmarkRetentionLargeDirectory(b *testing.B) {
	s, err := New(Options{Home: filepath.Join(b.TempDir(), "state")})
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 10000; i++ {
		if err := os.WriteFile(s.sessionPath(fmt.Sprintf("fixture-%d", i)), []byte("{}"), 0600); err != nil {
			b.Fatal(err)
		}
	}
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.cleanup(now, "active.json"); err != nil {
			b.Fatal(err)
		}
	}
}
