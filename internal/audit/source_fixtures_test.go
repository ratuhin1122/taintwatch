package audit

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestNoCompleteCredentialFixturesInSource(t *testing.T) {
	pattern := regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,}|sk-[A-Za-z0-9_-]{8,}|Bearer [A-Za-z0-9._-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?i:\b(?:password|secret|token|key|api_key|client_secret)["']?\s*[:=]\s*["']?[A-Za-z0-9_.-]{8,})`)
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join("..", "..", dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if pattern.Match(data) {
				t.Errorf("complete credential-shaped fixture in %s; construct it at runtime", path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
