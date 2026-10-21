//go:build linux || darwin

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratuhin1122/taintwatch/internal/state"
)

func TestSecretsNeverReachLog(t *testing.T) {
	s, e := state.New(state.Options{Home: filepath.Join(t.TempDir(), "state")})
	if e != nil {
		t.Fatal(e)
	}
	secret := "AKIAABCDEFGHIJKLMNOP ghp_fixture123456789 Bearer fixturebearer123 password=fixturepassword -----BEGIN PRIVATE KEY-----\nfixtureprivate\n-----END PRIVATE KEY-----"
	if e = Write(s, Record{Session: "session", Reason: secret, Evidence: []string{secret}, TaintSources: []string{secret}, InputSummary: "full file content fixturecontent"}); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(s.Home(), "audit.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"AKIAABCDEFGHIJKLMNOP", "fixture123456789", "fixturebearer123", "fixturepassword", "fixtureprivate", "fixturecontent"} {
		if strings.Contains(string(b), v) {
			t.Fatalf("leaked %s", v)
		}
	}
	for _, kind := range []string{"aws", "github", "bearer", "credential", "private-key"} {
		if !strings.Contains(string(b), "[REDACTED:"+kind+"]") {
			t.Fatalf("missing type %s: %s", kind, b)
		}
	}
}
