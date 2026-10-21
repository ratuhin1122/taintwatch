//go:build linux || darwin

package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditRotation(t *testing.T) {
	s, e := New(Options{Home: filepath.Join(t.TempDir(), "state"), AuditMaxBytes: 16, AuditKeep: 3})
	if e != nil {
		t.Fatal(e)
	}
	for i := 1; i <= 7; i++ {
		if e = s.AppendAudit([]byte(fmt.Sprintf(`{"sequence":%d}`, i))); e != nil {
			t.Fatal(e)
		}
	}
	for n := 0; n <= 3; n++ {
		b, e := os.ReadFile(s.auditPath(n))
		if e != nil || string(b) != fmt.Sprintf("{\"sequence\":%d}\n", 7-n) {
			t.Fatalf("%d: %s %v", n, b, e)
		}
		info, e := os.Stat(s.auditPath(n))
		if e != nil || info.Mode().Perm() != 0600 {
			t.Fatal("insecure log mode")
		}
	}
	if _, e = os.Stat(s.auditPath(4)); !os.IsNotExist(e) {
		t.Fatal("too many backups")
	}
	var got []string
	if e = s.ScanAudit(func(b []byte) error { got = append(got, string(b)); return nil }); e != nil || len(got) != 4 || !strings.Contains(got[0], "4") {
		t.Fatalf("%v %v", got, e)
	}
}
func TestRotationRejectsSymlink(t *testing.T) {
	s, e := New(Options{Home: filepath.Join(t.TempDir(), "state"), AuditMaxBytes: 1})
	if e != nil {
		t.Fatal(e)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if e = os.WriteFile(victim, []byte("keep"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(victim, s.auditPath(1)); e != nil {
		t.Fatal(e)
	}
	if e = s.AppendAudit([]byte(`{"x":1}`)); e != nil {
		t.Fatal(e)
	}
	if e = s.AppendAudit([]byte(`{"x":2}`)); e == nil {
		t.Fatal("rotation followed symlink")
	}
	b, _ := os.ReadFile(victim)
	if string(b) != "keep" {
		t.Fatal("victim changed")
	}
}
func TestLatestSession(t *testing.T) {
	s := testStore(t)
	if _, found, e := s.Latest(); e != nil || found {
		t.Fatalf("%t %v", found, e)
	}
	if _, e := s.Touch("../../hostile"); e != nil {
		t.Fatal(e)
	}
	v, found, e := s.Latest()
	if e != nil || !found || v.ID != "../../hostile" {
		t.Fatalf("%+v %t %v", v, found, e)
	}
	v, found, e = s.LoadKey(SanitizeSessionID("../../hostile"))
	if e != nil || !found || v.ID != "../../hostile" {
		t.Fatalf("%+v %t %v", v, found, e)
	}
	if _, found, e = s.LoadKey("../../escape"); e != nil || found {
		t.Fatalf("hostile lookup: %t %v", found, e)
	}
}

func TestAuditSnapshotDoesNotBlockAppend(t *testing.T) {
	s := testStore(t)
	if e := s.AppendAudit([]byte(`{"sequence":1}`)); e != nil {
		t.Fatal(e)
	}
	count := 0
	e := s.ScanAudit(func([]byte) error { count++; return s.AppendAudit([]byte(`{"sequence":2}`)) })
	if e != nil || count != 1 {
		t.Fatalf("snapshot extended or held writer lock: %d %v", count, e)
	}
	count = 0
	if e = s.ScanAudit(func([]byte) error { count++; return nil }); e != nil || count != 2 {
		t.Fatalf("%d %v", count, e)
	}
}
func TestAuditEnvironmentConfiguration(t *testing.T) {
	t.Setenv("TAINTWATCH_AUDIT_MAX_BYTES", "16")
	t.Setenv("TAINTWATCH_AUDIT_KEEP", "2")
	s, e := New(Options{Home: filepath.Join(t.TempDir(), "state")})
	if e != nil || s.auditMaxBytes != 16 || s.auditKeep != 2 {
		t.Fatalf("%+v %v", s, e)
	}
	s, e = New(Options{Home: filepath.Join(t.TempDir(), "state"), AuditMaxBytes: 32, AuditKeep: 1})
	if e != nil || s.auditMaxBytes != 32 || s.auditKeep != 1 {
		t.Fatalf("explicit override: %+v %v", s, e)
	}
	t.Setenv("TAINTWATCH_AUDIT_MAX_BYTES", "invalid")
	if _, e = New(Options{Home: t.TempDir()}); e == nil {
		t.Fatal("accepted invalid environment")
	}
}
