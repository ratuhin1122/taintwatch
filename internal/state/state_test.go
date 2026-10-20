package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSanitizeSessionID(t *testing.T) {
	for _, id := range []string{"abc_123-XYZ", strings.Repeat("a", 64), "../../etc/passwd", "", "..", "/absolute", `C:\escape`, "a.b", "héllo", strings.Repeat("a", 65), "line\nbreak"} {
		t.Run(id, func(t *testing.T) {
			got := SanitizeSessionID(id)
			if got != SanitizeSessionID(id) || filepath.Base(got) != got || strings.ContainsAny(got, "./\\\x00\n") || len(got) > 71 {
				t.Fatalf("unsafe filename %q", got)
			}
			literal := id == "abc_123-XYZ" || id == strings.Repeat("a", 64)
			if literal && got != id {
				t.Fatalf("changed safe id: %q", got)
			}
			if !literal && (!strings.HasPrefix(got, "sha256-") || len(got) != 71) {
				t.Fatalf("not hashed: %q", got)
			}
			if !literal && SanitizeSessionID(got) == got {
				t.Fatal("hashed names overlap literal namespace")
			}
		})
	}
}

func TestDefaultHome(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct{ name, override, xdg, want string }{
		{"override", filepath.Join(root, "override"), filepath.Join(root, "xdg"), filepath.Join(root, "override")},
		{"xdg", "", filepath.Join(root, "xdg"), filepath.Join(root, "xdg", "taintwatch")},
		{"fallback", "", "", filepath.Join(root, ".local", "state", "taintwatch")},
		{"relative XDG ignored", "", "relative", filepath.Join(root, ".local", "state", "taintwatch")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TAINTWATCH_HOME", tc.override)
			t.Setenv("XDG_STATE_HOME", tc.xdg)
			if runtime.GOOS == "windows" {
				t.Setenv("USERPROFILE", root)
			} else {
				t.Setenv("HOME", root)
			}
			got, err := DefaultHome()
			if err != nil || got != tc.want {
				t.Fatalf("got=%q err=%v want=%q", got, err, tc.want)
			}
		})
	}
}

func TestOptions(t *testing.T) {
	for _, opts := range []Options{{Retention: -time.Second}, {LockTimeout: -time.Second}} {
		if _, err := New(opts); err == nil {
			t.Fatal("accepted negative duration")
		}
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		if _, err := New(Options{Home: t.TempDir()}); !errors.Is(err, ErrUnsupportedPlatform) {
			t.Fatalf("platform error=%v", err)
		}
	}
}

func FuzzSanitizeSessionID(f *testing.F) {
	for _, id := range []string{"abc", "../../etc/passwd", "", strings.Repeat("x", 100)} {
		f.Add(id)
	}
	f.Fuzz(func(t *testing.T, id string) {
		name := SanitizeSessionID(id)
		if filepath.Base(name) != name || strings.ContainsAny(name, "./\\\x00") || len(name) > 71 || !sessionFilename(name+".json") {
			t.Fatalf("unsafe %q", name)
		}
	})
}

func FuzzSessionState(f *testing.F) {
	f.Add([]byte(`{"id":"s","tainted":false,"created_at":"2026-10-21T00:00:00Z","updated_at":"2026-10-21T00:00:00Z"}`), "s")
	f.Add([]byte(`null`), "s")
	f.Add([]byte(`{`), "s")
	f.Fuzz(func(t *testing.T, b []byte, id string) {
		session, err := decodeSession(b, id)
		if err == nil && (len(b) > maxStateBytes || !json.Valid(b) || session.ID != id || session.CreatedAt.IsZero() || session.UpdatedAt.IsZero() || !session.Tainted && len(session.TaintEvents) > 0) {
			t.Fatal("accepted invalid state")
		}
	})
}

// Keep a portable test referencing os so platform-specific path handling is
// exercised without pretending Windows provides Unix storage semantics.
func TestOverrideIsAbsolute(t *testing.T) {
	t.Setenv("TAINTWATCH_HOME", "relative-state")
	got, err := DefaultHome()
	cwd, cwdErr := os.Getwd()
	if err != nil || cwdErr != nil || got != filepath.Join(cwd, "relative-state") {
		t.Fatalf("home=%q err=%v cwdErr=%v", got, err, cwdErr)
	}
}
