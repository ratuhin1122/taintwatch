//go:build linux || darwin

package install

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLauncherFailureModes(t *testing.T) {
	launcher, e := filepath.Abs("../../bin/taintwatch-launcher")
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"pre", "post"} {
		for _, mode := range []string{"open", "closed"} {
			t.Run(kind+mode, func(t *testing.T) {
				dir := t.TempDir()
				tools := filepath.Join(dir, "tools")
				if e := os.Mkdir(tools, 0700); e != nil {
					t.Fatal(e)
				}
				for _, name := range []string{"uname", "mkdir", "dirname", "chmod"} {
					target, e := exec.LookPath(name)
					if e != nil {
						t.Fatal(e)
					}
					if e = os.Symlink(target, filepath.Join(tools, name)); e != nil {
						t.Fatal(e)
					}
				}
				cmd := exec.Command("/bin/sh", launcher, "hook", kind)
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "PATH="+tools, "HOME="+dir, "CLAUDE_PLUGIN_ROOT="+dir, "TAINTWATCH_HOME="+filepath.Join(dir, "state"), "TAINTWATCH_NO_BOOTSTRAP=1", "TAINTWATCH_FAIL_MODE="+mode)
				b, e := cmd.Output()
				if e != nil {
					t.Fatal(e)
				}
				if mode == "open" && len(b) != 0 {
					t.Fatal(string(b))
				}
				if mode == "closed" && !strings.Contains(string(b), map[string]string{"pre": "permissionDecision", "post": "additionalContext"}[kind]) {
					t.Fatal(string(b))
				}
				if kind == "post" && strings.Contains(string(b), "permissionDecision") {
					t.Fatal(string(b))
				}
			})
		}
	}
}

func TestLauncher(t *testing.T) {
	launcher, e := filepath.Abs("../../bin/taintwatch-launcher")
	if e != nil {
		t.Fatal(e)
	}
	for _, scenario := range []string{"bundled", "path", "download", "bad-checksum", "failed-download", "hook-no-bootstrap"} {
		t.Run(scenario, func(t *testing.T) {
			d := t.TempDir()
			root := filepath.Join(d, "plugin")
			tools := filepath.Join(d, "tools")
			home := filepath.Join(d, "home")
			for _, p := range []string{filepath.Join(root, "bin"), tools, home} {
				if e := os.MkdirAll(p, 0700); e != nil {
					t.Fatal(e)
				}
			}
			put := func(path, s string) {
				t.Helper()
				if e := os.WriteFile(path, []byte(s), 0700); e != nil {
					t.Fatal(e)
				}
			}
			// Isolate PATH so the host's taintwatch or curl can never be invoked.
			for _, name := range []string{"uname", "mkdir", "dirname", "mktemp", "rm", "rmdir", "awk", "chmod", "mv", "cat", "sha256sum", "shasum"} {
				if p, e := exec.LookPath(name); e == nil {
					if e = os.Symlink(p, filepath.Join(tools, name)); e != nil {
						t.Fatal(e)
					}
				}
			}
			uname, e := exec.Command("uname", "-s").Output()
			if e != nil {
				t.Fatal(e)
			}
			platform := "linux"
			if strings.TrimSpace(string(uname)) == "Darwin" {
				platform = "darwin"
			}
			archOut, _ := exec.Command("uname", "-m").Output()
			arch := "amd64"
			if strings.Contains(string(archOut), "arm64") || strings.Contains(string(archOut), "aarch64") {
				arch = "arm64"
			}
			asset := "taintwatch-" + platform + "-" + arch
			binary := "#!/bin/sh\nprintf 'executed:%s:%s\\n' \"$1\" \"$2\"\n"
			digest := fmt.Sprintf("%x", sha256.Sum256([]byte(binary)))
			if scenario == "bad-checksum" {
				digest = strings.Repeat("0", 64)
			}
			fixture := filepath.Join(d, "fixture")
			put(fixture, binary)
			checks := filepath.Join(d, "checksums")
			put(checks, digest+"  "+asset+"\n")
			calls := filepath.Join(d, "calls")
			put(filepath.Join(tools, "curl"), `#!/bin/sh
printf 'call\n' >> "$CALLS"
[ "$SCENARIO" != failed-download ] || exit 22
previous=
url=
for arg do
    if [ "$previous" = -o ]; then output=$arg; fi
    case "$arg" in https:*) url=$arg;; esac
    previous=$arg
done
case "$url" in */checksums.txt) cat "$CHECKS" > "$output";; *) cat "$FIXTURE" > "$output";; esac
`)
			if scenario == "bundled" {
				put(filepath.Join(root, "bin", asset), binary)
			}
			if scenario == "path" {
				put(filepath.Join(tools, "taintwatch"), binary)
			}
			run := func() string {
				t.Helper()
				cmd := exec.Command("/bin/sh", launcher, "hook", "pre")
				cmd.Dir = home
				noBootstrap := "0"
				if scenario == "hook-no-bootstrap" {
					noBootstrap = "1"
				}
				cmd.Env = append(os.Environ(), "PATH="+tools, "HOME="+home, "CLAUDE_PLUGIN_ROOT="+root, "TAINTWATCH_HOME="+filepath.Join(d, "state"), "TAINTWATCH_FAIL_MODE=closed", "TAINTWATCH_NO_BOOTSTRAP="+noBootstrap, "CALLS="+calls, "CHECKS="+checks, "FIXTURE="+fixture, "SCENARIO="+scenario)
				b, e := cmd.Output()
				if e != nil {
					t.Fatalf("launcher %v: %s", e, b)
				}
				return string(b)
			}
			got := run()
			success := scenario == "bundled" || scenario == "path" || scenario == "download"
			if success && !strings.Contains(got, "executed:hook:pre") {
				t.Fatal(got)
			}
			if !success && !strings.Contains(got, `"permissionDecision":"ask"`) {
				t.Fatal(got)
			}
			before, _ := os.ReadFile(calls)
			if scenario == "hook-no-bootstrap" {
				if len(before) != 0 {
					t.Fatal("hook performed bootstrap network request")
				}
				if _, e := os.Stat(filepath.Join(d, "state", "bootstrap", "0.1.0", "attempted")); !os.IsNotExist(e) {
					t.Fatal("hook consumed manual bootstrap attempt", e)
				}
			}
			if scenario == "download" { // cached executable is rechecked before every execution
				cache := filepath.Join(d, "state", "bootstrap", "0.1.0", asset)
				put(cache, "#!/bin/sh\necho UNVERIFIED\n")
				if got := run(); strings.Contains(got, "UNVERIFIED") || !strings.Contains(got, `"permissionDecision":"ask"`) {
					t.Fatal(got)
				}
			} else {
				run()
			}
			after, _ := os.ReadFile(calls)
			if string(before) != string(after) {
				t.Fatal("network retried on later run")
			}
			if (scenario == "bundled" || scenario == "path") && len(before) != 0 {
				t.Fatal("network despite local binary")
			}
		})
	}
}

func TestSettingsPermissionsAndLinks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "settings.json")
	if e := os.WriteFile(p, []byte(`{"unrelated":true}`), 0600); e != nil {
		t.Fatal(e)
	}
	_, backup, e := Change(p, "/bin/tw", false)
	if e != nil {
		t.Fatal(e)
	}
	for _, file := range []string{p, backup, p + ".taintwatch-install.json"} {
		info, e := os.Stat(file)
		if e != nil || info.Mode().Perm() != 0600 {
			t.Fatal(file, info, e)
		}
	}
	link := filepath.Join(dir, "link.json")
	if e := os.Symlink(p, link); e != nil {
		t.Fatal(e)
	}
	if _, _, e := Change(link, "/bin/tw", false); e == nil {
		t.Fatal("accepted symlink settings")
	}
	if e := os.Mkdir(p+".taintwatch-lock", 0700); e != nil {
		t.Fatal(e)
	}
	if _, _, e := Change(p, "/bin/tw", true); e == nil {
		t.Fatal("ignored installer lock")
	}
}
