//go:build linux || darwin

package hookio

import (
	"bytes"
	stdcontext "context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Representative fake canaries prove omission/redaction for these cases, not
// universal recognition of arbitrary secrets.
func TestBinaryAuditSecretsAndModes(t *testing.T) {
	temp := t.TempDir()
	project, home := filepath.Join(temp, "project"), filepath.Join(temp, "state")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(temp, "taintwatch")
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/taintwatch")
	build.Dir = root
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, b)
	}
	env := []string{}
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "TAINTWATCH_") && !strings.HasPrefix(value, "HOME=") {
			env = append(env, value)
		}
	}
	env = append(env, "TAINTWATCH_HOME="+home, "HOME="+filepath.Join(temp, "user"), "TAINTWATCH_AUDIT_MAX_BYTES=2048", "TAINTWATCH_AUDIT_KEEP=3")
	canaries := []string{"AKIAABCDEFGHIJKLMNOP", "ghp_m46FakeCredential123456789", "m46BearerCredential123", "m46PasswordCredential123", "m46PrivateKeyBody", "m46OpaqueBodyNeverLog"}
	knownSecrets := canaries[0] + " " + canaries[1] + " Bearer " + canaries[2] + " password=" + canaries[3] + "\n-----BEGIN PRIVATE KEY-----\n" + canaries[4] + "\n-----END PRIVATE KEY-----"
	secret := knownSecrets + "\n" + canaries[5]
	session := "../../audit-canary"
	auditRecords := 0
	inspect := func() {
		t.Helper()
		files, err := filepath.Glob(filepath.Join(home, "audit.jsonl*"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range files {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for i, canary := range canaries {
				if bytes.Contains(data, []byte(canary)) {
					t.Fatalf("canary %d reached audit log", i)
				}
			}
			auditRecords += bytes.Count(data, []byte("\n"))
		}
		err = filepath.WalkDir(home, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			want := os.FileMode(0600)
			if entry.IsDir() {
				want = 0700
			}
			if info.Mode().Perm() != want {
				t.Errorf("mode %s = %o, want %o", entry.Name(), info.Mode().Perm(), want)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	invoke := func(input []byte, args ...string) {
		t.Helper()
		runCtx, stop := stdcontext.WithTimeout(stdcontext.Background(), 5*time.Second)
		defer stop()
		command := exec.CommandContext(runCtx, binary, args...)
		command.Dir, command.Env, command.Stdin = project, env, bytes.NewReader(input)
		var output, diagnostic bytes.Buffer
		command.Stdout, command.Stderr = &output, &diagnostic
		if err := command.Run(); err != nil || diagnostic.Len() != 0 {
			t.Fatalf("binary failed: %v (diagnostic length %d)", err, diagnostic.Len())
		}
		inspect()
	}
	for n := 0; n < 8; n++ {
		input := map[string]any{"session_id": session, "cwd": project, "hook_event_name": "PostToolUse", "tool_name": "WebFetch", "tool_input": map[string]string{"url": "https://docs.example/guide"}, "tool_response": "<!-- " + secret + " -->\n\u200b"}
		data, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		invoke(data, "hook", "post")
		input["hook_event_name"], input["tool_name"] = "PreToolUse", "Bash"
		input["tool_input"] = map[string]string{"command": "printf '%s' '" + secret + "'"}
		delete(input, "tool_response")
		data, err = json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		invoke(data, "hook", "pre")
	}
	prompt, err := json.Marshal(map[string]any{"session_id": session, "cwd": project, "hook_event_name": "UserPromptSubmit", "prompt": "<!-- " + secret + " -->\n\u200b"})
	if err != nil {
		t.Fatal(err)
	}
	invoke(prompt, "hook", "prompt")
	// Free-form operator reasons are redacted by known patterns, not omitted.
	// Keep the opaque canary in tool bodies/arguments, whose omission is stronger.
	invoke(nil, "clear", "--session", session, "--reason", knownSecrets)
	if auditRecords == 0 {
		t.Fatal("no persisted audit records were inspected")
	}
	if _, err := os.Stat(filepath.Join(home, "audit.jsonl.1")); err != nil {
		t.Fatal("rotation was not exercised", err)
	}
	entries, err := os.ReadDir(filepath.Join(home, "sessions"))
	if err != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "sha256-") {
		t.Fatal("hostile session did not stay in hashed namespace", err)
	}
}
