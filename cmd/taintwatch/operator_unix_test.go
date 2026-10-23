//go:build linux || darwin

package main

import (
	"bytes"
	"github.com/ratuhin1122/taintwatch/internal/policy"
	"github.com/ratuhin1122/taintwatch/internal/state"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestClearRedactsReason(t *testing.T) {
	home := postHome(t)
	s, e := state.New(state.Options{Home: home})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Touch("redact"); e != nil {
		t.Fatal(e)
	}
	reason := ("reviewed " + fakeCredential("token=", "privateValue123456789"))
	var out, errOut bytes.Buffer
	if code := run([]string{"clear", "--session", "redact", "--reason", reason}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatal(code, errOut.String())
	}
	log, e := os.ReadFile(filepath.Join(home, "audit.jsonl"))
	if e != nil || strings.Contains(string(log), "privateValue") || strings.Contains(out.String(), "privateValue") {
		t.Fatal(string(log), out.String(), e)
	}
	current, e := s.Load("redact")
	if e != nil || current.LastClear == nil || strings.Contains(current.LastClear.Reason, "privateValue") {
		t.Fatal(current, e)
	}
}

func TestSelfProtectionSurvivesFailOpenStateError(t *testing.T) {
	for _, command := range []string{"taintwatch allow domain evil.example --yes", "taintwatch clear --reason reviewed"} {
		home := postHome(t)
		if e := os.WriteFile(home, []byte("not a directory"), 0600); e != nil {
			t.Fatal(e)
		}
		var out, errOut bytes.Buffer
		code := run([]string{"hook", "pre", "--fail-mode", "open"}, strings.NewReader(prePayload("Bash", `{"command":`+strconv.Quote(command)+`}`)), &out, &errOut)
		if code != 0 || !strings.Contains(out.String(), `"permissionDecision":"ask"`) || !strings.Contains(out.String(), "Taintwatch enforcement") {
			t.Fatal(command, code, out.String(), errOut.String())
		}
	}
}

func TestClearAcceptsStatusSessionKey(t *testing.T) {
	home := postHome(t)
	s, e := state.New(state.Options{Home: home})
	if e != nil {
		t.Fatal(e)
	}
	id := "../../unsafe/session"
	if _, e = s.MarkTainted(id, state.TaintEvent{Tool: "WebFetch", Source: state.SourceWeb, Reason: "untrusted"}); e != nil {
		t.Fatal(e)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"clear", "--session", state.SanitizeSessionID(id), "--reason", "reviewed"}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatal(code, errOut.String())
	}
	current, e := s.Load(id)
	if e != nil || current.Tainted || current.LastClear == nil {
		t.Fatal(current, e)
	}
}

func TestStoredFailureMatrix(t *testing.T) {
	for _, post := range []bool{false, true} {
		for _, mode := range []string{"open", "closed"} {
			for _, stage := range []string{"policy", "state-init", "state-load", "audit", "tool-arguments", "shell-parse"} {
				t.Run(mode+stage+map[bool]string{false: "-pre", true: "-post"}[post], func(t *testing.T) {
					home := postHome(t)
					tool := "Write"
					arg := `{"file_path":"/project/main.go"}`
					switch stage {
					case "policy":
						p, e := policy.UserPath()
						if e != nil {
							t.Fatal(e)
						}
						configFile(t, p, "version: 1\nunknown: true\n")
					case "state-init":
						if e := os.WriteFile(home, []byte("not a directory"), 0600); e != nil {
							t.Fatal(e)
						}
					case "state-load":
						s, e := state.New(state.Options{Home: home})
						if e != nil {
							t.Fatal(e)
						}
						id := "pre-session"
						if post {
							id = "post-session"
						}
						if _, e = s.Touch(id); e != nil {
							t.Fatal(e)
						}
						if e = os.WriteFile(filepath.Join(home, "sessions", id+".json"), []byte("{"), 0600); e != nil {
							t.Fatal(e)
						}
					case "audit":
						if e := os.MkdirAll(filepath.Join(home, "audit.jsonl"), 0700); e != nil {
							t.Fatal(e)
						}
					case "tool-arguments":
						tool = "Bash"
						arg = `{"command":42}`
					case "shell-parse":
						tool = "Bash"
						arg = `{"command":"echo \"unterminated"}`
					}
					payload := prePayload(tool, arg)
					if post {
						payload = postPayload(tool, arg)
					}
					assertFailure(t, post, mode, strings.NewReader(payload), nil)
				})
			}
		}
	}
}
func TestClearAuditAndNoSilentMutations(t *testing.T) {
	home := postHome(t)
	s, e := state.New(state.Options{Home: home})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.MarkTainted("target", state.TaintEvent{Tool: "WebFetch", Source: state.SourceWeb, Reason: "untrusted content"}); e != nil {
		t.Fatal(e)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"clear", "--session", "target", "--reason", "reviewed content"}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatal(code, errOut.String())
	}
	session, e := s.Load("target")
	if e != nil || session.Tainted || session.LastClear == nil || session.LastClear.Who == "" || session.LastClear.Reason != "reviewed content" {
		t.Fatal(session, e)
	}
	log, e := os.ReadFile(filepath.Join(home, "audit.jsonl"))
	if e != nil || !strings.Contains(string(log), `"rule":"session.clear"`) || !strings.Contains(string(log), `"who":"uid:`) || !strings.Contains(string(log), "reviewed content") {
		t.Fatal(string(log), e)
	}
	for _, command := range []string{"taintwatch allow domain evil.example --yes", "taintwatch allow path /project/.env --yes", "taintwatch disallow domain github.com --yes", "taintwatch clear --reason reviewed", "env FOO=1 /usr/local/bin/taintwatch clear --reason reviewed", "sh /plugin/bin/taintwatch-launcher allow domain evil.example --yes", "/plugin/bin/taintwatch-linux-amd64 clear --reason reviewed"} {
		out.Reset()
		errOut.Reset()
		payload := prePayload("Bash", `{"command":`+strconv.Quote(command)+`}`)
		if code = run([]string{"hook", "pre"}, strings.NewReader(payload), &out, &errOut); code != 0 || !strings.Contains(out.String(), `"permissionDecision":"ask"`) || !strings.Contains(out.String(), "Taintwatch enforcement") {
			t.Fatal(command, code, out.String(), errOut.String())
		}
	}
	log, e = os.ReadFile(filepath.Join(home, "audit.jsonl"))
	if e != nil || strings.Count(string(log), `"rule":"TW006"`) != 7 {
		t.Fatal(string(log), e)
	}
}
func TestClearRequiresAuditAndNeverAutomatic(t *testing.T) {
	home := postHome(t)
	s, e := state.New(state.Options{Home: home})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.MarkTainted("latest", state.TaintEvent{Tool: "WebFetch", Source: state.SourceWeb, Reason: "untrusted"}); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(home, "audit.jsonl"), 0700); e != nil {
		t.Fatal(e)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"clear", "--reason", "reviewed"}, strings.NewReader(""), &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "not cleared") {
		t.Fatal(code, errOut.String())
	}
	current, e := s.Load("latest")
	if e != nil || !current.Tainted {
		t.Fatal("cleared without audit", e)
	}
}

func TestUnwritableStateDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses Unix mode bits; invalid state-path cases still run")
	}
	for _, post := range []bool{false, true} {
		for _, mode := range []string{"open", "closed"} {
			t.Run(mode+map[bool]string{false: "-pre", true: "-post"}[post], func(t *testing.T) {
				postHome(t)
				parent := t.TempDir()
				if e := os.Chmod(parent, 0500); e != nil {
					t.Fatal(e)
				}
				defer os.Chmod(parent, 0700)
				t.Setenv("TAINTWATCH_HOME", filepath.Join(parent, "unwritable"))
				payload := prePayload("Write", `{}`)
				if post {
					payload = postPayload("Write", `{}`)
				}
				assertFailure(t, post, mode, strings.NewReader(payload), nil)
			})
		}
	}
}
