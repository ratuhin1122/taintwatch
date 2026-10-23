package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type blockedHookWriter struct {
	release  <-chan struct{}
	returned chan<- struct{}
}

func (w blockedHookWriter) Write(b []byte) (int, error) {
	<-w.release
	close(w.returned)
	return len(b), nil
}
func TestOutputDeadlineModes(t *testing.T) {
	operatorHome(t)
	for _, post := range []bool{false, true} {
		for _, mode := range []string{"open", "closed"} {
			release := make(chan struct{})
			returned := make(chan struct{})
			writer := blockedHookWriter{release, returned}
			start := time.Now()
			code := 0
			if post {
				code = runPostWithin([]string{"--fail-mode", mode}, strings.NewReader("{"), writer, io.Discard, 250*time.Millisecond)
			} else {
				code = runPreWithin([]string{"--fail-mode", mode}, strings.NewReader("{"), writer, io.Discard, 250*time.Millisecond)
			}
			close(release)
			select {
			case <-returned:
			case <-time.After(time.Second):
				t.Fatal("writer was not reached")
			}
			want := 0
			if !post && mode == "closed" {
				want = 2
			}
			if code != want || time.Since(start) > time.Second {
				t.Fatal(post, mode, code, time.Since(start))
			}
		}
	}

}

type panicHookReader struct{}

func (panicHookReader) Read([]byte) (int, error) { panic("secret panic text must not be logged") }

type errorHookReader struct{}

func (errorHookReader) Read([]byte) (int, error) {
	return 0, errors.New("secret I/O error must not be logged")
}
func assertFailure(t *testing.T, post bool, mode string, input io.Reader, args []string) {
	t.Helper()
	var out, errOut bytes.Buffer
	flags := append([]string{"--fail-mode", mode}, args...)
	code := 0
	if post {
		code = runPost(flags, input, &out, &errOut)
	} else {
		code = runPre(flags, input, &out, &errOut)
	}
	if code != 0 || errOut.Len() == 0 || strings.Contains(errOut.String(), "secret") {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	if mode == "open" {
		if out.String() != "{}\n" {
			t.Fatal(out.String())
		}
	} else if post {
		if !strings.Contains(out.String(), "additionalContext") || strings.Contains(out.String(), "permissionDecision") {
			t.Fatal(out.String())
		}
	} else if !strings.Contains(out.String(), `"permissionDecision":"ask"`) {
		t.Fatal(out.String())
	}
}
func TestPortableFailureMatrix(t *testing.T) {
	operatorHome(t)
	for _, post := range []bool{false, true} {
		for _, mode := range []string{"open", "closed"} {
			for _, tc := range []struct {
				name   string
				reader func() io.Reader
				args   []string
			}{{"bad-stdin", func() io.Reader { return strings.NewReader("{") }, nil}, {"read-error", func() io.Reader { return errorHookReader{} }, nil}, {"panic", func() io.Reader { return panicHookReader{} }, nil}, {"bad-flags", func() io.Reader { return strings.NewReader("") }, []string{"--invalid"}}} {
				t.Run(mode+tc.name+map[bool]string{false: "-pre", true: "-post"}[post], func(t *testing.T) { assertFailure(t, post, mode, tc.reader(), tc.args) })
			}
		}
	}
}
func TestDeadlineModes(t *testing.T) {
	operatorHome(t)
	for _, post := range []bool{false, true} {
		for _, mode := range []string{"open", "closed"} {
			t.Run(mode+map[bool]string{false: "-pre", true: "-post"}[post], func(t *testing.T) {
				release := make(chan struct{})
				returned := make(chan struct{})
				var out, errOut bytes.Buffer
				start := time.Now()
				var code int
				workerDone := make(chan struct{})
				args := []string{"--fail-mode", mode}
				code = guardedHook(args, blockedPostReader{release, returned}, &out, &errOut, 250*time.Millisecond, post, func(ctx context.Context, r io.Reader, observe func(string)) postOutcome {
					defer close(workerDone)
					if post {
						return postWork(ctx, args, r, observe)
					}
					return preWork(ctx, args, r, observe)
				})
				close(release)
				// The production process exits after returning its decision. This
				// in-process test must join the released reader worker before its
				// temporary HOME is removed, including deferred degraded writes.
				select {
				case <-workerDone:
				case <-time.After(time.Second):
					t.Fatal("released hook worker did not finish")
				}
				// A cancelled context may skip the underlying Read altogether.
				if code != 0 || time.Since(start) > time.Second || !strings.Contains(errOut.String(), "deadline") {
					t.Fatal(code, out.String(), errOut.String())
				}
				if mode == "open" && post && out.String() != "{}\n" {
					t.Fatal(out.String())
				}
				if !post && !strings.Contains(out.String(), `"permissionDecision":"ask"`) {
					t.Fatal("pre deadline must ask", out.String())
				}
				if mode == "closed" && !strings.Contains(out.String(), map[bool]string{true: "additionalContext", false: "permissionDecision"}[post]) {
					t.Fatal(out.String())
				}
			})
		}
	}
}
func TestOutputErrorModes(t *testing.T) {
	operatorHome(t)
	for _, post := range []bool{false, true} {
		for _, mode := range []string{"open", "closed"} {
			var errOut bytes.Buffer
			code := 0
			if post {
				code = runPost([]string{"--fail-mode", mode}, strings.NewReader("{"), postErrorWriter{}, &errOut)
			} else {
				code = runPre([]string{"--fail-mode", mode}, strings.NewReader("{"), postErrorWriter{}, &errOut)
			}
			want := 0
			if !post && mode == "closed" {
				want = 2
			}
			if code != want || !strings.Contains(errOut.String(), "output") {
				t.Fatal(post, mode, code, errOut.String())
			}
		}
	}
}

func TestInvalidFlagsStillHonorExplicitMode(t *testing.T) {
	operatorHome(t)
	for _, post := range []bool{false, true} {
		var out, errOut bytes.Buffer
		args := []string{"--unknown", "--fail-mode", "closed"}
		code := 0
		if post {
			code = runPost(args, strings.NewReader("{"), &out, &errOut)
		} else {
			code = runPre(args, strings.NewReader("{"), &out, &errOut)
		}
		if code != 0 || !strings.Contains(out.String(), map[bool]string{false: "permissionDecision", true: "additionalContext"}[post]) {
			t.Fatal(post, code, out.String())
		}
	}
}
