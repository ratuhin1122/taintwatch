package main

import (
	"context"
	"io"
	"time"

	"github.com/ratuhin1122/taintwatch/internal/audit"
	"github.com/ratuhin1122/taintwatch/internal/detect/hidden"
	"github.com/ratuhin1122/taintwatch/internal/detect/pasted"
	"github.com/ratuhin1122/taintwatch/internal/hookio"
)

func runPrompt(args []string, in io.Reader, out, errOut io.Writer) int {
	return runPromptWithin(args, in, out, errOut, postTimeout)
}

// Deliberately separate from permission-hook output/fail-mode handling. Normal
// execution cannot write stdout or return a blocking status, even on failure.
func runPromptWithin(args []string, in io.Reader, out, errOut io.Writer, timeout time.Duration) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		_, _ = io.WriteString(out, "Usage: taintwatch hook prompt [--help]\nTelemetry only; no prompt changes or permission decisions.\n")
		return exitOK
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	stage := ""
	if len(args) > 0 {
		stage = "arguments (prompt hook takes no arguments)"
	} else {
		done := make(chan string, 1)
		go func() {
			defer func() {
				if recover() != nil {
					done <- "internal panic"
				}
			}()
			done <- promptWork(ctx, contextReader{ctx, in})
		}()
		select {
		case stage = <-done:
		case <-ctx.Done():
			stage = "deadline"
		}
	}
	if stage != "" {
		// Diagnostics contain only fixed stage names, never prompt/policy content.
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() { _ = recover() }()
			_, _ = io.WriteString(errOut, "taintwatch prompt: telemetry skipped at "+stage+"; prompt unchanged\n")
		}()
		select {
		case <-done:
		case <-ctx.Done():
		}
	}
	return exitOK
}

func promptWork(ctx context.Context, in io.Reader) string {
	input, err := hookio.DecodeUserPromptSubmit(in)
	if err != nil {
		return "input decoding"
	}
	loaded, err := loadHookPolicy(input.CWD, "", "")
	if err != nil {
		return "policy loading"
	}
	if ctx.Err() != nil {
		return "deadline"
	}
	store, err := policyStore(loaded.Config)
	if err != nil {
		return "audit initialization"
	}
	h := hidden.Scan(input.Prompt)
	p := pasted.Scan(input.Prompt)
	if ctx.Err() != nil {
		return "deadline"
	}
	// No session Load/Touch/MarkTainted, approvals, classifier, or rules calls.
	r := audit.Record{Session: input.SessionID, Hook: "UserPromptSubmit", Tool: "prompt", Decision: "observe", Rule: "prompt.telemetry", Reason: "Prompt presentation and pasted-content hints recorded; no enforcement.", FailMode: "open", Hidden: &h, Pasted: &p}
	if err = audit.Write(store, r); err != nil {
		return "audit persistence"
	}
	return ""
}
