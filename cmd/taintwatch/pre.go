package main

import (
	"flag"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/ratuhin1122/taintwatch/internal/audit"
	"github.com/ratuhin1122/taintwatch/internal/hookio"
	"github.com/ratuhin1122/taintwatch/internal/policy"
	"github.com/ratuhin1122/taintwatch/internal/rules"
	"github.com/ratuhin1122/taintwatch/internal/shellparse"
)

func preFailure(mode, stage string) postOutcome {
	o := postOutcome{failure: stage}
	if mode == "closed" {
		o.result = hookio.Ask("Taintwatch could not complete the safety check (" + stage + "); confirm this action before proceeding.")
	}
	return o
}
func finishPre(o postOutcome, out, errOut io.Writer) int {
	if o.failure != "" {
		fmt.Fprintln(errOut, "taintwatch pre: internal error at "+o.failure)
	}
	if _, err := o.result.Write(out); err != nil {
		fmt.Fprintln(errOut, "taintwatch pre: hook output unavailable")
	}
	return exitOK
}
func runPre(args []string, in io.Reader, out, errOut io.Writer) int {
	return runPreWithin(args, in, out, errOut, postTimeout)
}
func runPreWithin(args []string, in io.Reader, out, errOut io.Writer, timeout time.Duration) int {
	f := flag.NewFlagSet("hook pre", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("fail-mode", "", "internal error behavior; default from policy")
	if err := f.Parse(args); err == flag.ErrHelp {
		fmt.Fprintln(out, "Usage: taintwatch hook pre [--fail-mode open|closed]")
		return exitOK
	} else if err != nil || f.NArg() != 0 {
		return finishPre(preFailure(userErrorMode(*mode), "configuration"), out, errOut)
	}
	if *mode != "" && *mode != "open" && *mode != "closed" {
		return finishPre(preFailure(userErrorMode(""), "configuration"), out, errOut)
	}
	done := make(chan postOutcome, 1)
	var closed atomic.Bool
	closed.Store(*mode == "closed")
	errorMode := func() string {
		if closed.Load() {
			return "closed"
		}
		return "open"
	}
	go func() {
		defer func() {
			if recover() != nil {
				done <- preFailure(errorMode(), "internal panic")
			}
		}()
		done <- processPreObserved(in, *mode, func(mode string) { closed.Store(mode == "closed") })
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case o := <-done:
		return finishPre(o, out, errOut)
	case <-timer.C:
		return finishPre(preFailure(errorMode(), "deadline"), out, errOut)
	}
}
func processPre(reader io.Reader, mode string) postOutcome {
	return processPreObserved(reader, mode, nil)
}
func processPreObserved(reader io.Reader, override string, observe func(string)) postOutcome {
	boot, _ := policy.Load(policy.Options{NoProject: true})
	mode := boot.Config.FailMode
	if override != "" {
		mode = override
	}
	if observe != nil {
		observe(mode)
	}
	in, err := hookio.DecodePreToolUse(reader)
	if err != nil {
		return preFailure(mode, "input decoding")
	}
	loaded, policyErr := loadHookPolicy(in.CWD, override, "")
	mode = loaded.Config.FailMode
	if observe != nil {
		observe(mode)
	}
	warning := policyWarning(loaded, policyErr)
	store, err := policyStore(loaded.Config)
	if err != nil {
		return preFailure(mode, "state initialization")
	}
	record := audit.Record{Session: in.SessionID, Hook: "PreToolUse", Tool: in.ToolName, FailMode: mode}
	if warning != "" {
		record.PolicyWarnings = []string{warning}
	}
	failure := func(stage string) postOutcome {
		record.Rule = "pre.error"
		record.Reason = "pre hook error at " + stage
		record.Decision = "allow"
		if mode == "closed" {
			record.Decision = "ask"
		}
		o := preFailure(mode, stage)
		if audit.Write(store, record) != nil {
			o.failure += " and audit persistence"
		}
		return o
	}
	if policyErr != nil && mode == "closed" {
		return failure("policy loading")
	}
	args, err := in.SourceArguments()
	if err != nil {
		return failure("tool arguments")
	}
	session, err := store.Load(in.SessionID)
	if err != nil {
		return failure("state loading")
	}
	record.StateKnown = true
	record.Tainted = session.Tainted
	for _, e := range session.TaintEvents {
		record.TaintSources = append(record.TaintSources, string(e.Source))
	}
	p := rules.FromPolicy(loaded.Config)
	p.StateHome = store.Home()
	p.SelfPaths = append(append([]string{}, loaded.Files...), store.AuditFile())
	input := rules.Input{Policy: p, Session: session, Tool: in.ToolName, CWD: in.CWD, Command: args.Command, FilePath: args.FilePath, URL: args.URL}
	if in.ToolName == "Bash" {
		input.Shell = shellparse.Parse(args.Command)
	}
	d := rules.Evaluate(input)
	record.Decision = string(d.Action)
	record.Rule = d.RuleID
	record.Reason = d.Reason
	record.Evidence = d.Evidence
	if err := audit.Write(store, record); err != nil {
		o := preFailure(mode, "audit persistence")
		if d.Action == rules.Ask {
			o.result = hookio.Ask(d.Reason)
		} else if d.Action == rules.Deny {
			o.result = hookio.Deny(d.Reason)
		}
		return o
	}
	switch d.Action {
	case rules.Ask:
		return postOutcome{result: hookio.Ask(d.Reason), failure: warning}
	case rules.Deny:
		return postOutcome{result: hookio.Deny(d.Reason), failure: warning}
	}
	// Abstain rather than overriding Claude Code's own permission checks.
	return postOutcome{failure: warning}
}
