package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/user"
	"strconv"
	"strings"

	"github.com/ratuhin1122/taintwatch/internal/audit"
	"github.com/ratuhin1122/taintwatch/internal/policy"
	"github.com/ratuhin1122/taintwatch/internal/state"
)

func confirmChange(in io.Reader, out io.Writer, yes, terminal bool) error {
	if yes {
		return nil
	}
	if !terminal {
		return errors.New("refusing non-interactive policy change; review the diff and explicitly pass --yes, or run in a terminal")
	}
	if _, e := fmt.Fprint(out, "Apply this USER policy change? [y/N] "); e != nil {
		return e
	}
	answer, e := bufio.NewReader(io.LimitReader(in, 16)).ReadString('\n')
	if e != nil && e != io.EOF {
		return e
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer != "y" && answer != "yes" {
		return errors.New("cancelled; policy unchanged")
	}
	return nil
}
func runAllow(name string, args []string, in io.Reader, out, errOut io.Writer) int {
	help := func() {
		fmt.Fprintf(out, "Usage: taintwatch %s <domain HOST|path FILE> [--yes]\nChanges USER policy only. Paths exempt exact files from TW001 secret reads, not other rules.\n", name)
	}
	yes := false
	pos := []string{}
	for _, arg := range args {
		switch arg {
		case "--help", "-h":
			help()
			return 0
		case "--yes":
			yes = true
		default:
			pos = append(pos, arg)
		}
	}
	if len(pos) != 2 {
		help()
		return 2
	}
	proposal, e := policy.PrepareUserEdit(pos[0], pos[1], name == "disallow")
	if e != nil {
		fmt.Fprintln(errOut, audit.Redact(e.Error()))
		return 1
	}
	if !proposal.Changed() {
		fmt.Fprintln(out, "No changes needed.")
		return 0
	}
	if _, e = fmt.Fprintln(out, "Persistent exception scope: domain = TW002 exact host; path = TW001 exact file only."); e != nil {
		return 1
	}
	if _, e = io.WriteString(out, audit.Redact(proposal.Diff())); e != nil {
		return 1
	}
	if e = confirmChange(in, out, yes, terminalInput(in)); e != nil {
		fmt.Fprintln(errOut, e)
		return 1
	}
	backup, e := proposal.Commit()
	if e != nil {
		fmt.Fprintln(errOut, audit.Redact(e.Error()))
		return 1
	}
	fmt.Fprintf(out, "Updated USER policy %s.\n", strconv.Quote(proposal.Path))
	if backup != "" {
		fmt.Fprintf(out, "Backup: %s\n", strconv.Quote(backup))
	}
	fmt.Fprintln(out, "Project restrictions and other matching rules still apply.")
	return 0
}
func runClear(args []string, out, errOut io.Writer) int {
	f := flag.NewFlagSet("clear", flag.ContinueOnError)
	f.SetOutput(errOut)
	id := f.String("session", "", "session ID; default most recent persisted session")
	reason := f.String("reason", "", "required explanation for explicit clear")
	f.Usage = func() {
		fmt.Fprintln(f.Output(), "Usage: taintwatch clear [--session ID] --reason TEXT\nExplicitly clears taint and records the OS identity and reason; never automatic.")
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		f.SetOutput(out)
		f.Usage()
		return 0
	}
	if e := f.Parse(args); e != nil {
		return 2
	}
	if f.NArg() != 0 || strings.TrimSpace(*reason) == "" || len(*reason) > 512 {
		fmt.Fprintln(errOut, "clear requires --reason containing 1..512 bytes and no positional arguments")
		return 2
	}
	loaded, e := policy.Load(policy.Options{})
	if e != nil {
		fmt.Fprintln(errOut, "invalid policy; run taintwatch policy check")
		return 1
	}
	policyNotices(loaded, errOut)
	store, e := policyStore(loaded.Config)
	if e != nil {
		fmt.Fprintln(errOut, "clear: state unavailable")
		return 1
	}
	var session state.Session
	var found bool
	if *id == "" {
		session, found, e = store.Latest()
	} else {
		// Accept both the raw transport ID and the safe key printed by status.
		session, found, e = store.LoadKey(*id)
		if e != nil || !found {
			session, found, e = store.LoadKey(state.SanitizeSessionID(*id))
		}
	}
	if e != nil || !found {
		fmt.Fprintln(errOut, "clear: no matching persisted session; supply --session ID after checking status")
		return 1
	}
	actor, e := user.Current()
	if e != nil || actor.Uid == "" {
		fmt.Fprintln(errOut, "clear: cannot determine OS identity")
		return 1
	}
	who := audit.Redact("uid:" + actor.Uid + " (" + actor.Username + ")")
	why := audit.Redact(strings.TrimSpace(*reason))
	record := audit.Record{Session: session.ID, Hook: "CLI", Tool: "clear", Decision: "requested", Rule: "session.clear.requested", Who: who, Reason: why, Tainted: session.Tainted, StateKnown: true, FailMode: loaded.Config.FailMode}
	for _, ev := range session.TaintEvents {
		record.TaintSources = append(record.TaintSources, string(ev.Source))
	}
	// Persist intent first. If audit is unavailable, taint is never cleared.
	if e = audit.Write(store, record); e != nil {
		fmt.Fprintln(errOut, "clear: audit unavailable; taint was not cleared")
		return 1
	}
	if _, e = store.Clear(session.ID, why, who); e != nil {
		fmt.Fprintln(errOut, "clear: state update failed; clear intent is recorded")
		return 1
	}
	record.Decision = "clear"
	record.Rule = "session.clear"
	record.Tainted = false
	record.TaintSources = nil
	if e = audit.Write(store, record); e != nil {
		fmt.Fprintln(errOut, "clear: taint cleared, but completion audit failed; the durable intent contains who and why")
		return 1
	}
	fmt.Fprintf(out, "Cleared session %s by %s. Reason: %s\n", strconv.Quote(state.SanitizeSessionID(session.ID)), strconv.Quote(who), strconv.Quote(why))
	return 0
}
