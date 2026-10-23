package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/ratuhin1122/taintwatch/internal/audit"
	"github.com/ratuhin1122/taintwatch/internal/explain"
	"github.com/ratuhin1122/taintwatch/internal/policy"
	"github.com/ratuhin1122/taintwatch/internal/state"
)

func runInspect(name string, args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(errOut)
	sessionID := flags.String("session", "", "session ID; default most recent")
	last := 10
	asJSON := false
	if name == "explain" {
		flags.IntVar(&last, "last", 10, "recent decisions (1..1000)")
		flags.BoolVar(&asJSON, "json", false, "structured output")
	}
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: taintwatch %s [--session ID]", name)
		if name == "explain" {
			fmt.Fprint(flags.Output(), " [--last N] [--json]")
		}
		fmt.Fprintln(flags.Output())
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		flags.SetOutput(out)
		flags.Usage()
		return exitOK
	}
	if e := flags.Parse(args); e != nil {
		return exitUsage
	}
	if flags.NArg() != 0 || last < 1 || last > 1000 {
		fmt.Fprintln(errOut, "invalid arguments; --last must be 1..1000")
		return exitUsage
	}
	loaded, e := policy.Load(policy.Options{})
	if e != nil {
		fmt.Fprintln(errOut, e)
		return exitFailure
	}
	policyNotices(loaded, errOut)
	store, e := policyStore(loaded.Config)
	if e != nil {
		fmt.Fprintln(errOut, "taintwatch "+name+": state is unavailable")
		return exitFailure
	}
	h, e := audit.Query(store, *sessionID, last)
	if e != nil {
		fmt.Fprintln(errOut, "taintwatch "+name+": could not read audit history")
		return exitFailure
	}
	if name == "explain" {
		global, err := store.Load(state.ObservationLossSession)
		if err != nil {
			fmt.Fprintln(errOut, "taintwatch explain: observation state unavailable")
			return exitFailure
		}
		h.Degraded, h.DegradedReason = global.Degraded, global.DegradedReason
		key := h.Session
		if *sessionID != "" {
			key = state.SanitizeSessionID(*sessionID)
		}
		if key != "" {
			current, found, err := store.LoadKey(key)
			if err != nil {
				fmt.Fprintln(errOut, "taintwatch explain: session state unavailable")
				return exitFailure
			}
			if found && current.Degraded {
				h.Degraded = true
				h.DegradedReason = current.DegradedReason
			}
		}
		e = explain.Render(out, h, asJSON)
	} else {
		var current state.Session
		known := false
		if *sessionID != "" {
			current, known, e = store.LoadKey(state.SanitizeSessionID(*sessionID))
			if e == nil && !known {
				fmt.Fprintln(out, "session not found")
				return exitOK
			}
		} else if h.Session != "" {
			current, known, e = store.LoadKey(h.Session)
		} else {
			current, known, e = store.Latest()
			if known {
				h, e = audit.Query(store, current.ID, last)
			}
		}
		if e != nil {
			fmt.Fprintln(errOut, "taintwatch status: could not read session state")
			return exitFailure
		}
		global, globalErr := store.Load(state.ObservationLossSession)
		if globalErr != nil {
			fmt.Fprintln(errOut, "taintwatch status: observation state unavailable")
			return exitFailure
		}
		if global.Degraded {
			current.Degraded = true
			current.DegradedReason = global.DegradedReason
		}
		e = explain.StatusWithPolicy(out, current, known, h, loaded.Files)
	}
	if e != nil {
		fmt.Fprintln(errOut, "taintwatch "+name+": output unavailable")
		return exitFailure
	}
	return exitOK
}
