package main

import (
	"fmt"
	"io"
	"time"

	"github.com/ratuhin1122/taintwatch/internal/policy"
	"github.com/ratuhin1122/taintwatch/internal/state"
)

func policyStore(p policy.Config) (*state.Store, error) {
	return state.New(state.Options{AuditPath: p.Log.Path, AuditMaxBytes: p.Log.Rotation.MaxBytes, AuditKeep: p.Log.Rotation.Keep, Retention: time.Duration(p.State.RetentionDays) * 24 * time.Hour})
}
func policyNotices(p policy.Effective, w io.Writer) {
	for _, v := range p.Ignored {
		fmt.Fprintf(w, "Ignored %s at %s: %s\n", v.Path, v.Origin, v.Reason)
	}
}
func runPolicy(args []string, out, errOut io.Writer) int {
	help := func() { fmt.Fprintln(out, "Usage: taintwatch policy check [file]\n       taintwatch policy show") }
	if len(args) == 0 || len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		help()
		return exitOK
	}
	if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") && (args[0] == "show" || args[0] == "check") {
		help()
		return exitOK
	}
	if args[0] == "check" && len(args) <= 2 {
		if len(args) == 2 {
			if err := policy.Check(args[1]); err != nil {
				fmt.Fprintln(errOut, err)
				return exitFailure
			}
			fmt.Fprintln(out, "Policy is valid (project trust restrictions apply when loaded).")
			return exitOK
		}
		p, err := policy.Load(policy.Options{})
		if err != nil {
			fmt.Fprintln(errOut, err)
			return exitFailure
		}
		policyNotices(p, errOut)
		fmt.Fprintln(out, "Effective policy is valid.")
		return exitOK
	}
	if args[0] == "show" && len(args) == 1 {
		p, err := policy.Load(policy.Options{})
		if err != nil {
			fmt.Fprintln(errOut, err)
			return exitFailure
		}
		policyNotices(p, errOut)
		if err = p.Show(out); err != nil {
			fmt.Fprintln(errOut, "could not write policy")
			return exitFailure
		}
		return exitOK
	}
	fmt.Fprintln(errOut, "invalid policy command or arguments")
	return exitUsage
}

// Invalid project policy cannot bypass the last valid protections.
func loadHookPolicy(cwd, mode, profile string) (policy.Effective, error) {
	p, err := policy.Load(policy.Options{CWD: cwd})
	if mode != "" {
		p.Config.FailMode = mode
	}
	if profile != "" {
		p.Config.Profile = profile
	}
	return p, err
}
func userErrorMode(override string) string {
	if override == "open" || override == "closed" {
		return override
	}
	p, _ := policy.Load(policy.Options{NoProject: true})
	return p.Config.FailMode
}
