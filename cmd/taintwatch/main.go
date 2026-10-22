// Command taintwatch provides the Taintwatch command-line interface.
// Taintwatch is defense-in-depth with an audit trail, not a solution to prompt injection.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

// version is set by the build's -ldflags; direct go builds use dev.
var version = "dev"

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

func main() {
	// Bound the entire command, including a stuck output pipe or filesystem call.
	// This final watchdog cannot reliably emit context through a broken transport.
	var watchdog *time.Timer
	if len(os.Args) >= 3 && os.Args[1] == "hook" && (os.Args[2] == "post" || os.Args[2] == "pre" || os.Args[2] == "prompt") {
		watchdogClosed.Store(initialClosed(os.Args[3:]))
		pre := os.Args[2] == "pre"
		watchdog = time.AfterFunc(hookHardTimeout, func() {
			if pre && watchdogClosed.Load() {
				os.Exit(2)
			}
			os.Exit(exitOK)
		})
	}
	code := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	if watchdog != nil {
		watchdog.Stop()
	}
	os.Exit(code)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	name := args[0]
	if name == "--help" || name == "-h" || name == "help" {
		if len(args) != 1 {
			fmt.Fprintln(stderr, "help takes no arguments")
			return exitUsage
		}
		usage(stdout)
		return exitOK
	}
	switch name {
	case "replay":
		return runReplay(args[1:], stdout, stderr)
	case "eval":
		return runEval(args[1:], stdout, stderr)
	case "allow", "disallow":
		return runAllow(name, args[1:], stdin, stdout, stderr)
	case "clear":
		return runClear(args[1:], stdout, stderr)
	case "install", "uninstall", "doctor":
		return runInstallation(name, args[1:], stdout, stderr)
	case "hook":
		return runHook(args[1:], stdin, stdout, stderr)
	case "policy":
		return runPolicy(args[1:], stdout, stderr)
	case "explain", "status":
		return runInspect(name, args[1:], stdout, stderr)
	case "version":
		fs := flag.NewFlagSet(name, flag.ContinueOnError)
		fs.SetOutput(stderr)
		fs.Usage = func() { fmt.Fprintf(fs.Output(), "Usage: taintwatch %s [--help]\n", name) }
		if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
			fs.SetOutput(stdout)
			fs.Usage()
			return exitOK
		}
		if err := fs.Parse(args[1:]); err != nil {
			return exitUsage
		}
		if fs.NArg() != 0 {
			fmt.Fprintf(stderr, "%s takes no arguments\n", name)
			return exitUsage
		}
		if name == "version" {
			fmt.Fprintln(stdout, version)
			return exitOK
		}
		fmt.Fprintf(stderr, "%s: not implemented (scaffold only)\n", name)
		return exitFailure
	default:
		fmt.Fprintf(stderr, "unknown subcommand %q\n", name)
		usage(stderr)
		return exitUsage
	}
}

func runHook(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(stdout, "Usage: taintwatch hook <pre|post|prompt|session-start> [--help]")
		fmt.Fprintln(stdout, "Pre checks actions; post records source taint; prompt records telemetry; session-start is a stub.")
		return exitOK
	}
	if len(args) == 0 {
		fmt.Fprintln(stderr, "hook requires pre, post, prompt, or session-start")
		return exitUsage
	}
	if args[0] == "post" {
		return runPost(args[1:], stdin, stdout, stderr)
	}
	if args[0] == "pre" {
		return runPre(args[1:], stdin, stdout, stderr)
	}
	if args[0] == "prompt" {
		return runPrompt(args[1:], stdin, stdout, stderr)
	}
	switch args[0] {
	case "pre", "post", "prompt", "session-start":
	default:
		fmt.Fprintf(stderr, "unknown hook %q\n", args[0])
		return exitUsage
	}
	if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		fmt.Fprintf(stdout, "Usage: taintwatch hook %s [--help]\nScaffold only: no hook processing or enforcement.\n", args[0])
		return exitOK
	}
	if len(args) != 1 {
		fmt.Fprintln(stderr, "hook handlers take no arguments")
		return exitUsage
	}
	// No fabricated Claude Code payload or decision schema is emitted by the scaffold.
	fmt.Fprintf(stderr, "hook %s: not implemented; no enforcement (scaffold only)\n", args[0])
	return exitFailure
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: taintwatch <command> [--help]")
	fmt.Fprintln(w, "Commands: hook <pre|post|prompt|session-start>, policy <check|show>, eval <validate|run>, replay, explain, status, version, install, uninstall, doctor, allow, disallow, clear")
	fmt.Fprintln(w, "Exit codes: 0 success/help; 1 unavailable or failed operation; 2 invalid CLI usage.")
}
