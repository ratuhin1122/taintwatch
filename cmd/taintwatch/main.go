// Command taintwatch provides the Taintwatch command-line interface.
// Taintwatch is defense-in-depth with an audit trail, not a solution to prompt injection.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// version is set by the build's -ldflags; direct go builds use dev.
var version = "dev"

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
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
	case "hook":
		return runHook(args[1:], stdout, stderr)
	case "explain", "status", "version":
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

func runHook(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(stdout, "Usage: taintwatch hook <pre|post|prompt|session-start> [--help]")
		fmt.Fprintln(stdout, "Scaffold only: hook handlers do not yet read stdin or enforce policy.")
		return exitOK
	}
	if len(args) == 0 {
		fmt.Fprintln(stderr, "hook requires pre, post, prompt, or session-start")
		return exitUsage
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
	fmt.Fprintln(w, "Commands: hook <pre|post|prompt|session-start>, explain, status, version")
	fmt.Fprintln(w, "Exit codes: 0 success/help; 1 unavailable or failed operation; 2 invalid CLI usage.")
}
