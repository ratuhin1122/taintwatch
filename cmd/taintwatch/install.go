package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/ratuhin1122/taintwatch/internal/install"
	"github.com/ratuhin1122/taintwatch/internal/policy"
	"github.com/ratuhin1122/taintwatch/internal/state"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func runInstallation(name string, args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() { fmt.Fprintf(fs.Output(), "Usage: taintwatch %s [--help]\n", name) }
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fs.SetOutput(out)
		fs.Usage()
		return 0
	}
	if e := fs.Parse(args); e != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return 2
	}
	binary, e := os.Executable()
	if e != nil {
		fmt.Fprintln(errOut, e)
		return 1
	}
	binary, e = filepath.EvalSymlinks(binary)
	if e != nil {
		fmt.Fprintln(errOut, e)
		return 1
	}
	path, e := install.SettingsPath()
	if e != nil {
		fmt.Fprintln(errOut, e)
		return 1
	}
	if name == "doctor" {
		return runDoctor(binary, path, out)
	}
	if runtime.GOOS == "windows" {
		fmt.Fprintln(errOut, "Run install/uninstall inside WSL; hooks require POSIX shell and Unix state locks.")
		return 1
	}
	changed, backup, e := install.Change(path, binary, name == "uninstall")
	if e != nil {
		fmt.Fprintln(errOut, e)
		return 1
	}
	if changed {
		fmt.Fprintf(out, "%s: updated %s\n", name, path)
		if backup != "" {
			fmt.Fprintf(out, "Backup: %s\n", backup)
		}
		fmt.Fprintln(out, "Restart Claude Code. Use doctor to check wiring; avoid enabling standalone and plugin hooks together.")
	} else {
		fmt.Fprintln(out, "No changes needed.")
	}
	return 0
}
func runDoctor(binary, path string, out io.Writer) int {
	checks := []install.Check{{Level: "PASS", Name: "binary", Detail: "version " + version}}
	if version == "dev" {
		checks[0] = install.Check{Level: "WARN", Name: "binary", Detail: "development build; use make build VERSION=0.1.0 for a versioned binary"}
	}
	if install.Wired(path, binary) {
		checks = append(checks, install.Check{Level: "PASS", Name: "hooks", Detail: "standalone pre/post hooks are wired"})
	} else {
		root := os.Getenv("CLAUDE_PLUGIN_ROOT")
		if root != "" {
			if install.PluginWired(root) {
				checks = append(checks, install.Check{Level: "PASS", Name: "hooks", Detail: "plugin pre/post configuration is present; confirm runtime delivery in /hooks"})
			} else {
				checks = append(checks, install.Check{Level: "FAIL", Name: "hooks", Detail: "plugin hook configuration is missing or unexpected; reinstall the plugin"})
			}
		} else {
			checks = append(checks, install.Check{Level: "WARN", Name: "hooks", Detail: "standalone wiring not found; run taintwatch install, or verify plugin hooks with /hooks"})
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, "claude", "--version").Output()
	if e != nil {
		checks = append(checks, install.Check{Level: "WARN", Name: "Claude Code", Detail: "version unavailable; install Claude Code and verify /hooks"})
	} else {
		v := strings.TrimSpace(string(b))
		if len(v) > 100 {
			v = v[:100]
		}
		checks = append(checks, install.Check{Level: "WARN", Name: "Claude Code", Detail: v + "; exact minimum for all hook features is unverified; validate and test real hook delivery"})
	}
	home, e := state.DefaultHome()
	if e != nil {
		checks = append(checks, install.Check{Level: "FAIL", Name: "state", Detail: "cannot resolve state directory; set TAINTWATCH_HOME"})
	} else if runtime.GOOS == "windows" {
		checks = append(checks, install.Check{Level: "FAIL", Name: "state", Detail: "Unix locks required; run inside WSL"})
	} else if info, er := os.Lstat(home); os.IsNotExist(er) {
		checks = append(checks, install.Check{Level: "WARN", Name: "state", Detail: "directory absent; first hook creates it with mode 0700"})
	} else if er != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		checks = append(checks, install.Check{Level: "FAIL", Name: "state", Detail: "expected a real directory with mode 0700; inspect ownership and chmod 700 the state directory"})
	} else {
		checks = append(checks, install.Check{Level: "PASS", Name: "state", Detail: "directory permissions are 0700"})
	}
	p, e := policy.Load(policy.Options{})
	if e != nil {
		checks = append(checks, install.Check{Level: "FAIL", Name: "policy", Detail: "invalid effective policy; run taintwatch policy check"})
	} else {
		if len(p.Ignored) > 0 {
			checks = append(checks, install.Check{Level: "WARN", Name: "policy", Detail: "project loosening was ignored; inspect taintwatch policy show"})
		} else {
			checks = append(checks, install.Check{Level: "PASS", Name: "policy", Detail: "effective policy is valid"})
		}
	}
	if e := install.DryRun(p.Config); e != nil {
		checks = append(checks, install.Check{Level: "WARN", Name: "dry-run", Detail: e.Error()})
	} else {
		checks = append(checks, install.Check{Level: "PASS", Name: "dry-run", Detail: "WebFetch taints; Read .env requires confirmation (in memory)"})
	}
	if install.RenderDoctor(out, checks) {
		return 1
	}
	return 0
}
