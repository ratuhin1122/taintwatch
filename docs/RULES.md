# Pre-tool action checks (M1.5)

`taintwatch hook pre [--fail-mode open|closed]` loads the session snapshot and
evaluates the Go rule table with the loaded YAML policy and rule overrides.
See [policy.md](policy.md). No hook is installed automatically. Only `hookio` decodes tool arguments and
writes Claude Code output. Safe actions emit `{}` with exit 0, preserving native
permissions. Risk matches emit a verified PreToolUse `ask`, also with exit 0.
No default rule denies. Every evaluated decision is recorded with its stable rule
ID, reason, evidence, and state provenance; raw command bodies are omitted.

Rules run in this order: TW006 self-protection, TW007 decode-and-run, TW001 secret
read, TW003 publication, TW004 destruction, TW005 protected write, TW002 egress,
TW008 uncertain shell analysis. TW006 and TW007 apply even when clean; the rest
require session taint. The strongest matching action wins (deny, ask, allow), with
table order breaking ties; default force-push still reports TW003. Tainted
reasons include the latest recorded source tool and its UTC time.

TW002 uses exact host matching, never domain suffix matching. Unknown destinations
ask. Default allowed hosts are github.com, api.github.com, raw.githubusercontent.com,
objects.githubusercontent.com, registry.npmjs.org, pypi.org, files.pythonhosted.org,
proxy.golang.org, and sum.golang.org. Redirects, DNS results, SSH aliases and Git
remote configuration are not resolved. These host exceptions are not a promise
that sending secrets to an allowed host is safe.

The parser uses mvdan.cc/sh/v3/syntax v3.8.0 (Go 1.21 minimum, compatible with the
project's Go 1.22 minimum): [module declaration](https://github.com/mvdan/sh/blob/v3.8.0/go.mod).
It visits Bash syntax without executing anything, retaining commands, pipelines,
lists, redirections, heredocs, substitutions and subshells. Literal quoting and
common wrappers are recognized. Literal shell `-c` scripts and eval are inspected
recursively, capped at eight levels; input is capped at 64 KiB. Unresolved
expansions and parse failures ask in tainted sessions through TW008.

Package manifests are protected conservatively even when the proposed content
does not contain scripts. `truncate` asks for any operand unless a caller supplies
a tracked-file list; hooks do not spawn Git. Self-protection covers conventional
Taintwatch paths, the actual state home, hook files and Claude settings. The
shell file-operand extractors are conservative candidates, not syscall tracing.

Errors default to open (diagnostic and `{}`). Closed errors return ask. A known
risk decision is retained if auditing fails. Input, filesystem and output failures
can prevent durable audit records; diagnostics are the fallback. A worker deadline
uses a 1.8-second context budget (1.35 seconds for evaluation, the remainder for
output); the process watchdog is two seconds. A broken output pipe cannot
reliably transmit an ask: closed pre-hooks use the documented blocking exit 2
as a last resort, while open pre-hooks and all post-hooks exit 0. Until policy
loading establishes a mode, timeout handling is conservative (closed), unless
an explicit `--fail-mode open` was supplied. Performance
has not been benchmarked against the under-50-ms target.

See [LIMITATIONS.md](LIMITATIONS.md). Real Claude Code payload captures remain pending.
