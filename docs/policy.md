# Policy version 1

Taintwatch loads built-in defaults, then `~/.config/taintwatch/policy.yaml`, then
the nearest `.taintwatch/policy.yaml` found by walking from cwd to the filesystem
root. Only the nearest project file is loaded; ancestor project files are not
stacked. Hooks use the hook envelope's cwd; inspection and policy commands use
the process cwd. Missing files leave the previous layer intact. The user path
is the stated home-directory path; `XDG_CONFIG_HOME` does not relocate it.

`allow domain/path` and `disallow domain/path` preview changes to the user layer
and require terminal confirmation or explicit `--yes`; see
[approvals.md](approvals.md). `secrets.allow_paths` is a list of exact canonical
absolute file names exempt only from TW001 reads. It defaults empty. Its lists
use the same `replace`/`append` syntax, and project additions count as loosening.

```sh
taintwatch policy check ./candidate.yaml  # validate this document only
taintwatch policy check                   # validate discovered layers and merge
taintwatch policy show                    # effective values with origin comments
```

Check/show exit 0 on success, 1 on invalid YAML or an I/O failure, and 2 on invalid
command arguments. Unknown keys, including misspelled nested keys and rule IDs,
are errors with source line numbers and a suggested key. Ignored project settings
are reported on stderr; they do not make an otherwise valid document invalid.
Checking an explicit file does not grant that file trust. Show prints resolved
lists in `replace:` blocks with origin comments for every value, including each
list item. Its output is valid version-1 YAML that can be checked before use as
an explicit configuration. Neither command initializes or mutates session state.

## Example user policy

Each file requires `version: 1`. All other keys are optional and inherit earlier
layers. This partial example is valid on its own:

```yaml
version: 1
fail_mode: closed
profile: balanced
allow_project_loosening: false

sources:
  tools:
    append: [CustomReader]
  mcp:
    trusted_servers:
      append: [internal_docs]
  bash:
    reader_commands:
      append: ['myclient get']
  read:
    taint_globs:
      append: ['**/downloads/**']
    temp_paths:
      append: ['/opt/imported']
    downloaded_paths:
      append: ['/opt/downloads']

egress:
  allow_domains:
    append: [docs.example.com]
secrets:
  paths:
    append: ['*.secret', '**/credentials/**']
  allow_paths:
    replace: []  # Exact absolute canonical files exempt only from TW001 reads.
protected_writes:
  append: ['**/deploy/**']

rules:
  TW001:
    action: deny
    enabled: true
    extra_match:
      append: ['sensitive-export']

log:
  path: audit.jsonl
  rotation:
    max_bytes: 10485760
    keep: 3
state:
  retention_days: 7
```

Use `chmod 600 ~/.config/taintwatch/policy.yaml` to keep the user file private.
Policies are configuration, not a place to store credentials. Regular files are
required; Unix leaf symlinks and FIFOs are rejected. Parents are operator-managed.
There is no include directive, command execution, network fetch, variable expansion
or YAML object construction.

## Lists and merging

Every list field requires **exactly one** list operation:

```yaml
egress:
  allow_domains:
    replace: [github.com, api.github.com]
```

`replace` sets the whole list, including `replace: []` to empty it. `append` adds
unique values in order and keeps existing values. Scalar fields override their
previous value. Rules merge by stable ID, then by field: setting an action leaves
that rule's enabled flag and extra patterns intact. Bare lists, simultaneous
replace/append operations, nulls, duplicate keys and duplicate documents are errors.
Source/permission implications below can limit project replacements.

## Untrusted project files

A repository can ship its own policy. Letting it trust its own MCP server, allow
an exfiltration domain, remove secret paths or disable a guard would let the
untrusted content choose its own security boundary. Project files therefore cannot
weaken the effective user policy unless the **user file** explicitly sets:

```yaml
version: 1
allow_project_loosening: true
```

The project cannot grant this permission to itself, even when the user has already
enabled it; this switch is controlled only by the user layer. The default is false.
Enabling it grants any discovered project broad authority to weaken policy; use it
only with that trust model in mind.

Without that permission:

| Project change | Result |
| --- | --- |
| Add secret/protected paths, source tools/readers/read globs/temp/download paths | Accepted |
| Remove any of those restrictions with replace | Removed entries are retained; ignored removals are reported |
| Add an allowed domain or trusted MCP server | New entries ignored |
| Remove an allowed domain or trusted MCP server | Accepted |
| Disable an enabled rule | Ignored |
| Lower a rule's action from deny to ask/allow, or ask to allow | Ignored |
| Enable a rule or strengthen ask to deny | Accepted |
| Add extra match patterns to an ask/deny rule | Accepted |
| Add extra match patterns to an allow rule | Ignored conservatively |
| Switch open to closed, balanced to paranoid | Accepted |
| Switch closed to open, paranoid to balanced | Ignored |
| Change log.path | Ignored |
| Reduce retention days, rotation size or backup count | Ignored |
| Increase retention days, rotation size or backup count | Accepted |

Comparison uses exact list membership, not an attempt to prove equivalence of
globs or regular expressions. A project replacement that mixes restrictive and
permissive changes applies the safe portion: for example, dropping a previously
allowed domain remains effective even if an accompanying new domain is ignored.
User-layer values can loosen protections directly. Ignored changes leave warnings
in hook diagnostics and audit metadata; `policy show/check` identify the key,
file and line. A malformed project document is rejected as a whole: open hooks
continue with the last valid policy, while closed pre hooks ask. Post hooks still
track known taint using that last valid policy and supply advisory context. Bad
repository YAML therefore cannot turn ordinary evaluation into a silent allow.

## Field reference and defaults

| Key | Type/default | Behavior |
| --- | --- | --- |
| version | Integer, required 1 | Other versions rejected |
| fail_mode | open or closed; open | Loaded for decoding/storage/deadline errors; closed pre asks, closed post advises |
| profile | balanced or paranoid; balanced | Paranoid taints every enabled Read |
| allow_project_loosening | Boolean; false | Only the user layer controls it |
| sources.tools | List; WebFetch, WebSearch, mcp__*, Bash, Read | Glob selectors for enabled provenance sources; other selected tools taint with source kind tool |
| sources.mcp.trusted_servers | List; empty | Exact full MCP server segments; no wildcards or tool names |
| sources.bash.reader_commands | List; gh issue view, gh pr view, gh pr diff, gh api, curl, wget | Literal command prefixes after parser normalization; replace really replaces the readers |
| sources.read.taint_globs | List; dependency globs from TAINT.md | Additional reasons an enabled Read taints |
| sources.read.temp_paths | List; system temporary directory, /tmp, /var/tmp | Directory prefixes; replace supported |
| sources.read.downloaded_paths | List; ~/Downloads resolved at startup | Directory prefixes; replace supported |
| egress.allow_domains | List; GitHub/npm/PyPI/Go hosts in RULES.md | Exact lowercase hostname or IP; no URL, port, wildcard or suffix trust |
| secrets.paths | List; M1 secret path patterns | Controls TW001 file candidates |
| protected_writes | List; M1 protected config/manifests | Controls TW005 write candidates |
| rules.ID.action | allow, ask or deny; ask | Only explicit policy introduces deny |
| rules.ID.enabled | Boolean; true | False removes that rule from evaluation |
| rules.ID.extra_match | List; empty | Go RE2 regexes OR-ed with the built-in predicate |
| log.path | String; audit.jsonl | Relative to state home, or absolute; ~/ prefix expanded only here |
| log.rotation.max_bytes | Integer; 10485760 | Positive, at most 1 GiB; see AUDIT.md for single-record behavior |
| log.rotation.keep | Integer; 3 | 1–20 backup files, plus the active log |
| state.retention_days | Integer; 7 | 1–3650 inactivity days for lazy session cleanup |

Path globs use `/` and `**` for zero or more path segments. A pattern without `/`
matches any basename, so `.env*` covers `.env` at any depth. Lexical and resolved
file candidates are checked by action rules. Temp/download paths are relative to
the hook cwd unless absolute; unlike log.path, they do not expand `~`. Outside-root
and unresolved Read provenance checks remain intrinsic to the balanced profile;
disabling Read altogether requires changing sources.tools. MCP exclusions apply
only when an MCP tool is selected. Ordinary Bash/Read calls are still conditional,
not automatically tainted merely because those tools appear in sources.tools.

Extra regexes search the tool name, raw Bash command, file path, or WebFetch URL.
They **add** matches; they cannot narrow a built-in predicate. The rule's original
`when` (tainted or always) still applies. Known IDs are TW001–TW008. All matching
enabled rules are considered: deny outranks ask, which outranks allow. Table order
breaks ties, preserving M1 reasons. This avoids an early allow/ask override masking
a later stronger rule. Allow means Taintwatch abstains; native Claude permissions
remain in effect. TW006 also protects loaded policy files and configured audit
paths. Read-only `taintwatch policy check/show` commands are not mutations.

Limits: 1 MiB per document, one document, bounded structure, 256 entries per list
operation, 2048 bytes per entry, and 4096 bytes for scalar strings. YAML anchors,
aliases, merge keys, custom tags and YAML 1.1 yes/no booleans are rejected. Patterns
are validated before any changes from a file apply. Origins identify built-ins,
file/line values, or the legacy operator environment overrides described below.

## Runtime precedence and storage

Trusted hook CLI `--fail-mode` and post `--profile` flags override the loaded
fields for that invocation. The existing operator environment variables
`TAINTWATCH_AUDIT_MAX_BYTES` and `TAINTWATCH_AUDIT_KEEP` override their merged
rotation fields and appear as environment origins in policy show. These variables
are not writable through project policy. `TAINTWATCH_HOME` continues to override
the state directory independently of policy. Inspecting from another cwd can
select a different project policy; use the project cwd when reading its history.

Custom audit parents are created privately if missing; existing parent permissions
are not changed. Parents must be real directories and are operator-trusted. Logs
remain 0600 with the state-home lock; do not share one custom log between different
state homes. Log paths overlapping the state lock or sessions directory are
rejected by storage initialization. Loading/checking a policy is not a guarantee
that its eventual filesystem destination will be writable.

Session/policy/audit access remains bounded by the hook worker and final watchdog.
Filesystem failures and timeouts can prevent a diagnostic or closed-mode response;
see LIMITATIONS.md. Shell analysis and secret detection remain best-effort.
