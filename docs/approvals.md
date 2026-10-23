# Explicit exceptions, clearing, and failure handling

Taintwatch cannot authenticate a human by reading a Bash command string.
The default TW006 rule asks before `allow`, `disallow`, `clear`, or any other
mutating Taintwatch command, even in a clean session, with `--yes`, inside common
wrappers, through the plugin launcher, or through a versioned platform binary.
This is best-effort shell analysis, not an operating-system security boundary;
renamed binaries, other languages, disabled hooks, or explicit policy overrides
can bypass that boundary. See [LIMITATIONS.md](LIMITATIONS.md).

## Permanent exceptions

```sh
taintwatch allow domain example.com
taintwatch allow path /absolute/path/to/.env.development
taintwatch disallow domain example.com
taintwatch disallow path /absolute/path/to/.env.development
```

These commands read and modify only `~/.config/taintwatch/policy.yaml`. They show
the full before/after policy diff (secret-shaped values redacted), ask `[y/N]`
on a real terminal, and default to refusal. Piped `y` is not terminal confirmation.
Noninteractive changes require the explicit `--yes` flag; it still prints the
diff and does not bypass TW006 in Claude Code. Review the exact proposal first.
Unchanged requests do not write or ask for confirmation. Interrupted edits may
leave a `policy.yaml.lock` directory; inspect it before manually removing it.

Domain exceptions are exact normalized lowercase hosts, without URL schemes,
ports, wildcards, or implicit subdomains. They update `egress.allow_domains`.
Path exceptions are existing regular files, resolved through symlinks to an
absolute canonical name, without globs or recursive directory access. They
update `secrets.allow_paths` and exempt only that file from TW001 secret reads.
The rule resolves each access again; retargeting a symlink does not approve its
new target. Other matched rules, including TW002 and TW005/TW006, still ask.
To remove an exception for a deleted file, pass its originally stored canonical
path. Disallow can remove a built-in domain using an explicit user replace list.

Unrelated YAML keys/comments remain in the proposed document. Lists use explicit
`replace` semantics, so editing one list fixes its current user-layer contents
until you change it again. Settings from the project are never copied into the
user policy, and a project restriction can still remove your exception. Projects
cannot add `secrets.allow_paths` entries without the existing user-layer
`allow_project_loosening` grant. Files/backups are 0600, the policy directory is
0700, replacement is atomic, and a changed file is rejected after preview rather
than overwriting a concurrent edit. External editors do not honor the lock.

## Explicit clearing

```sh
taintwatch clear --session SESSION_ID --reason "Reviewed the untrusted content"
```

Without `--session`, clear selects the most recently updated persisted session.
The mandatory reason records explicit clearing. Successful tool responses do not
clear taint. Lazy retention can delete an inactive tainted session after the
configured interval (seven days by default); a later observation starts new state.
Clear records the OS UID/username, not an invented Claude identity or a supplied
`--who`. State stores the redacted reason, actor, and timestamp. Audit records
`session.clear.requested` before changing state and `session.clear` afterward.
If intent cannot be audited, state is unchanged. If state update or completion
audit fails, the CLI reports the exact stage; the durable intent retains who/why.
State and audit updates are serialized individually, not a cross-file transaction.
A new concurrent post-hook source can immediately taint the session again.

## Native approvals are not cached

The documented hook schema offers no authenticated result telling this plugin
that the user approved a particular Taintwatch ask. PermissionRequest means a
prompt is needed; PostToolUse means execution succeeded. Neither proves a user
approved it: settings, another hook, or another permission host could have allowed
it. `permission_mode`, `permission_suggestions`, a transcript, and the arrival of
a successful tool result are not approval receipts. See the dated source checks
in [ASSUMPTIONS.md](ASSUMPTIONS.md).

Taintwatch does not populate/use session approvals automatically. Each risky
action asks again while tainted. Use Claude's native once-only approval for that
invocation, or review a permanent domain/path exception with `allow`.

## Fail modes and deadlines

Active pre/post hooks use a context deadline from entry through output: 1.8s
total, with a 1.35s evaluation deadline reserving output time. A final two-second
process watchdog handles a stuck Reader/Writer or kernel call that Go cannot
cancel. After cancellation, readers reject further data and checkpoints stop
further processing; the process exit kills remaining workers. An already started
filesystem write can complete before exit; cancellation is not rollback.
Machine scheduling and process startup are outside Go's hard real-time control.
Plugin hook wiring disables download bootstrap; run the launcher `version`
command explicitly before enabling hooks when a local binary is unavailable.

| Error | Open | Closed |
| --- | --- | --- |
| Bad stdin, bad policy, unavailable state, argument errors, recovered panic | Pre abstains with `{}`; post emits no error context | Pre asks; post supplies advisory confirmation context |
| Pre-hook evaluation deadline | Ask, including open mode | Ask |
| Lost post observation | Persist degraded state if possible; later sensitive actions ask | Same, plus advisory context |
| Shell syntax/size failure in a clean session | Pre abstains; post reports diagnostic | Pre asks; post supplies advisory context |
| Unparseable shell in a tainted session | TW008 asks | TW008 asks |
| Audit failure after detecting risk or a source | Known ask/deny or provenance context is retained | Known ask/deny or provenance context is retained |
| Unwritable or stuck pre-hook output | Exit 0 | Exit 2 blocks because an ask cannot be delivered |
| Unwritable or stuck post-hook output | Exit 0 | Exit 0; a completed tool cannot be undone |

Bad policy uses the last valid defaults/user layer where available; open does
not erase an already known risk. Unknown mode during a stalled policy load is
handled conservatively as closed; an explicit CLI override is known immediately.
No untrusted panic/error body is printed. When stdin, state, or output is broken,
audit/diagnostic delivery may be impossible. Bootstrap launcher failure behavior
is separate and documented in [install.md](install.md).

Always rules are evaluated before session storage is opened. A known TW006
self-protection or TW007 decision survives state initialization/loading failures
even in open mode; lack of storage is not a permanent-exception mechanism.
