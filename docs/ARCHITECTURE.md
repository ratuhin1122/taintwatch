# Architecture

Taintwatch tracks untrusted sources after tools run and checks subsequent tool
requests against session taint and built-in action rules. Each hook invocation is
a separate, bounded command-line process. No network or model call runs inside a
hook. The root module's parser dependency is `mvdan.cc/sh/v3/syntax`.

```mermaid
flowchart TD
    Claude["Claude Code hook event: JSON on stdin"] --> Input["hookio: bounded, tolerant input decoding"]
    Input --> Pre["hook pre: normalize attempted action"]
    Input --> Post["hook post: normalize completed tool source"]
    Eval["eval run: ordered corpus events, isolated runtime"] --> Pre
    Eval --> Post
    Policy["policy: built-ins → user → guarded project merge"] --> Rules
    Policy --> Taint
    Policy -->|"Retention and audit settings"| State
    Pre --> Shell["shellparse: Bash AST and risk facts"]
    Pre --> Rules["rules: action, rule ID, reason, evidence"]
    Shell --> Rules
    State["state: session snapshots and Unix lock"] -->|"Load taint snapshot"| Rules
    Post --> Taint["taint: source classifier"]
    Taint -->|"Tainting response strings"| Values["valuematch: bounded extraction and encodings"]
    Values -->|"Persist original indicators and variants"| State
    Taint -->|"Tainting response strings"| Encoded["encoded: bounded single-level telemetry"]
    Encoded -->|"Hint types and counts only"| Audit
    State -->|"Retained patterns"| Matcher["valuematch: compiled Aho-Corasick"]
    Matcher -->|"Argument matches: TW009"| Rules
    Taint -->|"MarkTainted or Touch"| State
    Rules --> Audit["audit: redact metadata and encode record"]
    Taint --> Audit
    Audit --> Store["state: single append write and rotation"]
    Store --> Log["audit.jsonl and retained backups, mode 0600"]
    Rules --> Result["hookio.Result: verified output JSON"]
    Taint --> Result
    Result --> Output["stdout: abstain, ask, or post-tool context; exit 0"]
    State --> Sessions["sessions/sanitized-ID.json, mode 0600"]
    Log --> Query["audit.Query: retained history and ask counts"]
    Query --> Explain["explain: reasons, rule IDs, guidance, text or JSON"]
    Query --> Status["status: current taint, sources, asks, policy files"]
    State --> Status
```

Only `internal/hookio` knows Claude Code's hook input/output JSON contract.
Transport is limited to 8 MiB, unknown fields are tolerated, and tool results
remain opaque. In particular, WebFetch provenance does not depend on a guessed
response-body schema. Real capture confirmation remains pending in
[ASSUMPTIONS.md](ASSUMPTIONS.md); the spike is an independent throwaway module.

Pre/post processing lives in `internal/hooks`, shared by the CLI handlers and
`internal/eval`. Normal hooks use production policy/storage loaders; evaluation
injects built-ins, per-scenario private state and a fixed storage clock through
Go dependencies, with no public policy-bypass switch. Replay never executes the
proposed tools. See [EVAL.md](EVAL.md) for metrics and CI gate semantics.

PreToolUse loads current state, derives shell facts for Bash, and evaluates the
ordered Go rule table. Clean benign decisions emit `{}` so Claude Code's normal
permissions still apply. Built-in risk matches ask, including always-on
self-protection and decode-and-run rules. No default rule denies. Reasons name
the taint source and attempted risk. See [RULES.md](RULES.md).

PostToolUse classifies WebFetch/WebSearch, MCP, shell readers, and selected file
reads. It records a taint event or touches the existing session, persists an audit
observation, and may add factual untrusted-data context. Touch does not clear
earlier taint. The completed tool call cannot be blocked retroactively. See
[TAINT.md](TAINT.md).

The state home is selected through `TAINTWATCH_HOME`, then XDG state paths. Managed
directories are 0700, session files use temp-file-plus-rename publication, and a
bounded Unix advisory lock coordinates processes. Audit records are redacted
before one append write; rotation defaults to 10 MiB with three backups. State
and audit updates are separate operations. Inspection reads bounded audit
snapshots outside the writer lock and never refreshes session expiry. See
[STATE.md](STATE.md) and [AUDIT.md](AUDIT.md).

Open is the default error mode. Closed pre-hook errors ask; closed post-hook
errors add advisory context. Input/storage/output failures can prevent durable
audit records. A worker deadline and final process watchdog bound stalls; a
broken transport cannot reliably deliver an ask. Shell analysis is best-effort,
and session-level taint loses fine-grained provenance. These are defense-in-depth
checks, not a solution to prompt injection. See [LIMITATIONS.md](LIMITATIONS.md).

`policy` strictly validates YAML and merges built-in, user and nearest-project
settings. A project cannot grant itself permission to loosen protections; ignored
changes are reported and invalid project YAML retains the last valid policy.
Hooks, status and explain use the loaded configuration. `policy show` annotates
each value with its origin. See [policy.md](policy.md).

Value provenance stores bounded indicators and encodings in session state and
matches later arguments through TW009. Originals are not copied into audit
reasons. Exact matching cannot infer intent or semantic transformations; see
[VALUEMATCH.md](VALUEMATCH.md). Native approval reuse remains unverified.

Encoded-content analysis decodes a bounded set of base64/hex candidates once and
reuses lexical, URL and shell AST heuristics. Its decoded bodies never enter the
rule table or value-provenance state; only informational type/count metadata
reaches audit and explain. See [ENCODED-CONTENT.md](ENCODED-CONTENT.md).

## M1 executable scenario

`TestBinarySessionFlow` builds the real binary and sends hook JSON over stdin in
isolated subprocesses with a temporary `TAINTWATCH_HOME`. It verifies clean secret
read → WebFetch taint → secret-read ask → secret-read/egress ask → benign command
allow → explain with matching rule IDs and reasons. The combined pipeline matches
TW001 first; rule precedence is intentional. Status assertions verify persisted
taint, and audit assertions verify both asks were recorded. This test runs with
`make test` on Linux/macOS; native Windows storage is unsupported.

For a recording, run `bash scripts/demo.sh` from any working directory. It builds
the executable, displays the same checks and reasons, then prints explain/status.
Requests use fixture data; the displayed shell commands are hook inputs. The
temporary project, fake `.env`, binary and state are removed on exit. Bash, Go
1.22+ and standard Unix utilities are sufficient; jq/Python are not required.
For WSL without a Go SDK, an absolute `TAINTWATCH_DEMO_BINARY` may point to a
fresh cross-compiled Linux executable. The subprocess test similarly accepts
`TAINTWATCH_E2E_BINARY` for that verification setup; normal CI compiles afresh.

## Distribution and trust boundaries

The repository is both a single-plugin marketplace (`ratuhin1122-plugins`) and a standalone Go CLI. Plugin hooks call the POSIX launcher with bootstrap disabled. It locates a bundled/platform binary, a PATH binary, or a verified cached asset; only an explicit non-hook first-run invocation can attempt a release download. Checksums from the same release provide integrity against corruption, not an independent release signature. There is currently no published release. Standalone installation backs up user settings and tracks exactly the hook entries it owns; enabling both forms duplicates hooks.

Runtime hook analysis makes no network/model calls and sends no telemetry. Explicit installation/bootstrap and dependency downloads are a separate network boundary. JSON stdin, tool responses, repository policy and audit logs are untrusted inputs. The loader rejects recognized project-policy loosening without user-layer authorization; this does not guarantee every repository-induced failure or analysis bypass is covered. Output decisions go through hookio; hidden/encoded/prompt heuristics only write local informational metadata. TW009 value provenance is an action rule and can ask independently of detector findings.

Audit redaction occurs before serialization and full response bodies are omitted. Session state retains bounded original indicators/variants, which may be sensitive; private file permissions do not make them redacted. State mutations and rotation use Unix advisory locks. Native Windows locking is unsupported; WSL deployments should keep state on the Linux filesystem.

Eval routes ordered synthetic events through the hook decision path using isolated state. Replay operates only on redacted recorded snapshots and supported compatible overrides; it cannot recreate raw inputs or arbitrary source/matcher changes. Doctor validates local configuration and an in-memory synthetic scenario, not live Claude delivery. CLI validation and synthetic replay do not replace the outstanding real hook payload checks in ASSUMPTIONS.md.

For deployment boundaries, fail behavior, coarse taint and analysis gaps, see [LIMITATIONS.md](LIMITATIONS.md). For the current measured gate result, see [EVAL.md](EVAL.md).
