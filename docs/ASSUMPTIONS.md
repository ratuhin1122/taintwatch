# Claude Code format verification

Checked 2026-10-21 against official documentation. **Verified means documented,
not observed in a live session.** No real payloads have been supplied. The initial
verification task created documentation and a disposable spike. M1.2 now provides
documented input envelopes and structured output in `internal/hookio`, following
the user's explicit approval to implement from documentation while real captures
remain pending. Real-session golden tests and compatibility verification are
still outstanding.

## Sources read

- [Hooks reference](https://code.claude.com/docs/en/hooks)
- [Plugins overview](https://code.claude.com/docs/en/plugins)
- [Publishing](https://code.claude.com/docs/en/plugins/publish)
- [Create a marketplace](https://code.claude.com/docs/en/plugin-marketplaces)
- [Manifest reference](https://code.claude.com/docs/en/plugins/manifest-reference)
- [Marketplace reference](https://code.claude.com/docs/en/plugins/marketplace-reference)
- [Create a plugin](https://code.claude.com/docs/en/plugins/create)

## Hook transport and decisions

| Item | Status and contract |
| --- | --- |
| PreToolUse stdin | **verified (https://code.claude.com/docs/en/hooks#pretooluse-input)**: JSON object; `session_id`, `cwd`, `transcript_path`, `hook_event_name`, `tool_name`, `tool_input`, `tool_use_id`; `permission_mode` appears in the common example. |
| Additional common fields | **verified (https://code.claude.com/docs/en/hooks#common-input-fields)**: optional/context-dependent `prompt_id`, `scratchpad_dir`, `effort`, `agent_id`, `agent_type`; don't require their presence. |
| PreToolUse decisions | **verified (https://code.claude.com/docs/en/hooks#pretooluse-decision-control)**: stdout objects below, exit 0. `ask` requests confirmation; `deny` prevents execution; explicit `allow` skips normal prompting subject to remaining permission rules. A no-op response is preferable to explicit allow when merely abstaining. |
| Exit 0 | **verified (https://code.claude.com/docs/en/hooks#exit-code-output)**: applies valid JSON; no decision means normal processing. Invalid JSON/schema normally causes a non-blocking hook error. |
| Exit 2 | **verified (https://code.claude.com/docs/en/hooks#exit-code-output)**: PreToolUse blocks; stderr supplies the denial reason; JSON cannot override the block. PostToolUse cannot undo execution; stderr is feedback. |
| Other exit codes | **verified (https://code.claude.com/docs/en/hooks#exit-code-output)**: ordinarily non-blocking errors, **but valid decision JSON can still apply**. Configured failure-blocking hooks are exceptions. Do not implement fail-open by assuming every nonzero exit ignores stdout. |
| PostToolUse stdin | **verified (https://code.claude.com/docs/en/hooks#posttooluse-input)**: common envelope plus `tool_name`, `tool_input`, `tool_response`, `tool_use_id`; optional `duration_ms`. Success event only. MCP provenance may also be present. |
| Read result | **unverified**: exact `tool_response` shape, variants (text/image/PDF), and truncation behavior require captures; no concrete struct yet. |
| WebFetch result | **unverified**: exact `tool_response` shape, redirects and truncation require captures. |
| Bash result | **verified (https://code.claude.com/docs/en/hooks#posttooluse-decision-control)**: documented object example has `stdout`, `stderr`, `interrupted`, `isImage`. **unverified**: exhaustive shape and background/error variants on the installed version. |
| MCP result | **unverified**: exact `tool_response` shape is tool-dependent; do not assume every hook receives a standard MCP `content` envelope. |
| PostToolUse stdout | **verified (https://code.claude.com/docs/en/hooks#posttooluse-decision-control)**: `{}` abstains; context JSON below adds feedback. Top-level `decision:"block"` with `reason` annotates a completed result. Current docs also describe nested `updatedToolOutput` and MCP-only `updatedMCPToolOutput`; spike relies on neither. |
| Reader argument subset | **verified (https://code.claude.com/docs/en/hooks#pretooluse-input)**: Bash `tool_input.command` and Read `tool_input.file_path` are strings. The PostToolUse reference identifies `tool_input` as the original arguments, so M1.4 extracts only those fields inside `hookio`. Read paths are documented absolute; the classifier also handles relative paths defensively. No result schema is added. |
| Pre action arguments (M1.5) | **verified (https://code.claude.com/docs/en/hooks#pretooluse-input)**: Write and Edit use string `file_path`; WebFetch uses string `url`. Only this argument subset is decoded by pre rules. Real captures remain pending. |

Exact PreToolUse stdout (one object only, no diagnostic text on stdout):

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"Reason for allowing this action."}}
```

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"Please approve this action."}}
```

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Policy explicitly denies this action."}}
```

Exact PostToolUse context stdout, exit 0:

```json
{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"This session read untrusted content."}}
```

These are transport examples, not default Taintwatch policy. Product defaults will
ask, with deny available only through explicit user policy.

## Matchers and lightweight events

| Item | Status and contract |
| --- | --- |
| Tool matchers | **verified (https://code.claude.com/docs/en/hooks#matcher-patterns)**: match `tool_name`; `*`, empty or omitted matches all. Current docs distinguish exact names/lists (`Read`, `Edit|Write`, `Edit, Write`) from unanchored JavaScript regex when other characters occur. Spike uses explicit anchors: `^(Read|WebFetch|Bash|mcp__.*)$`. |
| MCP names | **verified (https://code.claude.com/docs/en/hooks#match-mcp-tools)**: `mcp__<server>__<tool>`; plugin servers use `mcp__plugin_<plugin-name>_<server-name>__<tool>`. Names alone are not provenance guarantees. |
| UserPromptSubmit input | **verified (https://code.claude.com/docs/en/hooks#userpromptsubmit-input)**: common envelope plus string `prompt`. No matcher support. **unverified**: actual optional fields and pasted-content representation on user's version. |
| UserPromptSubmit telemetry contract (M2.6, checked 2026-10-22) | **verified (https://code.claude.com/docs/en/hooks#userpromptsubmit-decision-control)**: stdout text or `additionalContext` adds model context; `decision:"block"` or exit 2 can block. Taintwatch emits nothing and exits 0, including on telemetry errors. **verified (https://code.claude.com/docs/en/hooks#userpromptsubmit-input)**: docs describe expanded pasted text and optional `<pasted_content id="…">` wrappers. **unverified**: actual delivery/wrappers on the user's version; no authenticity or instruction/data separation is inferred. |
| SessionStart input | **verified (https://code.claude.com/docs/en/hooks#sessionstart-input)**: common envelope plus `source` (`startup`, `resume`, `clear`, `compact`, `fork`); optional `model`, `agent_type`, `session_title`. **unverified**: actual field availability on user's version. |

## Plugin packaging

| Item | Status and contract |
| --- | --- |
| Hook file | **verified (https://code.claude.com/docs/en/plugins/manifest-reference#standard-layout)**: `hooks/hooks.json` at plugin root, outside `.claude-plugin/`. Its top-level `hooks` maps event names to arrays of matcher groups, each with `hooks` handler arrays. See working spike file. |
| Root substitution | **verified (https://code.claude.com/docs/en/plugins/manifest-reference#environment-variables)**: `${CLAUDE_PLUGIN_ROOT}` resolves to installed plugin root. Quote shell-form paths. Hook cwd need not be plugin root. Don't duplicate the default hook file in manifest `hooks`; declared hooks merge with the default. |
| Manifest fields | **verified (https://code.claude.com/docs/en/plugins/manifest-reference#fields)**: `.claude-plugin/plugin.json`: `name` required string; optional strings `displayName`, `version`, `description`, `homepage`, `repository`, `license`; `keywords` string array; `author` object with required `name`, optional `email`, `url`. `homepage` must parse as URL; `license` is an SPDX identifier. Component fields include `commands`, `agents`, `skills`, `hooks`, `mcpServers`, `lspServers`, `outputStyles`; only minimal metadata is used in spike. |
| Marketplace file | **verified (https://code.claude.com/docs/en/plugin-marketplaces#create-a-marketplace)**: `.claude-plugin/marketplace.json`; required `name`, `owner` (required `name`, optional `email`, `url`), `plugins` array. Entries require `name`, `source`. |
| Single-plugin root source | **verified (https://code.claude.com/docs/en/plugins/marketplace-reference#relative-path-plugin-source)**: relative sources resolve from marketplace root; `"./"` designates that root. **unverified**: install/cache behavior of our eventual single-plugin repository until tested. |
| Category/tags | **verified (https://code.claude.com/docs/en/plugins/marketplace-reference#plugin-entries)**: entry `category` string, `tags` string array; manifest uses `keywords`, not an invented manifest `tags`. |
| Validation | **verified (https://code.claude.com/docs/en/plugins/publish#prepare-your-plugin-for-release)**: `claude plugin validate ./spike`, optionally `--strict` to fail on warnings. Validate marketplace root likewise. This checks format, not live hook delivery. |

Illustrative future single-plugin catalog (not installed or published):

```json
{
  "name": "taintwatch-community",
  "owner": {"name": "Taintwatch contributors"},
  "description": "Taintwatch plugin catalog",
  "plugins": [{"name": "taintwatch", "source": "./", "category": "security", "tags": ["taint-tracking"]}]
}
```

### Reserved marketplace names

**verified (https://code.claude.com/docs/en/plugins/marketplace-reference#reserved-names)**:
reserved names include `claude-code-marketplace`, `claude-code-plugins`,
`claude-plugins-official`, `anthropic-marketplace`, `anthropic-plugins`,
`agent-skills`, `anthropic-agent-skills`, `life-sciences`, `knowledge-work-plugins`,
`claude-for-legal`, `claude-for-financial-services`, `financial-services-plugins`,
`first-party-plugins`, `claude-tag-plugins`, `claude-community`,
`claude-plugins-community`, `healthcare`, `anthropic-plugin-directory`, and
`claude-plugin-directory` (documented Anthropic-source exceptions apply).
Also reserved: `inline`, `builtin`, `skills-dir`, `synced`, `claude-plugin-test`;
case-insensitive `npm`, `pip`, `uv`, `cargo`, `github`, `gh`; JavaScript object
member names `constructor`, `hasOwnProperty`, `isPrototypeOf`,
`propertyIsEnumerable`, `toLocaleString`, `toString`, `valueOf`; `claudeai-`
prefix outside claude.ai hosting. Impersonating names, non-ASCII/control/bidi
characters, alternate spellings of reserved names, and collisions with registered
GitHub marketplace download-directory names also have documented restrictions.
Use the validator and installer rather than implementing a frozen copy of these rules.

## Version boundary

| Feature | Status |
| --- | --- |
| Plugin system launch | **verified (https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md)**: release 2.0.12 introduced plugins. This is a historical lower bound, not a proven minimum for this spike's complete behavior. |
| Tool-call correlation field | **verified (https://raw.githubusercontent.com/anthropics/claude-code/main/CHANGELOG.md)**: 2.0.43 added `tool_use_id` to PreToolUse/PostToolUse input types. Requiring it would raise the historical lower bound to 2.0.43; the spike does not require it. |
| Exact minimum for Pre/PostToolUse, ask/reason, context, timeout, plugin-root substitution, regex, --plugin-dir, CLI validation | **unverified**: current pages do not establish introduction versions for the complete combination. Do not advertise 2.0.12 as a tested minimum. |
| MCP `mcp_server` provenance | **verified (https://code.claude.com/docs/en/hooks#pretooluse-input)**: 2.1.274+. Not required by the spike; future engine must handle absence conservatively. |
| Optional `scratchpad_dir` | **verified (https://code.claude.com/docs/en/hooks#common-input-fields)**: 2.1.257+. Not required. |
| Optional WebFetch `offset` | **verified (https://code.claude.com/docs/en/hooks#pretooluse-input)**: 2.1.290+. Not required. |
| Local CLI | Observed `claude --version`: 2.1.175. Live hook behavior **unverified**. Current documentation describes later features; absence on this CLI is expected. Record the capture machine's version before promoting any assumption. |

## Payload gate and intended hookio boundary

**unverified**: real-session payloads and tool-specific result structs. During
M1.2, the user explicitly approved implementing the documented envelope while
leaving real captures pending. `internal/hookio` now defines `CommonInput`,
`ToolEventInput`, `PreToolUseInput`, `PostToolUseInput`, `UserPromptSubmitInput`,
and `SessionStartInput`; tool input/response remain `json.RawMessage`.
No concrete Read/WebFetch/MCP result schema has been inferred from synthetic data.

**verified (https://code.claude.com/docs/en/hooks#common-input-fields)**: optional
`effort` is an object containing string `level`. **verified
(https://code.claude.com/docs/en/hooks#pretooluse-input)**: optional `mcp_server`
contains string `name` and `source`. Unknown level/source values remain strings,
not closed enums.

Decoder validation is a Taintwatch implementation choice, not a claim about
required fields in every Claude Code version: require nonempty `session_id`,
the expected `hook_event_name`, and, for tool events, nonempty `tool_name` plus an
object `tool_input`. PostToolUse also requires the `tool_response` key, but accepts
any JSON value including null. Other missing fields have zero values; optional
metadata can be absent. Unknown envelope fields are ignored; unknown content
inside raw tool JSON is retained. Empty prompt text and new session sources are
accepted. No path sanitization or source trust is implied by successful decoding.

The whole input, including whitespace, is capped at 8 MiB plus one byte to detect
overflow. Exactly one JSON object is accepted. Reader errors are wrapped; malformed
or oversized payloads return errors and no partially decoded event. A byte cap
cannot bound elapsed time for a stalled `io.Reader`; hook entry points must also
apply process/deadline controls. Pre/post commands use this package and process
watchdogs; prompt now uses a separate always-open telemetry handler with a process
watchdog, while session-start remains a stub. Plugin packaging does not establish
real-session compatibility confirmation.

`Result` constructors keep output JSON inside `internal/hookio`; all structured
outputs, including deny, use exit 0. Its zero value emits `{}`. `Allow()` includes
an empty string reason because it accepts no reason argument. Write failures return
exit 1 and an error for the entry point's configurable failure handling. Output
fixtures and documented-envelope examples in `testdata/hookio/` are explicitly
documentation-derived. Real sanitized spike fixtures remain **unverified/pending**.

Taintwatch is defense-in-depth, not a solution to prompt injection. Session-level
taint is coarse; content detectors will be telemetry only. Hook-visible reads do
not cover every way context enters a session (for example direct file mentions).

Spike performance: not measured separately. Product hook median/p99 latency was
measured in the dated [hardening report](HARDENING.md). Real-session compatibility
remains unmeasured.
Supported product target: macOS/Linux amd64/arm64; Windows best-effort through WSL.

## M2.2 packaging verification (2026-10-22)

- Manifest name/version/description/author/homepage/repository/license/keywords:
  **verified (https://code.claude.com/docs/en/plugins/manifest-reference)**.
  Default `commands/` and `hooks/hooks.json` discovery and quoted plugin-root
  substitution in shell hooks: **verified (same source URL)**. Markdown command
  bodies also substitute `${CLAUDE_PLUGIN_ROOT}`; Bash tool processes do not
  automatically inherit that variable. Doctor's command exports it explicitly.
- Marketplace name/description/owner/plugins, entry name/source/description/category/tags,
  relative `"./"`, and reserved-name restrictions: **verified
  (https://code.claude.com/docs/en/plugins/marketplace-reference)**.
  The chosen marketplace is `ratuhin1122-plugins`.
- User settings at `~/.claude/settings.json`, strict JSON, and
  `CLAUDE_CONFIG_DIR` override: **verified
  (https://code.claude.com/docs/en/settings)**. Hook groups use the previously
  verified hooks reference schema; installer receipt fields are Taintwatch's
  private format, never Claude settings keys.
- Flat Markdown command files and `description` frontmatter: **verified
  (https://code.claude.com/docs/en/plugins/manifest-reference)** and
  **verified (https://code.claude.com/docs/en/slash-commands)**. Commands intentionally
  grant no pre-approved tools. `allow` is an interactive review workflow, not a
  transport permission or unconditional approval.
- Local validation: installed Claude Code `2.1.175` accepted plugin.json and
  marketplace.json with `claude plugin validate <manifest-path>` on 2026-10-22.
  Marketplace validation initially warned about its optional missing catalog
  description; the verified top-level description field was then added.
  Passing hooks/hooks.json directly to this command is not a supported separate
  validation mode: it interprets that file as a plugin manifest. The plugin uses
  the verified default hooks path instead.
- Exact minimum version for the full feature combination: **unverified**.
  Doctor always reports this limitation rather than inventing a version floor.
  Real plugin installation, real-session hook delivery, real payload fixtures,
  hosted repository availability, and published v0.1.0 release assets:
  **unverified**. No release was published by this task.
- Launcher checksum validation, attempt marker, platform asset naming, CLI
  install receipt/backup, and bootstrap failure policy are implementation choices,
  not Claude plugin schema claims. See `docs/install.md`. The missing-binary
  shell emits only the already verified fixed ask/context envelopes. All product
  Go hook JSON still comes from `internal/hookio`.

## M2.3 approval signal review (2026-10-22)

- **verified (https://code.claude.com/docs/en/hooks#permissionrequest)**:
  PermissionRequest happens before a permission decision; it does not report the
  human's eventual selection.
- **verified (https://code.claude.com/docs/en/hooks#posttooluse-input)**:
  PostToolUse reports execution/input/result; its documented fields do not prove
  who granted permission. Session `permission_mode` is not an approval receipt.
- **verified (https://code.claude.com/docs/en/hooks#notification)**:
  `permission_prompt` notifies that permission is needed.
  **verified (https://code.claude.com/docs/en/hooks#permissiondenied)**:
  PermissionDenied reports auto-mode denials, not successful human approvals.
- An authenticated signal for approval of a particular Taintwatch ask:
  **unverified / not documented in the current hook reference**. This scoped
  documentation finding makes no claim about private internals or future
  versions. Taintwatch never infers approval from success, transcripts, mode,
  notification text, or suggestions. Risky actions ask again while tainted;
  no per-session approval cache is automatically populated or consulted.
- **verified (https://code.claude.com/docs/en/hooks#exit-code-2)**: exit 2 blocks
  PreToolUse and cannot undo PostToolUse. Closed errors normally emit ask JSON
  with exit 0. When an ask cannot be written before the deadline, a closed
  pre-hook uses blocking exit 2 as its final fallback. Go context deadlines,
  OS identity attribution, and reviewed user-policy editing are implementation
  behavior, documented in `docs/approvals.md`.

M2.3 hook commands also set the launcher-owned `TAINTWATCH_NO_BOOTSTRAP=1` environment
variable so first-run networking cannot delay hook entry; checksum bootstrap is
an explicit command before a session. This is an implementation setting, not a
Claude Code schema field.

## M4.3 documentation verification — 2026-10-22

- Marketplace command syntax: **verified (https://code.claude.com/docs/en/plugin-marketplaces)**. The documented shell forms are `claude plugin marketplace add <owner>/<repo>` and `claude plugin install <plugin>@<marketplace>`; corresponding in-session `/plugin` forms are documented on the same page. The interactive install opens a plugin panel.
- Plugin command namespace: **verified (https://code.claude.com/docs/en/plugins)**. This repository's command is `/taintwatch:doctor`; execution in a live authenticated session remains **unverified**.
- Local CLI test: Claude Code 2.1.175 accepted manifest validation and local marketplace registration; a staged local plugin installed enabled. The local directory must be `./`, not bare `.` with this CLI. These checks do not establish a minimum compatible version or live hook delivery.
- Public repository exists; latest-release endpoint returned 404 on 2026-10-22. This is publication status, not a hook compatibility guarantee. See [README command verification](README-VERIFICATION.md).

## M4.5 publishing verification — 2026-10-22

- Manifest metadata fields and marketplace entry `category`/`tags`: **verified (https://code.claude.com/docs/en/plugins/marketplace-reference)** and validated using Claude Code 2.1.175. The marketplace name remains `ratuhin1122-plugins`; local validation does not prove global directory-name availability.
- Current Anthropic community/directory route: **verified (https://code.claude.com/docs/en/plugins/publish#submit-to-anthropics-directory)** and **verified (https://claude.com/docs/plugins/submit)**: use `claude.ai/directory/manage`; the official marketplace does not take submissions through that portal. No submission, review outcome or name reservation is implied.
- Portal eligibility/name availability and Taintwatch acceptance: **unverified**; no authenticated portal submission was made. The maintainer supplied exact GitHub About values in Part 3; description, website and all twenty topics were applied and API-readback verified on 2026-10-22. This is repository metadata, not directory acceptance. See [PUBLISHING.md](PUBLISHING.md).

## M4.6 compatibility review — 2026-10-23

- Upstream release: **verified (https://raw.githubusercontent.com/anthropics/claude-code/main/CHANGELOG.md)**: latest entry is 2.1.308. Installed CLI remains 2.1.175; live behavior on 2.1.308 is **unverified**.
- Existing envelope, matcher, PreToolUse allow/ask/deny JSON and PostToolUse additionalContext contracts: **verified (https://code.claude.com/docs/en/hooks)**. New optional fields remain tolerantly ignored. `defer`, `updatedToolOutput`, `classifierContext` and PostToolBatch exist but are unused. PostToolBatch examples do not establish PostToolUse response shapes. Nonzero exits other than 2 can still apply valid JSON; exit 2 blocks pre-hooks but cannot undo completed tools.
- MCP provenance: **verified (https://code.claude.com/docs/en/hooks)**: `mcp_server` identifies name/source. Current trusted-server exceptions use names only; the empty default trusts none. Provenance-aware exceptions are not implemented.
- Manifest and marketplace metadata: **verified (https://code.claude.com/docs/en/plugins/manifest-reference)** and **verified (https://code.claude.com/docs/en/plugins/marketplace-reference)**; no packaging migration identified.
- Real Read/WebFetch/MCP result shapes, authenticated approval signal, and minimum version for the complete feature chain remain **unverified**. SessionStart remains a stub. Documented-envelope tests are not real session captures.
