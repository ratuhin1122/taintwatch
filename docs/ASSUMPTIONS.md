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
apply process/deadline controls. M1.4 wires the post command through this package
and adds a process watchdog; other hook handlers remain stubs. No automatic plugin
registration or real-session compatibility confirmation is implied.

`Result` constructors keep output JSON inside `internal/hookio`; all structured
outputs, including deny, use exit 0. Its zero value emits `{}`. `Allow()` includes
an empty string reason because it accepts no reason argument. Write failures return
exit 1 and an error for the entry point's configurable failure handling. Output
fixtures and documented-envelope examples in `testdata/hookio/` are explicitly
documentation-derived. Real sanitized spike fixtures remain **unverified/pending**.

Taintwatch is defense-in-depth, not a solution to prompt injection. Session-level
taint is coarse; content detectors will be telemetry only. Hook-visible reads do
not cover every way context enters a session (for example direct file mentions).

Spike performance: not yet measured. Real-session compatibility: not yet measured.
Supported product target: macOS/Linux amd64/arm64; Windows best-effort through WSL.
