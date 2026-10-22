# Install and diagnose Taintwatch

Linux and macOS on amd64/arm64 are supported. On Windows, run Claude Code and
Taintwatch together inside WSL. Plugin version is currently `0.1.0`.

## Local plugin

Build a versioned binary and put it on PATH before starting Claude Code:

```sh
make build VERSION=0.1.0
mkdir -p "$HOME/.local/bin"
cp build/taintwatch "$HOME/.local/bin/taintwatch"
export PATH="$HOME/.local/bin:$PATH"
claude plugin validate .claude-plugin/plugin.json
claude plugin validate .claude-plugin/marketplace.json
claude --plugin-dir "$PWD"
```

The hooks invoke the launcher through `sh`, so copying the repository through
Windows does not require preserving its executable bit. Alternatively, put a
binary in `bin/taintwatch-linux-amd64` (or the matching platform name), chmod 700
it, then launch Claude with `--plugin-dir`.

For a marketplace installation, add this repository with Claude's
`/plugin marketplace add ratuhin1122/taintwatch`, then
`/plugin install taintwatch@ratuhin1122-plugins`. Local testing can use
`/plugin marketplace add /absolute/path/to/taintwatch` first. Repository hosting
and published release availability must be established separately; this task
does not publish anything. Confirm both hooks in `/hooks`, then run the
capture experiment in `spike/` to check real delivery. Commands are
`/taintwatch:status`, `/taintwatch:explain`, `/taintwatch:doctor`, and
`/taintwatch:allow`. The last command previews a policy diff and waits for an
explicit user confirmation; it grants no permission by itself.

## Bootstrap and offline behavior

The launcher prefers a bundled platform binary, then `taintwatch` on PATH.
Only when neither exists does it attempt a download from
`https://github.com/ratuhin1122/taintwatch/releases/download/v0.1.0/`.
Expected assets are `taintwatch-{linux,darwin}-{amd64,arm64}` and `checksums.txt`,
with lowercase SHA256 and two spaces before each filename. The checksum and
binary must both download over HTTPS from that same release. This establishes
integrity relative to the release, not an independent publisher signature.
`sh scripts/release-assets.sh` builds those files locally without publishing.

A persistent `bootstrap/0.1.0/attempted/` directory under the state home is created
before networking. Later runs never retry, even after a failed download. A
successful cached binary is rehashed against its saved verified checksum before
every execution. Bad checksums never execute. Downloading each file is bounded
to 15 seconds (3 second connect timeout). Preinstall a local binary for offline,
fast hook startup; bootstrap may exceed Claude's hook timeout. It is better to
bootstrap explicitly with `sh bin/taintwatch-launcher version` before a session.
After fixing a failed download, explicitly remove only the version's
`attempted/` directory to authorize another first-run attempt, or install a
local binary. Failed cache validation requires inspecting/removing the cached
binary and `verified` marker as well.

Bootstrap errors go to stderr (Claude's hook diagnostics), with no payload or
secret logging. Normal binary execution loads merged policy. If the binary is
missing, the shell cannot safely parse/merge YAML: set `TAINTWATCH_FAIL_MODE`
to `open` or `closed` in the environment to select its fallback. Without that
override it defaults open only when no user/project policy file exists; any
policy file, unreadable policy, or explicit unknown mode conservatively selects
closed. Closed PreToolUse emits the documented ask JSON with exit 0; PostToolUse
always exits 0 and cannot undo a tool call. Non-hook bootstrap failure exits 1.
This small static bootstrap response is the sole shell protocol fallback;
product Go hook responses still go through `internal/hookio`.

## Standalone hooks

Stop Claude Code while editing its settings, then run:

```sh
taintwatch install
taintwatch doctor
# Later:
taintwatch uninstall
```

Install uses `~/.claude/settings.json`, or `$CLAUDE_CONFIG_DIR/settings.json`.
It adds dedicated pre/post groups using the absolute current executable path,
preserves unrelated JSON keys/groups, saves a mode-0600 byte-for-byte backup
before changing existing settings, and atomically replaces the settings file.
An adjacent mode-0600 `.taintwatch-install.json` receipt owns only entries it
added. Repeated installs do nothing. Uninstall removes only unchanged entries
in that receipt; manually edited or pre-existing entries remain. Keep the
receipt for reversal. A settings file created by install is removed on uninstall
only if it otherwise contains no settings. A `.taintwatch-lock` directory excludes other installers;
after an interrupted invocation, inspect the backup/receipt and remove that
empty lock manually. Other settings writers do not honor this lock, hence the
instruction to stop Claude first. Restart Claude after changes. Use either
standalone or plugin wiring to avoid duplicate processing.

`doctor` is read-only: it checks version, standalone wiring or plugin environment,
Claude version availability, state directory permissions, effective policy, and
an in-memory WebFetch → Read .env scenario. PASS means the named local check
passed; WARN includes missing wiring and an intentionally weakened sample
policy. FAIL exits 1; PASS/WARN-only reports exit 0. The full feature set's exact
minimum Claude version and real hook delivery remain unverified, so doctor
reports a compatibility warning with instructions to validate and test `/hooks`.
