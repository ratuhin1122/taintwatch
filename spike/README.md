# Disposable hook-format probe

No product packages or policy engine. Standard library only, Go 1.26+.
`PreToolUse` saves the raw payload then returns `ask`; `PostToolUse` saves the raw
payload and returns `{}`. Failures/timeouts fail open (stderr, exit 0, no JSON).
Input is limited to 8 MiB; process work to 3 seconds; Claude hook timeout is 5 seconds.

Captures intentionally contain **raw, unredacted test input and output**. Use a
disposable project, harmless content, and a read-only MCP tool with no credentials
in its response. Review captures before sharing. This is not the product audit log.
Each payload is a separate atomic `.json` file; concurrent invocations do not append
to a shared log. Files use 0600 and the directory 0700 on macOS/Linux. Native
Windows permission modes do not provide equivalent ACL protection; use WSL with
the checkout and captures on its Linux filesystem (not `/mnt/c`).

## Build and check (macOS, Linux, or WSL)

From the repository root, run these in a terminal yourself:

```sh
cd spike
go build -o hook-spike .
go vet ./...
go test -race ./...
go test -run=^$ -fuzz=FuzzCapture -fuzztime=5s
cd ..
claude --version
claude plugin validate ./spike
```

Keep the absolute path to this checkout. WSL users build inside WSL, not with the
Windows Go compiler. A local smoke check (from repository root):

```sh
printf '%s\n' '{"hook_event_name":"PreToolUse","session_id":"smoke","tool_name":"Read","tool_input":{"file_path":"/tmp/public.txt"}}' | ./spike/hook-spike
```

Expect one JSON object with `permissionDecision: "ask"`, exit 0, and one file in
`spike/captures/`. This synthetic check does not establish Claude compatibility.

## Capture real payloads

1. In an ordinary terminal create a disposable directory and test file:

   ```sh
   mkdir -p /tmp/taintwatch-format-test
   printf 'public taintwatch probe\n' > /tmp/taintwatch-format-test/public.txt
   cd /tmp/taintwatch-format-test
   claude --plugin-dir /ABSOLUTE/PATH/TO/Taintwatch/spike
   ```

   Use an interactive session in normal/default permission mode. Do not use `-p`
   or bypass-permissions mode. Approve workspace trust if Claude requests it.
   This loads only the spike for this invocation; no persistent settings changes.

2. Run `/hooks` and confirm the spike has both PreToolUse and PostToolUse handlers.
   Ask Claude, one request at a time:

   - `Use Read to read /tmp/taintwatch-format-test/public.txt.`
   - `Use WebFetch on https://example.com with prompt "Return the page title".`
   - `Use Bash to run exactly: printf 'taintwatch-bash-probe\n'`
   - `Use the read-only MCP tool <exact tool name> once with <harmless arguments>.`

   Choose an existing connected MCP tool via `/mcp`; replace the placeholders
   yourself. Do not add a new server just for the test. If none is connected,
   report that the MCP sample is pending. Approve each harmless call when the
   spike asks. Allow the tool to finish so PostToolUse can fire. If Claude chooses
   a different tool, retry with the requested tool explicitly. If a call fails,
   report the failure; a failed call does not supply a successful PostToolUse.

3. Quit Claude. From the repository root inspect the files:

   ```sh
   ls -l spike/captures/*.json
   cat spike/captures/*.json
   ```

   The earlier smoke file has `session_id: "smoke"`; exclude it. Paste the **eight
   real objects** (Pre and Post for each of four tools), your `claude --version`,
   OS/architecture, permission mode, exact MCP tool name/server origin, and whether
   the ask prompt appeared. Label each object. Keep keys/types intact; replace
   sensitive string values with `[REDACTED]`. Do not paste credentials or unrelated
   session captures. If a prompt/handler is missing, paste the observed error and
   relevant `/hooks` details instead of inventing a payload.

4. Start future Claude sessions without `--plugin-dir` to stop loading this spike.
   Captures remain local and ignored by Git. Remove them manually when finished.

The exact `internal/hookio` structs will be proposed only after these captures are
confirmed. See [the verification ledger](../docs/ASSUMPTIONS.md).
