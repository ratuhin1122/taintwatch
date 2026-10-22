# README verification — 2026-10-22

This record separates executed local examples from live integration. It is not a claim that a fresh user has completed an authenticated Claude Code session in five minutes.

## Executed

- `make build test lint`: passed on the Windows host using MSYS Make, Go and the existing local caches; race tests, vet and formatting passed. Native Windows state remains unsupported; Unix runtime paths were checked separately under Ubuntu WSL.
- `make build VERSION=0.1.0` and `make build VERSION=m4.2`: build commands completed. PowerShell selected an old sibling `.exe` for an extensionless invocation; the newly built artifact was copied to a unique `.exe` for inspection. The POSIX README path is unambiguous. Linux cross-build labeled m4.2 was used for Unix runtime verification.
- `bash scripts/demo.sh`: passed under Ubuntu WSL with `TAINTWATCH_DEMO_BINARY` pointing to the real compiled Linux binary because WSL has no Go SDK. Observed clean Read allow, WebFetch taint, two TW001 asks, clean development action allow, then explain/status. The default build-inside-demo branch was not executed in WSL during this documentation task.
- User-bin directory creation, binary copy, PATH export and `taintwatch version`: executed with a disposable Linux HOME and a cross-built binary. The source-build commands ran on the host; this is not an exact end-to-end Linux source quickstart test.
- `taintwatch install`, `doctor`, `status`, `explain --last 10`, `policy check`, `policy show`, `clear --reason "Reviewed untrusted content"`, and `uninstall`: executed with isolated HOME, TAINTWATCH_HOME and CLAUDE_CONFIG_DIR in WSL. Exit 0. Doctor emitted expected warnings for absent Linux Claude CLI/state; its synthetic scenario passed.
- README YAML: extracted unchanged and accepted as the user policy by `policy check`.
- `taintwatch allow domain example.com`: executed non-interactively; exit 1 correctly refused mutation after preview. Repeating with explicit `--yes` in disposable state succeeded. Interactive y/N was not entered during this run.
- `taintwatch replay --log testdata/replay/audit.jsonl --policy testdata/replay/candidate.yaml`: executed in WSL. See the fixture's own golden tests for snapshot limitations.
- `taintwatch eval validate`: passed; `taintwatch eval run --markdown`: exit 1, reproducing the 50-scenario documented baseline and the benign TW009 mismatch. The Linux binary was labeled m4.2. The one-line README reproduction combines these same operations; its exact POSIX Make chain was not executed because WSL lacks Go.
- `claude plugin validate .`: passed with Claude Code 2.1.175. `claude plugin marketplace add ./`: passed in isolated config. Installing directly from this checkout encountered a sandbox EPERM while scanning `.git`; staging only distribution files into a disposable directory allowed the same manifest/plugin to install successfully and appear enabled.

- Public marketplace CLI equivalents: `claude plugin marketplace add ratuhin1122/taintwatch` cloned and validated the public repository; `claude plugin install taintwatch@ratuhin1122-plugins` succeeded and `claude plugin list` showed version 0.1.0 enabled. These used a disposable CLAUDE_CONFIG_DIR; they do not prove live slash-command execution or hook delivery.

## Network and links

GitHub's repository API returned HTTP 200 for ratuhin1122/taintwatch; latest-release returned 404. Every README badge image returned HTTP 200, including the actual CI status endpoint; no passing status is hard-coded. The release badge deliberately says not yet published. GitHub issue forms and Dependabot YAML parsed, README internal anchors resolved, and `git diff --check` passed. Local Markdown file targets were checked for existence; SVG XML and the two-frame GIF parsed successfully. The GIF is original placeholder artwork, not a recorded live interaction.

Official marketplace instructions and the two related-project READMEs were read during this task. Their exact links appear beside the claims. Contributor Covenant 2.1 was retrieved from its official Markdown source with attribution retained. These are point-in-time checks; external links and hosted status can change.

## Outstanding acceptance checks

The interactive `/plugin marketplace add ratuhin1122/taintwatch`, `/plugin install taintwatch@ratuhin1122-plugins`, and `/taintwatch:doctor` were not entered into an authenticated live session. CLI equivalents and local packaging checks cannot prove their live behavior. Real hook payloads and tool-specific golden captures remain pending, as recorded in ASSUMPTIONS.md. An exact minimum Claude Code version and normal/tail hook latency remain unmeasured.

Before claiming a complete first-time install in under five minutes: run the source quickstart on a machine with Linux/macOS Go installed, complete the interactive marketplace flow, verify actual hook delivery, and time the sequence. Configure the private security/moderation contacts, publish matching release assets/checksums if offering downloads, and resolve the documented failing eval gate. No release, settings change to the real user profile, or private reporting channel was published by this documentation task.
