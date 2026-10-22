# Publishing Taintwatch

Prepared 2026-10-22; final validation and anonymous GitHub readback 2026-10-23. This is a launch runbook, not an announcement that Taintwatch has been accepted by a directory. External submission instructions were read from their operators' pages on this date; check them again before submitting. No directory submission or announcement was sent during M4.5.

**Current launch status: not ready.** Exact GitHub metadata from Part 3 is applied and verified. There is no published release at the checked latest-release endpoint, the demo GIF is a labeled placeholder, SECURITY.md has no monitored private contact, live payload confirmation is pending, and the documented eval gate has a benign TW009 mismatch. Checked preparation items below do not waive these launch blockers.

## Plugin and marketplace metadata

The following plugin values are applied in `.claude-plugin/plugin.json`:

```json
{
  "name": "taintwatch",
  "version": "0.1.0",
  "description": "A Claude Code plugin for action-based prompt injection defense using taint tracking, approval gates, and a local audit log.",
  "author": {
    "name": "ratuhin1122"
  },
  "homepage": "https://github.com/ratuhin1122/taintwatch",
  "repository": "https://github.com/ratuhin1122/taintwatch",
  "license": "MIT",
  "keywords": [
    "claude-code",
    "claude-code-plugin",
    "claude-code-hooks",
    "prompt-injection",
    "indirect-prompt-injection",
    "taint-tracking",
    "ai-agent-security",
    "guardrails",
    "mcp-security",
    "secret-protection",
    "data-exfiltration",
    "audit-log",
    "golang"
  ]
}
```

The single-plugin repository uses this marketplace catalog at `.claude-plugin/marketplace.json`:

```json
{
  "name": "ratuhin1122-plugins",
  "description": "Independent security plugins maintained by ratuhin1122.",
  "owner": {
    "name": "ratuhin1122"
  },
  "plugins": [
    {
      "name": "taintwatch",
      "source": "./",
      "description": "A Claude Code plugin for action-based prompt injection defense using taint tracking, approval gates, and a local audit log.",
      "category": "security",
      "tags": [
        "claude-code",
        "prompt-injection",
        "taint-tracking",
        "mcp-security",
        "secret-protection",
        "audit-log"
      ]
    }
  ]
}
```

The entry deliberately uses the same plugin name and root source `./`. Manifest discovery terms belong in `keywords`; the marketplace entry supports `category` and `tags`. `ratuhin1122-plugins` is an owner-scoped name, not a reserved or official-sounding Anthropic name. The supported fields and reserved-name rules were checked in the [official marketplace reference](https://code.claude.com/docs/en/plugins/marketplace-reference). Passing local validation does not reserve a globally unique directory name.

From the repository root:

```sh
claude plugin validate .
claude plugin validate --strict .
claude plugin validate --strict ./.claude-plugin/plugin.json
```

All three commands passed with Claude Code 2.1.175 on 2026-10-22. This validates file formats; it does not prove hook delivery, portal eligibility, or approval. See [ASSUMPTIONS.md](ASSUMPTIONS.md).

## Exact GitHub About settings — maintainer supplied

Repository: [ratuhin1122/taintwatch](https://github.com/ratuhin1122/taintwatch). The description and all twenty topics below were supplied verbatim in Part 3. The supplied repository link is also used as the Website value. The topics are an exact replacement set, not an append to plugin keywords.

```json
{
  "description": "Taint-tracking guardrails for Claude Code. Flags untrusted content (web, MCP, issues) and gates secret reads, network egress and git push. Prompt injection defense with an audit log. Written in Go.",
  "homepage": "https://github.com/ratuhin1122/taintwatch",
  "topics": [
    "claude-code",
    "claude-code-plugin",
    "claude-code-hooks",
    "prompt-injection",
    "ai-agent-security",
    "llm-security",
    "ai-security",
    "taint-tracking",
    "mcp-security",
    "guardrails",
    "ai-coding-agent",
    "data-exfiltration",
    "secret-protection",
    "zero-trust",
    "devsecops",
    "security-tools",
    "audit-log",
    "anthropic",
    "golang",
    "go"
  ]
}
```

**Application status: applied and verified on 2026-10-22.** GitHub API readback matched the description and website exactly and the complete twenty-topic set. The description already matched before the update; the website and topics were previously unset. The supplied repository link was used as the website, as stated above.

For future changes, use repository administration access to set these values, then read back the public metadata. If GitHub rejects a supplied value, report its validation error instead of silently rewriting it. See the [GitHub repository API](https://docs.github.com/en/rest/repos/repos#update-a-repository).

## Social preview specification

[Original SVG source](assets/social-preview.svg): **1280 × 640**, viewBox `0 0 1280 640`, opaque background, no external images, scripts, fonts, or artwork. It uses the original Taintwatch shield, the title, source → taint → approval flow, a local audit-log caption, and a short defense-in-depth limitation. Text stays within a 64-pixel horizontal safe margin; the illustration makes no efficacy or endorsement claim.

Suggested alt text: “Taintwatch tracks untrusted sources, marks session taint, and asks before selected risky actions, with a local audit log.”

GitHub requires a supported raster upload rather than this SVG source. Export an opaque 1280 × 640 PNG under 1 MB, inspect readability at social-card size, then upload it through repository Settings → General → Social preview. That export/upload remains a launch step; the SVG is the editable spec. See [GitHub social preview documentation](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/customizing-your-repositorys-social-media-preview).

## Anthropic community/directory submission — current process

The current [Claude Code publishing guide](https://code.claude.com/docs/en/plugins/publish#submit-to-anthropics-directory) sends community submissions to the developer portal at [claude.ai/directory/manage](https://claude.ai/directory/manage). Do not treat older community forms or a PR against a marketplace mirror as the current workflow. Listing is **not automatic**. `claude-plugins-official` does **not** accept submissions through the community/directory forms or portal; the guide directs authors with an Anthropic partner contact to discuss that separate route with them.

Follow the [official submission instructions](https://claude.com/docs/plugins/submit):

1. Confirm eligible paid-plan/role access and connect a GitHub account that can push to this repository. The repository must be public before publication.
2. In the portal, choose **Submit new → Plugin bundle**.
3. Enter repository `ratuhin1122/taintwatch`; this plugin is at the repository root, so no subfolder is needed. Choose the tracked branch or tag intentionally; a tag remains on its commit.
4. Select **Validate**. Fix blocking findings, push, and revalidate the changed commit. Local CLI validation covers fewer checks.
5. Review the listing details. Answer the data-handling questions accurately, provide a working contact, and complete the compliance acknowledgements.
6. Review and submit. Choose push-webhook or scheduled update checks deliberately; webhook setup requires repository admin access. Follow the portal's review and publication controls for that version; submission alone is not publication.

Before attempting this, complete the [official pre-submission checklist](https://claude.com/docs/plugins/pre-submission-checklist). Directory validation checks name collisions beyond the CLI's schema validation. The launcher/download behavior and compiled artifacts need explicit review against those rules; a valid manifest is not evidence they will be accepted.

**Platform scope:** Taintwatch has been built for Claude Code, not verified in chat or Cowork. The [official support table](https://claude.com/docs/plugins/platform-support) distinguishes hook support and top-level `bin/` executables by surface; in particular, those executables prevent installation on chat/Cowork. Let portal validation establish the supported listing surfaces; do not advertise cross-app compatibility.

**Data-handling answers must describe local storage.** Runtime hook analysis has no outbound telemetry or model calls, but local audit records and session indicators can contain personal or sensitive metadata. State retention and audit rotation are configurable; redaction is best-effort. Explicit installation/bootstrap can fetch public assets. Disclose these distinctions rather than answering “stores no data” or “never uses the network.” See [limitations](LIMITATIONS.md), [architecture](ARCHITECTURE.md), and [release verification](releases.md).

## Independent directories with verified submission routes

The following operators' own submission pages were opened on 2026-10-22. Both currently accept this kind of project for consideration; neither has accepted Taintwatch, and availability of a submission route is not an endorsement or guaranteed listing.

| Directory | Verified route | What to prepare |
| --- | --- | --- |
| [ClaudePluginHub](https://www.claudepluginhub.com/tools/submit-plugin) | Sign in, then submit a public GitHub plugin or marketplace URL for validation/indexing. Its page describes a queue and manifest/component checks. | Public repository URL, valid plugin manifest and working installation instructions. |
| [Claude Code Marketplaces](https://www.claudemarketplace.net/submit) | Its page explicitly accepts plugin marketplaces and developer tools; use the email/message contact shown there to request review. | Repository URL, short summary, README, install steps, logo and suggested category. |

Use `https://github.com/ratuhin1122/taintwatch` for either route after the release and safety checklist is satisfied. No email, message, form or PR was sent. Recheck the linked page and its submission conditions before contacting its operator. Directories whose plugin-submission route could not be established were omitted; a live homepage or automatic index is not evidence that manual plugin submissions are accepted.

## Launch checklist

Preparation is complete only when each relevant unchecked launch gate is resolved. Keep evidence beside the item instead of checking it merely because a file exists.

### Metadata and identity

- [x] Plugin description is one factual sentence using the primary terms; repository/homepage/license and discoverable keywords are set.
- [x] Marketplace entry uses supported description/category/tags and the owner-scoped name `ratuhin1122-plugins`.
- [x] Local marketplace and plugin validation pass (Claude Code 2.1.175; commands above).
- [x] Exact GitHub description, website and all twenty topics from Part 3 applied and read back on 2026-10-22. Approved values are recorded above.
- [ ] Directory name availability checked by portal validation for `taintwatch`, including look-alikes; retain the result for the submitted commit. Local validation is not a reservation or trademark clearance.
- [ ] Check the chosen name against relevant existing projects/brands before public promotion. No global uniqueness or legal clearance is claimed.

### Working release and evidence

- [ ] Tagged release published with matching manifest/launcher/tag versions and a nonempty versioned CHANGELOG section; verify all four platform assets, checksums, SBOMs and the workflow's Cosign identity. See [release runbook](releases.md). The checked latest-release endpoint returned 404 on 2026-10-22.
- [ ] Resolve the existing benign TW009 expectation failure before the release workflow can pass its strict eval gate; rerun and record the outcome.
- [ ] Capture and sanitize actual Claude Code hook payloads, verify delivery, and complete pending real-payload golden tests. See [assumptions](ASSUMPTIONS.md).
- [ ] Perform a fresh Linux/macOS install and time the first decision; do not advertise an unmeasured five-minute or latency claim.
- [ ] Replace `docs/assets/demo.gif` with an original live recording and an accurate text transcript. It is currently a labeled placeholder, not a live demo.
- [x] README evaluation numbers are filled with the measured 50-scenario synthetic baseline and reproduction command, including the benign ask. See [EVAL.md](EVAL.md).
- [ ] Rerun evaluation at the release commit; update date, version, corpus size/hashes, misses and friction together if anything changed. Preserve the synthetic-corpus caveat.
- [ ] Review advisory govulncheck/gosec reports and document the disposition of relevant findings; nonblocking scans do not mean findings are resolved.

### Trust and presentation

- [ ] Set and test a monitored private reporting contact in SECURITY.md; configure the pending moderation contact as well. No invented address or unstaffed response guarantee.
- [x] Editable original social preview spec exists at 1280 × 640.
- [ ] Export the social preview as PNG, inspect it, and upload it in GitHub's repository settings.
- [ ] Confirm README examples, release/install availability, supported platforms, fail mode, storage/network disclosures and limitations match the release.
- [ ] Complete portal validation, review and publication when ready; record the submission/version state without claiming official-marketplace inclusion.
- [ ] Optionally submit to the verified independent directories, recording actual review/listing status.
- [ ] Pin the repository on the maintainer's GitHub profile when launch-ready; pinning is not a directory listing or endorsement.
- [ ] Publish the reviewed announcement only after its links and claims match the released commit.

## Announcement outline

Draft for maintainer review; not posted:

1. **Problem:** Coding agents read issue text, dependency READMEs, web pages and MCP results that can contain indirect prompt injection. Explain the risky follow-up actions without sensational examples or real secrets.
2. **Approach:** Taintwatch tracks untrusted sources at session level and asks before selected secret reads, egress and protected changes. Show WebFetch → Read .env with an explainable rule ID and local audit record; distinguish informational content detectors from action rules.
3. **Evidence:** Link the dated, reproducible synthetic evaluation and report benign friction and known misses alongside guarded scenarios. Do not extrapolate to real-world coverage or compare competitors without the same evaluation.
4. **Honest limitations:** Coarse taint, best-effort shell parsing, transformed-value evasion, allowlisted-host leakage, user approvals and hook visibility. Keep native permissions and sandboxing; a clean-session .env read is allowed by the default policy.
5. **How to try it:** Link the README, release verification, supported-platform source/demo path and `/taintwatch:doctor`. Only offer release downloads after they exist. Invite sanitized false-positive reports and point private vulnerabilities to the configured security contact.

Suggested title: **Taintwatch: action-based taint-tracking guardrails for Claude Code**.

Taintwatch is an independent open-source project and is not affiliated with or endorsed by Anthropic. “Claude” and “Claude Code” are trademarks of Anthropic.

## Final verification — 2026-10-23

- `claude plugin validate .`, strict marketplace validation, and strict plugin-manifest validation passed with Claude Code 2.1.175.
- An unauthenticated public GitHub API readback matched the exact supplied description, website, and all twenty topics. The prior authenticated apply/readback also succeeded; the later anonymous check had been interrupted by an approval-service usage limit and completed on this date.
- Embedded JSON metadata matches the actual manifest/catalog files and approved About values. Local documentation links resolve; the original SVG parses as 1280 by 640 with no external artwork or scripts, and its text fits the specified horizontal safe bounds.
- Submission routes are sourced and dated above. No submission, announcement, release publication, social-preview upload, or global name reservation is claimed. Unchecked items are launch work, not completed discoverability checks.
