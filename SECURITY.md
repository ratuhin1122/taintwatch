# Security policy

## Private reporting

**TODO for the maintainer before release: configure and verify a private reporting contact.**
Current placeholder: `SECURITY_CONTACT_NOT_CONFIGURED`. This is not a mailbox. Maintainers must replace it with a monitored private address or enable and verify GitHub private vulnerability reporting before inviting sensitive submissions. Do not send reports to an inferred email address and do not publish secrets or exploit details in public issues. If a private route is unavailable, keep sensitive details private; a public request to establish a contact should contain no vulnerability details.

## Scope

Report bypasses of documented action rules, policy trust-boundary failures, state traversal/concurrency flaws, audit secret leakage, unsafe release bootstrap, hook fail-mode/deadline failures and dependency vulnerabilities affecting the current source. Provide version/commit, platform, Claude Code version, a minimal synthetic reproduction, expected/actual decisions, and a proposed impact assessment. Use fake credentials and disposable directories. Native Windows operation and documented best-effort analysis gaps are not promises of protection, but concrete improvements and unexpected behavior are welcome.

The project is pre-release. There is no published supported release series or security backport commitment; fixes initially target the current development branch. See [limitations](docs/LIMITATIONS.md) and [verified assumptions](docs/ASSUMPTIONS.md).

## Response expectations

Once a monitored private channel is configured, the maintainer aims to acknowledge reports within five business days and provide an initial assessment within ten business days. These are goals, not a staffed service or guaranteed SLA; the placeholder currently provides no delivery or response guarantee. Coordinate disclosure and a reasonable fix window privately, including mitigations and advisory publication when appropriate. Do not assume an arbitrary date means the issue is fixed.

## Good-faith research / safe harbor

The maintainer welcomes good-faith testing of a local, disposable copy you control and will not pursue legal action for that authorized research conducted under this policy. Use minimal proof, avoid accessing others' data, do not disrupt services, and stop if unexpected sensitive data is encountered. No authorization extends to Anthropic, GitHub, third-party infrastructure or other users' systems; their owners' permission and applicable law still apply. The maintainer cannot bind third parties or waive their rights.

## Handling logs

Redaction is best-effort. Review even redacted snippets before sharing; session state can retain sensitive extracted values and encoded variants. Never submit full private files, real tokens, or a complete tool-response transcript as a public attachment.
