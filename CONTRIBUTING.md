# Contributing to Taintwatch

Start with a small issue or pull request describing the observable behavior and a sanitized sequence of hook events. Discuss broad policy/schema changes before implementing them. Follow the [Code of Conduct](CODE_OF_CONDUCT.md); vulnerabilities belong in the [private reporting process](SECURITY.md), once configured.

## Development

Use Go 1.26+, Make, a POSIX shell, and a race-capable C toolchain on Linux/macOS. Windows contributors should use WSL for runtime state tests. From the checkout root:

```sh
make build test lint
```

CI covers Ubuntu/macOS and Go 1.26.x/stable. Eval is a separate strict gate: declared harmful-step known misses are expected failures; every other expectation mismatch and every passing known-miss scenario fails CI. See the exact reproduction command and measured baseline in [EVAL.md](docs/EVAL.md); do not hide it by changing an expected allow to ask without a reviewed behavioral reason.

## Changes and validation

Add table tests for new rule behavior, near-misses and wrappers; add bounded fuzz targets for new parsers. Check the relevant package first, then the complete build/test/lint targets. Never weaken project-policy anti-loosening, bootstrap verification, redaction or hook deadlines incidentally. Content detectors remain informational.

For corpus contributions, supply ordered events, harmful-step expectations, provenance and license metadata. Write original payloads or attribute permissively licensed material. Explain known misses; do not claim synthetic coverage is real-world efficacy. No real credentials, full private tool responses or unredacted logs in issues or fixtures.

Keep changes focused. PRs should explain user-visible behavior, validation and limitations. Update policy/architecture/compatibility docs when contracts change. Maintain the MIT license and existing copyright notices; contributors retain ownership of their contributions.

## Documentation and releases

Use working relative links and copy-pasteable examples. Record which commands ran, on what platform, and what remains unverified. A live authenticated Claude Code test is distinct from synthetic replay or manifest validation.

Before publication, configure the private security/moderation contacts, verify live payloads, resolve or explicitly communicate the failing eval gate, publish matching release assets/checksums, replace the demo placeholder with an original recording, and update release status. See [README verification](docs/README-VERIFICATION.md).
