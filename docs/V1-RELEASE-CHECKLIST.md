# v1.0 release checklist

Use [the dated hardening report](HARDENING.md) as evidence, not as a promise of
complete prompt-injection prevention. Do not tag v1.0 while release gates below
remain unresolved. A v0.9.0 preview is the recommended next milestone.

## Release gates

- [x] Resolve benign MCP code-read friction with unchanged allow expectations;
  stabilization gates provenance on sensitive reuse and the local eval passes.
- [ ] Collect sanitized real Read, WebFetch, Bash and MCP PostToolUse captures;
  turn them into golden fixtures and test ask behavior in a real session.
- [ ] Test a current Claude Code release and record a supported minimum version.
- [ ] Review the final race, fuzz, analysis, vulnerability and latency evidence in
  HARDENING.md. Repeat on macOS and the remaining release architectures in CI.
- [ ] Meet the 50 ms median target on the agreed large-directory fixture, or
  explicitly revise that release target with measured storage costs. Do not
  silently trade away sync/retention behavior to improve a benchmark.
- [ ] Decide whether schema `version: 1`, list merge semantics, anti-loosening,
  fail modes and action/rule identifiers are stable enough to support at v1.0.
- [ ] Resolve or explicitly accept scanner findings with their reachability and
  dependency versions recorded; scanner crashes are not passing scans.
- [ ] Choose whether trusted MCP exceptions must validate provenance as well as
  names before they are advertised for untrusted project configurations.
- [ ] Finish the reviewed corpus expansion (currently 74 scenarios including stabilization regressions),
  with original/permissive provenance and honest synthetic-data qualification.
- [ ] Set a working private SECURITY.md reporting contact; remove placeholders.
- [ ] Record a real demo GIF and ensure README install commands work from the
  published release rather than unpublished local assets.
- [ ] Validate manifests, launcher checksum rejection, snapshot assets, SBOM and
  release metadata; test a clean installation and uninstall with unrelated hooks.
- [ ] Verify tag/version/manifest/changelog agreement and signed checksum
  verification instructions. Check release workflow permissions and action pins.
- [ ] Check publish checklist, name availability and directory submission status
  in PUBLISHING.md. Directory listing is never automatic.
- [ ] Tag only after reviewing the exact tree to be released; retain CI artifacts
  and include known gaps and measured results in release notes.

## Decisions the maintainer should double-check

1. **v0.9.0 first:** live payload compatibility and sustained CI evidence remain release
   risks that a preview makes explicit.
2. **Policy stability:** changing merge/trust/fail semantics after v1.0 can silently
   change users' security expectations. Define migration and compatibility rules.
3. **Provenance scope:** ordinary in-project reads are now allowed; sensitive
   reuse still asks. Review these intentional defaults and regression tests.
4. **Privacy boundary:** redaction recognizes patterns, not every possible secret.
   State contains extracted indicators; free-form metadata must stay secret-free.
5. **Trust and availability:** name-based MCP trust, fail-open defaults, launcher
   time outside the Go deadline, same-user storage tampering and allowlisted
   egress must remain visible rather than being described as containment.
6. **Retention cost:** checking every session on every state write is linear in
   directory size. A future bounded/amortized cleanup schedule would change that
   contract and needs an explicit policy/documentation decision.
