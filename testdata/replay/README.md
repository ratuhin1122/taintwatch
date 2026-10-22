# Replay fixtures

These are original synthetic audit records under the repository's MIT license,
not captured user sessions. The portable source paths in the YAML candidates keep
the matching-policy digest independent of the test runner's home/temp directory.

`audit.jsonl` covers enabling a previously disabled match, disabling a selected
rule, competing rules, escalation to deny, a rule-only change, an unchanged
decision, legacy/incomplete history, an unsupported snapshot version and ignored
post/prompt events. `candidate.golden` records the action/enable comparison.
`matching-change.golden` demonstrates that adding a domain cannot be inferred
from the omitted original inputs and is reported as unreplayable.
