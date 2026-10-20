# Hook fixtures and provenance

No real Claude Code session payloads have been supplied yet. The files currently
under `spike/captures/` are synthetic smoke inputs and must not be promoted to
real-payload golden fixtures.

`outputs/*.golden` are **documentation-derived output expectations**, based on the
verified JSON in `docs/ASSUMPTIONS.md`. They are not captured Claude Code inputs.
Real sanitized input fixtures must record their originating Claude Code version,
event, tool, and capture provenance before being added here.

`inputs/*.documented.json` are synthetic examples of the documented envelope, added
with the user's approval to proceed while real captures are pending. They do not
establish live compatibility or complete tool-response schemas. Decoder tests
also construct clearly synthetic unknown-field and arbitrary-response probes.
