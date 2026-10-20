# Policy (planned)

No policy schema or loader is implemented. Planned layering is built-in defaults,
then user, then project. Default restrictions ask; deny requires explicit policy.
Internal errors default open, with an optional closed mode that asks for approval.
Agent-initiated changes weakening Taintwatch must always ask, even when untainted.
These are design requirements, not protections supplied by the scaffold.
