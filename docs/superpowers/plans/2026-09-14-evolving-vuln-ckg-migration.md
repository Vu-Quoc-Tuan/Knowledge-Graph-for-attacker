# Evolving Vulnerability CKG Migration — Archived Design Record

This historical plan is retained as an architecture record. Its implementation
checklist and path references were superseded by the canonical v2 runtime work
completed on 2026-09-22.

The current runtime contract is documented in:

- `docs/superpowers/plans/2026-09-22-v2-canonical-unification.md`
- `docs/superpowers/plans/2026-09-22-security-architecture-hardening.md`
- `docs/superpowers/specs/2026-09-19-provenance-temporal-remediation-design.md`

The migration boundary remains explicit: canonical CWE/CAPEC ingestion and the
v2 graph are the maintained runtime path; legacy registry and event-log modules
are one-way adapters used by the dedicated migration command. This record does
not define active tests, entry points, asset trees, or schema migrations.
