# Evidence Contract

Every persisted claim references one or more `EvidenceSpan` records. A span has
an `evidence_id`, a SHA-256 digest of immutable source bytes and a non-empty
locator. Locators are source-relative: JSON Pointer for JSON, an XPath plus
attribute or line range for XML, heading/range for Markdown and file/hunk range
for a patch.

`retrieved_at` records when the system acquired bytes. Publication time is a
property of the source record, not a replacement for retrieval/known time.
Evidence content is written once to `objects/<sha256>` and read back only after
the digest is checked.
