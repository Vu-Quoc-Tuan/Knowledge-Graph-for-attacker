from ckg.ingestion.digests import sha256_digest, verify_snapshot_digest


def test_source_snapshot_digest_must_match_exact_bytes() -> None:
    content = b"canonical source bytes"
    verify_snapshot_digest(content, sha256_digest(content))
    try:
        verify_snapshot_digest(content, "sha256:" + "0" * 64)
    except ValueError as error:
        assert "mismatch" in str(error)
    else:
        raise AssertionError("mismatched source digest must be rejected")
