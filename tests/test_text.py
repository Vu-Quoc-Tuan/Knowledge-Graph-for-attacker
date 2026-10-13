from utils.text import abridge


def test_abridge_respects_newline_boundary() -> None:
    assert abridge("abc\ndef\nghi", 8, boundary="\n") == "abc…"


def test_abridge_never_exceeds_requested_length() -> None:
    assert len(abridge("abcdefghij", 5, boundary="\n")) == 5
