import re

_WHITESPACE_RE = re.compile(r"\s+")
ELLIPSIS = "…"

def collapse(text: str) -> str:
    """One line, single-spaced. Upstream wraps prose at arbitrary columns."""
    return _WHITESPACE_RE.sub(" ", text).strip()

def abridge(text: str, limit: int, *, boundary: str = " ") -> str:
    """
    A hard slice cut MITRE descriptions mid-word ("...able to exploit this discr")
    and code snippets mid-token. Both read as corrupted data rather than as an
    excerpt, and left the consumer no way to tell which it was.
    """
    if len(text) <= limit:
        return text
    head = text[: max(limit - len(ELLIPSIS), 0)]
    cut = head.rsplit(boundary, 1)[0] if boundary in head else head
    trailing = " ,;:" if boundary == " " else " "
    cut = cut.rstrip(trailing)
    return f"{cut or head.rstrip(trailing)}{ELLIPSIS}"