import re
from typing import Any

from utils.text import abridge, collapse

_FENCE_OPEN_RE = re.compile(r"^```[A-Za-z0-9+#-]*\n?")
_FENCE_CLOSE_RE = re.compile(r"\n?```$")


def _clean(text: Any, limit: int = 600) -> str:
    if text is None:
        return ""
    return abridge(collapse(str(text)), limit)


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def likelihood(record: dict[str, Any]) -> str | None:
    return _clean(record.get("LikelihoodOfExploit"), 40) or None


def detection_methods(record: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for method in _as_list(record.get("DetectionMethods")):
        if not isinstance(method, dict):
            continue
        name = _clean(method.get("Method"), 120)
        description = _clean(method.get("Description"))
        if name and description:
            out.append(f"{name}: {description}")
        elif name or description:
            out.append(name or description)
    return out


def mitigations(record: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for mitigation in _as_list(record.get("PotentialMitigations")):
        if not isinstance(mitigation, dict):
            continue
        description = _clean(mitigation.get("Description"))
        if not description:
            continue
        strategy = _clean(mitigation.get("Strategy"), 80)
        out.append(f"[{strategy}] {description}" if strategy else description)
    return out


def applicable_platforms(record: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for platform in _as_list(record.get("ApplicablePlatforms")):
        if not isinstance(platform, dict):
            continue
        # A platform names either a specific technology (Name) or a whole class
        # ("Not Language-Specific"); keep whichever is present.
        name = _clean(platform.get("Name") or platform.get("Class"), 80)
        if not name:
            continue
        kind = _clean(platform.get("Type"), 40)
        prevalence = _clean(platform.get("Prevalence"), 40)
        label = f"{kind}: {name}" if kind else name
        if prevalence:
            label = f"{label} ({prevalence})"
        out.append(label)
    return out


def demonstrative_examples(record: dict[str, Any], limit: int = 6) -> list[str]:
    """Code snippets from the examples, tagged with their nature and language.

    MITRE wraps each snippet in a markdown fence and labels it Bad/Good/Attack;
    that label is worth keeping (a "Good" snippet is the fix, "Bad" the flaw).
    """
    out: list[str] = []
    for example in _as_list(record.get("DemonstrativeExamples")):
        if not isinstance(example, dict):
            continue
        for entry in _as_list(example.get("Entries")):
            if not isinstance(entry, dict) or not entry.get("ExampleCode"):
                continue
            snippet = str(entry["ExampleCode"]).strip()
            snippet = _FENCE_OPEN_RE.sub("", snippet)
            snippet = _FENCE_CLOSE_RE.sub("", snippet).strip()
            # On a newline: half a line of code is worse than one line fewer.
            snippet = abridge(snippet, 800, boundary="\n")
            if not snippet:
                continue
            tag = "/".join(
                part
                for part in (
                    _clean(entry.get("Nature"), 30),
                    _clean(entry.get("Language"), 30),
                )
                if part
            )
            out.append(f"[{tag}]\n{snippet}" if tag else snippet)
            if len(out) >= limit:
                return out
    return out