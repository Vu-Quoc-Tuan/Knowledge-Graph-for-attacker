"""Evaluate ALL/ANY/NOT constraints without collapsing unknown to false."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ckg.domain.enums.applicability import Applicability


class ConstraintKind(StrEnum):
    CONFIGURATION = "configuration"
    VERSION = "version"
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    FEATURE = "feature"
    ENVIRONMENT = "environment"


@dataclass(frozen=True)
class EnvironmentSnapshot:
    environment_id: str
    product: str | None = None
    version: str | None = None
    configuration: dict[str, bool | None] | None = None
    network: dict[str, bool | None] | None = None
    authentication: dict[str, bool | None] | None = None
    features: dict[str, bool | None] | None = None

    def value(self, kind: str, key: str) -> bool | None:
        data = {
            ConstraintKind.CONFIGURATION: self.configuration,
            ConstraintKind.NETWORK: self.network,
            ConstraintKind.AUTHENTICATION: self.authentication,
            ConstraintKind.FEATURE: self.features,
        }.get(ConstraintKind(kind)) if kind in ConstraintKind._value2member_map_ else None
        return data.get(key) if data else None


@dataclass(frozen=True)
class EvaluatedConstraint:
    applicability: Applicability
    satisfied: tuple[str, ...]
    unsatisfied: tuple[str, ...]
    unknown: tuple[str, ...]


def _not(value: Applicability) -> Applicability:
    if value == Applicability.APPLICABLE:
        return Applicability.NOT_APPLICABLE
    if value == Applicability.NOT_APPLICABLE:
        return Applicability.APPLICABLE
    return Applicability.UNKNOWN


def _all(values: list[Applicability]) -> Applicability:
    if any(value == Applicability.NOT_APPLICABLE for value in values):
        return Applicability.NOT_APPLICABLE
    if any(value == Applicability.UNKNOWN for value in values):
        return Applicability.UNKNOWN
    return Applicability.APPLICABLE


def _any(values: list[Applicability]) -> Applicability:
    if any(value == Applicability.APPLICABLE for value in values):
        return Applicability.APPLICABLE
    if any(value == Applicability.UNKNOWN for value in values):
        return Applicability.UNKNOWN
    return Applicability.NOT_APPLICABLE


_VERSION_PART = re.compile(r"^(\d+(?:\.\d+)*)$")


def _version_tuple(value: str) -> tuple[int, ...] | None:
    match = _VERSION_PART.fullmatch(value.strip())
    return tuple(int(item) for item in match.group(1).split(".")) if match else None


def _compare_versions(actual: str | None, operator: str, expected: str) -> Applicability:
    left, right = _version_tuple(actual or ""), _version_tuple(expected)
    if left is None or right is None:
        return Applicability.UNKNOWN
    width = max(len(left), len(right))
    left += (0,) * (width - len(left))
    right += (0,) * (width - len(right))
    operators = {
        "==": left == right,
        ">=": left >= right,
        ">": left > right,
        "<=": left <= right,
        "<": left < right,
    }
    if operator not in operators:
        return Applicability.UNKNOWN
    return Applicability.APPLICABLE if operators[operator] else Applicability.NOT_APPLICABLE


def _parse_expression(expression: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(expression, dict):
        return expression
    try:
        parsed = json.loads(expression)
    except json.JSONDecodeError as exc:
        raise ValueError("constraint expression must be JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("constraint expression must be an object")
    return parsed


def evaluate(expression: str | dict[str, Any], environment: EnvironmentSnapshot) -> EvaluatedConstraint:
    """Evaluate expression grammar: leaf, ``all``, ``any`` and ``not``.

    Leaf shape is ``{"kind": "network", "key": "dns_egress", "equals":
    true}``; version leaf is ``{"kind": "version", "operator": "<",
    "value": "2.0"}``.  Invalid/missing data returns UNKNOWN rather than a
    deceptive negative applicability result.
    """
    satisfied: list[str] = []
    unsatisfied: list[str] = []
    unknown: list[str] = []

    def visit(node: dict[str, Any], path: str) -> Applicability:
        if "all" in node:
            children = node["all"]
            if not isinstance(children, list) or not children:
                unknown.append(path)
                return Applicability.UNKNOWN
            return _all([visit(child, f"{path}/all/{index}") if isinstance(child, dict) else Applicability.UNKNOWN for index, child in enumerate(children)])
        if "any" in node:
            children = node["any"]
            if not isinstance(children, list) or not children:
                unknown.append(path)
                return Applicability.UNKNOWN
            return _any([visit(child, f"{path}/any/{index}") if isinstance(child, dict) else Applicability.UNKNOWN for index, child in enumerate(children)])
        if "not" in node:
            child = node["not"]
            if not isinstance(child, dict):
                unknown.append(path)
                return Applicability.UNKNOWN
            return _not(visit(child, f"{path}/not"))
        kind = str(node.get("kind", ""))
        if kind == ConstraintKind.VERSION:
            result = _compare_versions(environment.version, str(node.get("operator", "")), str(node.get("value", "")))
        elif kind in {item.value for item in ConstraintKind if item != ConstraintKind.VERSION}:
            actual = environment.value(kind, str(node.get("key", "")))
            expected = node.get("equals", True)
            result = Applicability.UNKNOWN if actual is None or not isinstance(expected, bool) else (Applicability.APPLICABLE if actual == expected else Applicability.NOT_APPLICABLE)
        else:
            result = Applicability.UNKNOWN
        if result == Applicability.APPLICABLE:
            satisfied.append(path)
        elif result == Applicability.NOT_APPLICABLE:
            unsatisfied.append(path)
        else:
            unknown.append(path)
        return result

    result = visit(_parse_expression(expression), "$")
    return EvaluatedConstraint(result, tuple(satisfied), tuple(unsatisfied), tuple(unknown))
