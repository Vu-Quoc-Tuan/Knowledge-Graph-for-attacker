"""Models for Scenario candidates, validation execution records, and validated scenarios."""

from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field


class ScenarioValidationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    validationId: str = Field(pattern=r"^VAL-[0-9a-f]{8,64}$")
    candidateId: str = Field(min_length=1)
    targetVulnId: str = Field(pattern=r"^[A-Za-z0-9_.-]+$")
    environment: str = Field(min_length=1)
    vulnerableTargetResult: Literal["passed", "failed", "inconclusive"]
    patchedTargetResult: Literal["passed", "failed", "inconclusive"]
    observedOutcome: str = Field(min_length=1)
    executionDigest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    evidenceRef: str = Field(min_length=1)
    evidenceHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    validatedAt: str = Field(min_length=1)
    validatedBy: str = Field(min_length=1)
    # A fixture/demo receipt may prove that a protocol works, but it cannot
    # prove that the named CVE was reproduced on its affected product.
    executionMode: Literal["target", "synthetic"]
    status: Literal["passed", "failed"] = "passed"


class ValidatedScenarioRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    scenarioId: str = Field(min_length=1)
    candidateId: str = Field(min_length=1)
    targetVulnId: str = Field(pattern=r"^[A-Za-z0-9_.-]+$")
    validationId: str = Field(pattern=r"^VAL-[0-9a-f]{8,64}$")
    hypothesisId: str = Field(min_length=1)
    groundingScore: float = Field(ge=0.0, le=1.0)
    steps: list[dict[str, Any]] = Field(min_length=1)
    acceptedAt: str = Field(min_length=1)
    acceptedBy: str = Field(min_length=1)
