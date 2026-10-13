from enum import StrEnum


class FactStatus(StrEnum):
    """Epistemic lifecycle of a claim, distinct from review and execution state."""

    CANONICAL = "CANONICAL"
    REPORTED = "REPORTED"
    EXTRACTED = "EXTRACTED"
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    SUPPORTED = "SUPPORTED"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
