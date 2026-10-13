from __future__ import annotations

from ingest.slices import SLICES


def test_every_authoritative_slice_family_has_strategy_hint() -> None:
    missing = sorted(
        (slice_.weakness_id, family.key)
        for slice_ in SLICES
        for family in (
            *slice_.families,
            *((slice_.intruder_family,) if slice_.intruder_family else ()),
        )
        if family.detection_signal is None
    )
    assert missing == []
