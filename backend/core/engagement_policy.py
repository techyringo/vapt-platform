"""Deterministic engagement intensity and authorization policy."""

from __future__ import annotations

from typing import Any


INTENSITY_LIMITS: dict[str, dict[str, int]] = {
    "safe": {
        "rate_limit": 2,
        "max_depth": 3,
        "max_pages": 150,
        "max_requests_total": 3_000,
    },
    "standard": {
        "rate_limit": 5,
        "max_depth": 5,
        "max_pages": 500,
        "max_requests_total": 15_000,
    },
    "lab": {
        "rate_limit": 20,
        "max_depth": 8,
        "max_pages": 1_500,
        "max_requests_total": 50_000,
    },
}


def engagement_limits(overrides: dict[str, Any] | None) -> dict[str, Any]:
    """Return bounded limits for an explicitly authorised assessment.

    Callers may lower a profile limit, but cannot silently exceed it. The lab
    profile requires a separate confirmation so a real client target cannot be
    moved into high-volume behaviour with one accidental selection.
    """
    values = dict(overrides or {})
    if values.get("authorization_confirmed") is not True:
        raise ValueError("Confirm that you own the targets or are explicitly authorized to test them")

    intensity = str(values.get("intensity") or "safe").strip().lower()
    if intensity not in INTENSITY_LIMITS:
        raise ValueError(f"Unknown assessment intensity: {intensity}")
    if intensity == "lab" and values.get("lab_target_confirmed") is not True:
        raise ValueError("Lab intensity requires confirmation that every target is an isolated test system")

    policy = dict(INTENSITY_LIMITS[intensity])
    for key, ceiling in INTENSITY_LIMITS[intensity].items():
        requested = values.get(key)
        if requested is None or requested == "":
            continue
        try:
            parsed = int(requested)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key} must be an integer") from exc
        if parsed < 1:
            raise ValueError(f"{key} must be at least 1")
        policy[key] = min(parsed, ceiling)

    return {
        **policy,
        "intensity": intensity,
        "authorization_confirmed": True,
        "lab_target_confirmed": intensity == "lab",
    }
