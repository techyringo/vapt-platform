import pytest

from core.engagement_policy import engagement_limits


def test_engagement_requires_explicit_authorization():
    with pytest.raises(ValueError, match="authorized"):
        engagement_limits({"intensity": "safe"})


def test_standard_limits_cannot_be_silently_exceeded():
    policy = engagement_limits({
        "authorization_confirmed": True,
        "intensity": "standard",
        "rate_limit": 500,
        "max_requests_total": 999_999,
    })
    assert policy["rate_limit"] == 5
    assert policy["max_requests_total"] == 15_000


def test_lab_profile_requires_separate_confirmation():
    with pytest.raises(ValueError, match="isolated test system"):
        engagement_limits({"authorization_confirmed": True, "intensity": "lab"})

    policy = engagement_limits({
        "authorization_confirmed": True,
        "intensity": "lab",
        "lab_target_confirmed": True,
    })
    assert policy["rate_limit"] == 20
