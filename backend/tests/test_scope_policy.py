from core.models import ScopeConfig
from core.scope import ScopeManager
from core.targeting import classify_target, scope_from_classifications


def test_exact_domain_does_not_authorise_subdomain_active_testing():
    scope = ScopeManager(ScopeConfig(authorized_domains=["matters.ai"]))

    assert scope.is_in_scope("https://matters.ai") is True
    assert scope.is_in_scope("https://app.matters.ai") is False
    assert scope.is_discoverable_host("app.matters.ai") is True


def test_wildcard_domain_authorises_subdomains_for_active_testing():
    scope = ScopeManager(ScopeConfig(authorized_domains=["*.matters.ai"]))

    assert scope.is_in_scope("https://matters.ai") is True
    assert scope.is_in_scope("https://app.matters.ai") is True
    assert scope.is_in_scope("https://api.dev.matters.ai") is True


def test_out_of_scope_overrides_wildcard_authorisation():
    scope = ScopeManager(
        ScopeConfig(
            authorized_domains=["*.matters.ai"],
            out_of_scope=["demo.matters.ai"],
        )
    )

    assert scope.is_in_scope("https://app.matters.ai") is True
    assert scope.is_in_scope("https://demo.matters.ai") is False
    assert scope.is_discoverable_host("demo.matters.ai") is False


def test_wildcard_target_classification_sets_wildcard_scope():
    classification = classify_target("*.matters.ai")
    domains, ips = scope_from_classifications([classification])

    assert classification.target_type == "domain_wildcard"
    assert classification.host == "matters.ai"
    assert classification.metadata["execution_seed"] == "matters.ai"
    assert domains == ["*.matters.ai"]
    assert ips == []
