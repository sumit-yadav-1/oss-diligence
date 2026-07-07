import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.aggregator import _validate_cve_mentions, aggregator_node, _fallback_recommendation
from agents.health_analyst import health_analyst_node
from agents.security_analyst import security_analyst_node
from tools.github_client import GitHubClientError
from tools.osv_client import OSVClientError


def test_health_analyst_handles_github_failure_gracefully():
    """If GitHub API fails, the agent should write health_error, not raise."""
    with patch(
        "agents.health_analyst.fetch_repo_health_signals",
        side_effect=GitHubClientError("repo not found"),
    ):
        result = health_analyst_node({"repo_slug": "nonexistent/repo"})

    assert result["health_report"] is None
    assert "repo not found" in result["health_error"]
    print("PASS: health_analyst_node degrades gracefully on GitHub API failure")


def test_security_analyst_handles_osv_failure_gracefully():
    """If OSV API fails, the agent should write security_error, not raise."""
    with patch(
        "agents.security_analyst.fetch_vulnerabilities",
        side_effect=OSVClientError("network timeout"),
    ):
        result = security_analyst_node(
            {"package_name": "somepackage", "ecosystem": "PyPI", "version": None}
        )

    assert result["security_report"] is None
    assert "network timeout" in result["security_error"]
    print("PASS: security_analyst_node degrades gracefully on OSV API failure")


def test_aggregator_insufficient_evidence_when_both_branches_fail():
    """If both parallel branches failed, aggregator must not fabricate a verdict."""
    state = {
        "health_report": None,
        "health_error": "GitHub rate limited",
        "security_report": None,
        "security_error": "OSV timeout",
    }
    result = aggregator_node(state)

    assert result["recommendation"] == "insufficient evidence"
    assert result["verdict_confidence"] == "low"
    print("PASS: aggregator_node returns 'insufficient evidence' when both branches fail")


def test_hallucination_guard_flags_unverified_cve():
    """
    Core hallucination-guard test: if the LLM's verdict text mentions a CVE ID
    that doesn't appear anywhere in the grounded security report, it must be
    flagged as unverified rather than silently accepted.
    """
    fake_security_report = {
        "raw_signals": {
            "vulnerabilities": [
                {"id": "GHSA-real-1234", "aliases": ["CVE-2024-0001"]},
            ]
        }
    }

    verdict_mentioning_real_and_fake = (
        "This package has GHSA-real-1234 (confirmed) and also CVE-1999-9999 "
        "which does not exist in our source data."
    )

    rejected = _validate_cve_mentions(verdict_mentioning_real_and_fake, fake_security_report)

    assert any("CVE-1999-9999" in r for r in rejected)
    assert not any("GHSA-real-1234" in r for r in rejected)
    print("PASS: hallucination guard flags fabricated CVE IDs and clears real ones")


def test_fallback_recommendation_uses_raw_scores_when_llm_fails():
    health_report = {"maintenance_score": "healthy"}
    security_report = {"risk_level": "critical"}
    rec = _fallback_recommendation(health_report, security_report)
    assert rec == "avoid"
    print("PASS: fallback recommendation correctly prioritizes critical security risk")


if __name__ == "__main__":
    test_health_analyst_handles_github_failure_gracefully()
    test_security_analyst_handles_osv_failure_gracefully()
    test_aggregator_insufficient_evidence_when_both_branches_fail()
    test_hallucination_guard_flags_unverified_cve()
    test_fallback_recommendation_uses_raw_scores_when_llm_fails()
    print("\nAll tests passed.")