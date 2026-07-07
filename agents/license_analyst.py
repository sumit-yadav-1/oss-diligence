from tools.github_client import (
    GitHubClientError,
    fetch_repo_health_signals,
)

from utils.llm import call_llm, LLMCallFailed
from utils.state import DiligenceState


SYSTEM_PROMPT = """
You are a License Compliance Analyst.

Determine whether the repository's software license
poses adoption or compliance risks.

Classify compatibility as:

- permissive
- caution
- restrictive
- unknown

Examples:

MIT -> permissive
Apache-2.0 -> permissive
BSD-3-Clause -> permissive
LGPL -> caution
GPL -> restrictive
AGPL -> restrictive

End with:

COMPATIBILITY: permissive|caution|restrictive|unknown
"""


def license_analyst_node(state: DiligenceState):

    repo_slug = state["repo_slug"]

    try:
        repo_data = fetch_repo_health_signals(repo_slug)

    except GitHubClientError as exc:
        return {
            "license_error": str(exc),
            "license_report": None,
        }

    license_name = repo_data.get("license")

    if not license_name:
        return {
            "license_error": "No license detected",
            "license_report": None,
        }

    try:

        assessment = call_llm(
            SYSTEM_PROMPT,
            f"Repository license: {license_name}",
            max_tokens=200,
        )

    except LLMCallFailed as exc:

        return {
            "license_error": str(exc),
            "license_report": {
                "license_name": license_name,
                "compatibility": "unknown",
                "assessment": "LLM unavailable",
            },
        }

    compatibility = _extract_compatibility(assessment)

    return {
        "license_report": {
            "license_name": license_name,
            "compatibility": compatibility,
            "assessment": assessment,
        },
        "license_error": None,
    }


def _extract_compatibility(text):

    lower = text.lower()

    for c in (
        "permissive",
        "caution",
        "restrictive",
        "unknown",
    ):
        if f"compatibility: {c}" in lower:
            return c

    return "unknown"