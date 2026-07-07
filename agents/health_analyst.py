from tools.github_client import GitHubClientError, fetch_repo_health_signals
from utils.llm import LLMCallFailed, call_llm
from utils.state import DiligenceState

SYSTEM_PROMPT = """You are a health analyst agent auditing open source dependency maintenance.

You will be given RAW, VERIFIED signals retrieved from the github API about a repository.
Your job is to write a short, grounded assessment of its maintenance health.

STRICT RULES:
- Only make claims that are directly supported by the raw signals given to you.
- Do not invent statistics, dates, or facts not present in the data.
- If a signal is missing (null), say so explicitly rather than guessing.
- End your response with a single line: "SCORE: healthy" or "SCORE: moderate" or "SCORE: concerning"
  based on commit recency, release cadence, contributor count, and archived status.
"""


def health_analyst_node(state: DiligenceState) -> dict:
    repo_slug = state["repo_slug"]

    try:
        raw_signals = fetch_repo_health_signals(repo_slug)
    except GitHubClientError as exc:
        return {
            "health_error": f"Could not retrieve GitHub data for '{repo_slug}': {exc}",
            "health_report": None,
        }

    user_prompt = f"""Repository: {raw_signals['repo_slug']}

Raw signals retrieved from GitHub API:
- Description: {raw_signals['description']}
- Stars: {raw_signals['stars']}
- Forks: {raw_signals['forks']}
- Open issues: {raw_signals['open_issues_count']}
- Archived: {raw_signals['archived']}
- License: {raw_signals['license']}
- Days since last commit: {raw_signals['days_since_last_commit']}
- Contributor count: {raw_signals['contributor_count']}{' (capped at 100, actual may be higher)' if raw_signals['contributor_count_is_capped'] else ''}
- Latest release: {raw_signals['latest_release_tag']}
- Days since last release: {raw_signals['days_since_last_release']}

Write your grounded maintenance-health assessment now."""

    try:
        assessment = call_llm(SYSTEM_PROMPT, user_prompt, max_tokens=500)
    except LLMCallFailed as exc:
        return {
            "health_error": f"LLM assessment failed for '{repo_slug}': {exc}",
            "health_report": {
                "repo_slug": raw_signals["repo_slug"],
                "raw_signals": raw_signals,
                "assessment": "LLM assessment unavailable — raw signals only.",
                "maintenance_score": "unknown",
            },
        }

    score = _extract_score(assessment)

    return {
        "health_report": {
            "repo_slug": raw_signals["repo_slug"],
            "raw_signals": raw_signals,
            "assessment": assessment,
            "maintenance_score": score,
        },
        "health_error": None,
    }


def _extract_score(assessment: str) -> str:
    lower = assessment.lower()
    for candidate in ("healthy", "moderate", "concerning"):
        if f"score: {candidate}" in lower:
            return candidate
    return "unknown"