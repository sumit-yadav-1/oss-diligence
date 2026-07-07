import os
import time
from datetime import datetime, timezone
from typing import Optional

import requests

GITHUB_API_BASE = "https://api.github.com"


class GitHubClientError(Exception):
    """Raised when the GitHub API can't be reached or returns bad data."""


def _headers() -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _get(url: str, params: Optional[dict] = None, retries: int = 2) -> dict:
    """GET with basic retry/backoff. Raises GitHubClientError on final failure."""
    last_exc = None
    for attempt in range(retries + 1):
        try:
            resp = requests.get(url, headers=_headers(), params=params, timeout=10)
            if resp.status_code == 404:
                raise GitHubClientError(f"Repository or resource not found: {url}")
            if resp.status_code == 403 and "rate limit" in resp.text.lower():
                raise GitHubClientError(
                    "GitHub API rate limit exceeded. Set GITHUB_TOKEN in .env to raise the limit."
                )
            resp.raise_for_status()
            return resp.json()
        except (requests.RequestException, GitHubClientError) as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
                continue
    raise GitHubClientError(str(last_exc))


def parse_repo_slug(repo_input: str) -> str:
    """
    Accepts 'owner/repo' or a full GitHub URL and returns 'owner/repo'.
    """
    repo_input = repo_input.strip().rstrip("/")
    if "github.com" in repo_input:
        parts = repo_input.split("github.com/")[-1].split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        raise GitHubClientError(f"Could not parse owner/repo from URL: {repo_input}")
    if "/" in repo_input:
        return repo_input
    raise GitHubClientError(
        f"Expected 'owner/repo' or a GitHub URL, got: {repo_input}"
    )


def fetch_repo_health_signals(repo_slug: str) -> dict:
    """
    Fetch raw, factual health/maintenance signals for a repo.
    Returns a dict of grounded facts — no interpretation.
    """
    repo_slug = parse_repo_slug(repo_slug)
    base = f"{GITHUB_API_BASE}/repos/{repo_slug}"

    repo_data = _get(base)

    #Recent commit activity
    try:
        commits = _get(f"{base}/commits", params={"per_page": 1})
        last_commit_date = commits[0]["commit"]["committer"]["date"] if commits else None
    except GitHubClientError:
        last_commit_date = None

    #Issues
    open_issues_count = repo_data.get("open_issues_count", 0)

    #Contributors
    try:
        contributors = _get(f"{base}/contributors", params={"per_page": 100, "anon": "true"})
        contributor_count = len(contributors)
        contributor_count_is_capped = len(contributors) == 100
    except GitHubClientError:
        contributor_count = None
        contributor_count_is_capped = False

    #Latest release
    try:
        latest_release = _get(f"{base}/releases/latest")
        latest_release_date = latest_release.get("published_at")
        latest_release_tag = latest_release.get("tag_name")
    except GitHubClientError:
        latest_release_date = None
        latest_release_tag = None

    days_since_last_commit = _days_since(last_commit_date)
    days_since_last_release = _days_since(latest_release_date)

    return {
        "repo_slug": repo_slug,
        "description": repo_data.get("description"),
        "stars": repo_data.get("stargazers_count"),
        "forks": repo_data.get("forks_count"),
        "open_issues_count": open_issues_count,
        "archived": repo_data.get("archived", False),
        "license": (repo_data.get("license") or {}).get("spdx_id"),
        "last_commit_date": last_commit_date,
        "days_since_last_commit": days_since_last_commit,
        "contributor_count": contributor_count,
        "contributor_count_is_capped": contributor_count_is_capped,
        "latest_release_tag": latest_release_tag,
        "latest_release_date": latest_release_date,
        "days_since_last_release": days_since_last_release,
        "source_url": repo_data.get("html_url"),
    }


def _days_since(iso_date: Optional[str]) -> Optional[int]:
    if not iso_date:
        return None
    dt = datetime.strptime(iso_date, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days