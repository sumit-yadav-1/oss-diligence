import time
from typing import Optional

import requests

OSV_API_BASE = "https://api.osv.dev/v1"


class OSVClientError(Exception):
    """Raised when the OSV API can't be reached or returns bad data."""


def _post(url: str, payload: dict, retries: int = 2) -> dict:
    last_exc = None
    for attempt in range(retries + 1):
        try:
            resp = requests.post(url, json=payload, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
                continue
    raise OSVClientError(str(last_exc))


def fetch_vulnerabilities(
    package_name: str, ecosystem: str = "PyPI", version: Optional[str] = None
) -> dict:
    """
    Query OSV.dev for known vulnerabilities affecting a package (and optionally
    a specific version). Returns raw, grounded vulnerability records.

    ecosystem: one of OSV's supported ecosystem strings, e.g. "PyPI", "npm", "Go", "crates.io".
    """
    payload = {"package": {"name": package_name, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version

    data = _post(f"{OSV_API_BASE}/query", payload)
    raw_vulns = data.get("vulns", [])

    shaped = []
    for v in raw_vulns:
        severity = _extract_severity(v)
        shaped.append(
            {
                "id": v.get("id"),
                "summary": v.get("summary", "No summary available"),
                "severity": severity,
                "aliases": v.get("aliases", []),
                "affected_ranges": _extract_ranges(v),
                "fixed": _has_fix(v),
                "published": v.get("published"),
                "source_url": f"https://osv.dev/vulnerability/{v.get('id')}",
            }
        )

    return {
        "package_name": package_name,
        "ecosystem": ecosystem,
        "version_checked": version,
        "vulnerability_count": len(shaped),
        "vulnerabilities": shaped,
    }


def _extract_severity(vuln: dict) -> str:
    db_specific = vuln.get("database_specific", {})
    sev = db_specific.get("severity")
    if sev:
        return sev
    severity_list = vuln.get("severity", [])
    if severity_list:
        return severity_list[0].get("score", "UNKNOWN")
    return "UNKNOWN"


def _extract_ranges(vuln: dict) -> list:
    ranges = []
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            events = r.get("events", [])
            ranges.append(events)
    return ranges


def _has_fix(vuln: dict) -> bool:
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    return True
    return False