from utils.llm import LLMCallFailed, call_llm
from utils.state import DiligenceState

SYSTEM_PROMPT = """You are the Aggregator/Critic agent in a dependency due-diligence system.

You receive three independent reports:

1. Health Report (maintenance signals)
2. Security Report (vulnerability signals)
3. License Report (license compliance signals)

Your job:
- Reconcile all reports into ONE final verdict.
- Explicitly call out conflicts.
- Use only facts present in the reports.
- If any report is unavailable, mention that limitation.
- Do NOT invent facts.

You MUST use EXACTLY this structure:

**VERDICT:**

One overall summary paragraph.

**Health Report:**
Summarize the maintenance assessment.

**Security Report:**
Summarize the vulnerability assessment.

**License Report:**
Summarize the license assessment.

**Conflicts:**
Describe any conflicts between reports.
If there are no conflicts, explicitly write:
"No material conflicts identified."

End with exactly:

RECOMMENDATION: <safe to use | use with caution | avoid | insufficient evidence>
CONFIDENCE: <high | medium | low>
"""


def aggregator_node(state: DiligenceState) -> dict:

    health_report = state.get("health_report")
    health_error = state.get("health_error")

    security_report = state.get("security_report")
    security_error = state.get("security_error")

    license_report = state.get("license_report")
    license_error = state.get("license_error")

    if (
        not health_report
        and not security_report
        and not license_report
    ):
        return {
            "final_verdict": (
                "All analysts failed to retrieve data. "
                "No verdict can be produced without evidence."
            ),
            "verdict_confidence": "low",
            "recommendation": "insufficient evidence",
            "rejected_claims": [],
        }

    health_section = _format_health(
        health_report,
        health_error,
    )

    security_section = _format_security(
        security_report,
        security_error,
    )

    license_section = _format_license(
        license_report,
        license_error,
    )

    user_prompt = f"""HEALTH REPORT:
{health_section}

SECURITY REPORT:
{security_section}

LICENSE REPORT:
{license_section}

Produce the final reconciled verdict now.
"""

    try:
        verdict_text = call_llm(
            SYSTEM_PROMPT,
            user_prompt,
            max_tokens=900,
        )

    except LLMCallFailed as exc:

        fallback_rec = _fallback_recommendation(
            health_report,
            security_report,
            license_report,
        )

        return {
            "final_verdict": (
                f"LLM synthesis failed ({exc}). "
                "Falling back to raw signals."
            ),
            "verdict_confidence": "low",
            "recommendation": fallback_rec,
            "rejected_claims": [],
        }

    rejected_claims = _validate_cve_mentions(
        verdict_text,
        security_report,
    )

    recommendation = _extract_field(
        verdict_text,
        "RECOMMENDATION",
    )

    confidence = _extract_field(
        verdict_text,
        "CONFIDENCE",
    )

    cleaned_lines = []

    for line in verdict_text.splitlines():

        upper = line.strip().upper()

        if upper.startswith("RECOMMENDATION:"):
            continue

        if upper.startswith("CONFIDENCE:"):
            continue

        cleaned_lines.append(line)

    cleaned_verdict = "\n".join(
        cleaned_lines
    ).strip()

    return {
        "final_verdict": cleaned_verdict,
        "verdict_confidence": confidence or "low",
        "recommendation": recommendation or "insufficient evidence",
        "rejected_claims": rejected_claims,
    }


def _format_health(report, error):

    if error and not report:
        return f"[UNAVAILABLE] {error}"

    if not report:
        return "[UNAVAILABLE] No health report produced."

    return (
        f"Maintenance score: {report['maintenance_score']}\n"
        f"Assessment: {report['assessment']}"
    )


def _format_security(report, error):

    if error and not report:
        return f"[UNAVAILABLE] {error}"

    if not report:
        return "[UNAVAILABLE] No security report produced."

    return (
        f"Risk level: {report['risk_level']}\n"
        f"Assessment: {report['assessment']}"
    )


def _format_license(report, error):

    if error and not report:
        return f"[UNAVAILABLE] {error}"

    if not report:
        return "[UNAVAILABLE] No license report produced."

    return (
        f"License: {report['license_name']}\n"
        f"Compatibility: {report['compatibility']}\n"
        f"Assessment: {report['assessment']}"
    )


def _safe_get(report, key):
    return report.get(key, "unknown") if report else "unknown"


def _fallback_recommendation(
    health_report,
    security_report,
    license_report,
):

    risk = _safe_get(
        security_report,
        "risk_level",
    )

    compatibility = _safe_get(
        license_report,
        "compatibility",
    )

    if risk in ("critical", "high"):
        return "avoid"

    if compatibility == "restrictive":
        return "use with caution"

    if (
        risk in ("none", "low")
        and compatibility == "permissive"
        and _safe_get(
            health_report,
            "maintenance_score",
        ) == "healthy"
    ):
        return "safe to use"

    return "insufficient evidence"


def _validate_cve_mentions(
    verdict_text,
    security_report,
):
    import re

    mentioned_ids = set(
        re.findall(
            r"\b(?:CVE-\d{4}-\d+|GHSA-[\w-]+)\b",
            verdict_text,
        )
    )

    if not mentioned_ids:
        return []

    known_ids = set()

    if security_report:
        for v in security_report.get(
            "raw_signals",
            {},
        ).get(
            "vulnerabilities",
            [],
        ):
            known_ids.add(v["id"])
            known_ids.update(
                v.get("aliases", [])
            )

    rejected = [
        vid
        for vid in mentioned_ids
        if vid not in known_ids
    ]

    return [
        f"Unverified vulnerability ID mentioned in verdict: {vid}"
        for vid in rejected
    ]


def _extract_field(
    text,
    field_name,
):

    for line in text.splitlines():

        if line.strip().upper().startswith(
            field_name.upper() + ":"
        ):
            return (
                line.split(":", 1)[1]
                .strip()
                .lower()
            )

    return ""