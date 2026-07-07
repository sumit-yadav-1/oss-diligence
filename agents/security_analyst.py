from tools.osv_client import OSVClientError, fetch_vulnerabilities
from utils.llm import LLMCallFailed, call_llm
from utils.state import DiligenceState

SYSTEM_PROMPT = """You are a Security Analyst agent auditing open-source dependency vulnerabilities.

You will be given RAW, VERIFIED vulnerability records retrieved from the OSV.dev database.
Your job is to write a short, grounded risk assessment.

STRICT RULES:
- Only cite vulnerabilities that are actually present in the data given to you, using their real IDs.
- Do not invent CVE IDs, severities, or fix statuses.
- If there are zero vulnerabilities, say so plainly — do not imply risk that isn't there.
- End your response with a single line:
"RISK: none" if no vulnerabilities exist.
"RISK: low" if vulnerabilities exist but all have fixes available.
"RISK: moderate/high/critical" based on the highest-severity unfixed vulnerability.
"""


def security_analyst_node(state: DiligenceState) -> dict:
    package_name = state["package_name"]
    ecosystem = state.get("ecosystem", "PyPI")
    version = state.get("version")

    try:
        raw_signals = fetch_vulnerabilities(package_name, ecosystem, version)
    except OSVClientError as exc:
        return {
            "security_error": f"Could not retrieve OSV data for '{package_name}': {exc}",
            "security_report": None,
        }

    vulns = raw_signals["vulnerabilities"]
    vuln_lines = (
        "\n".join(
            f"- {v['id']} | severity={v['severity']} | fixed_available={v['fixed']} | {v['summary']}"
            for v in vulns
        )
        if vulns
        else "No vulnerabilities found in OSV.dev for this package/version."
    )

    user_prompt = f"""Package: {raw_signals['package_name']} ({raw_signals['ecosystem']})
Version checked: {raw_signals['version_checked'] or 'all versions'}
Total vulnerabilities found: {raw_signals['vulnerability_count']}

Raw vulnerability records:
{vuln_lines}

Write your grounded security risk assessment now."""

    try:
        assessment = call_llm(SYSTEM_PROMPT, user_prompt, max_tokens=500)
    except LLMCallFailed as exc:
        return {
            "security_error": f"LLM assessment failed for '{package_name}': {exc}",
            "security_report": {
                "package_name": raw_signals["package_name"],
                "ecosystem": raw_signals["ecosystem"],
                "raw_signals": raw_signals,
                "assessment": "LLM assessment unavailable — raw signals only.",
                "risk_level": "unknown",
            },
        }

    risk_level = _calculate_risk_level(raw_signals)

    return {
        "security_report": {
            "package_name": raw_signals["package_name"],
            "ecosystem": raw_signals["ecosystem"],
            "raw_signals": raw_signals,
            "assessment": assessment,
            "risk_level": risk_level,
        },
        "security_error": None,
    }


def _calculate_risk_level(raw_signals) -> str:
    vulns = raw_signals["vulnerabilities"]

    if not vulns:
        return "none"

    unfixed = [v for v in vulns if not v["fixed"]]

    if not unfixed:
        return "low"

    severity_text = " ".join(
        str(v["severity"]).upper()
        for v in unfixed
    )

    if "CRITICAL" in severity_text:
        return "critical"

    if "HIGH" in severity_text:
        return "high"

    if "MODERATE" in severity_text:
        return "moderate"

    return "low"