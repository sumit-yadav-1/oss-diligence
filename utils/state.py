from typing import Optional, TypedDict


class HealthReport(TypedDict, total=False):
    repo_slug: str
    raw_signals: dict
    assessment: str
    maintenance_score: str


class SecurityReport(TypedDict, total=False):
    package_name: str
    ecosystem: str
    raw_signals: dict
    assessment: str
    risk_level: str

class LicenseReport(TypedDict, total=False):
    license_name: str
    compatibility: str
    assessment: str

class DiligenceState(TypedDict, total=False):
    repo_slug: str
    package_name: str
    ecosystem: str
    version: Optional[str]

    health_report: Optional[HealthReport]
    health_error: Optional[str]
    health_retry_count: int

    security_report: Optional[SecurityReport]
    security_error: Optional[str]
    security_retry_count: int

    license_report: Optional[LicenseReport]
    license_error: Optional[str]
    license_retry_count: int

    final_verdict: Optional[str]
    verdict_confidence: Optional[str]
    rejected_claims: list
    recommendation: Optional[str]