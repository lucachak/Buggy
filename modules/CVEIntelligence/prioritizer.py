from __future__ import annotations

from .models import CVECandidate


def prioritize(candidate: CVECandidate, exposure: float = 1.0) -> CVECandidate:
    """Combine impact and exploitation signals into a transparent 0–100 score."""
    exposure = max(0.0, min(float(exposure), 1.0))
    cvss_points = min(max(candidate.cvss_score, 0.0), 10.0) * 2.5
    epss_points = max(0.0, min(candidate.epss, 1.0)) * 25.0
    kev_points = 40.0 if candidate.kev else 0.0
    exposure_points = exposure * 10.0
    score = round(min(cvss_points + epss_points + kev_points + exposure_points, 100), 1)

    candidate.priority_score = score
    candidate.priority = (
        "CRITICAL" if score >= 80 else
        "HIGH" if score >= 60 else
        "MEDIUM" if score >= 35 else "LOW"
    )
    reasons = [f"CVSS {candidate.cvss_score:.1f}", f"EPSS {candidate.epss:.3f}"]
    if candidate.kev:
        reasons.append("CISA KEV")
    if exposure >= 0.75:
        reasons.append("internet-facing")
    candidate.reasons = reasons
    return candidate
