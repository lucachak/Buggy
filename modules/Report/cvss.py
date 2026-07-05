from typing import TypedDict


class CVSSEntry(TypedDict):
    base_score: float
    severity:   str
    vector:     str
    description: str


# Mapeamento finding_type → CVSS v3.1
# Vector: AV:N = Network, AV:A = Adjacent, AV:L = Local
# AC:L = Low complexity, AC:H = High
# PR:N = No privs, PR:L = Low, PR:H = High
# UI:N = No user interaction, UI:R = Required
# S:U = Unchanged scope, S:C = Changed
# C:H/M/L/N = Confidentiality, I:H/M/L/N = Integrity, A:H/M/L/N = Availability
CVSS_MAP: dict[str, CVSSEntry] = {
    # ── Injection ─────────────────────────────────────────────────────────────
    "sqli":               {"base_score": 9.8, "severity": "CRITICAL",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                           "description": "SQL Injection — full DB compromise possible"},
    "sqli_blind":         {"base_score": 7.5, "severity": "HIGH",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                           "description": "Blind SQL Injection — data exfiltration via timing/boolean"},
    "command_injection":  {"base_score": 9.8, "severity": "CRITICAL",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                           "description": "OS Command Injection — RCE"},
    "ssti":               {"base_score": 9.8, "severity": "CRITICAL",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                           "description": "Server-Side Template Injection — RCE risk"},
    "xxe":                {"base_score": 8.6, "severity": "HIGH",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                           "description": "XML External Entity — file read / SSRF"},

    # ── XSS / Client ─────────────────────────────────────────────────────────
    "xss_reflected":      {"base_score": 6.1, "severity": "MEDIUM",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                           "description": "Reflected XSS"},
    "xss_stored":         {"base_score": 8.8, "severity": "HIGH",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N",
                           "description": "Stored XSS — persistent, targets all users"},
    "xss_dom":            {"base_score": 6.1, "severity": "MEDIUM",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                           "description": "DOM-based XSS"},
    "csrf":               {"base_score": 6.5, "severity": "MEDIUM",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                           "description": "Cross-Site Request Forgery"},
    "open_redirect":      {"base_score": 6.1, "severity": "MEDIUM",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                           "description": "Open Redirect — phishing / token theft"},

    # ── SSRF / Path Traversal ─────────────────────────────────────────────────
    "ssrf":               {"base_score": 8.6, "severity": "HIGH",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                           "description": "Server-Side Request Forgery — internal network access"},
    "ssrf_blind":         {"base_score": 5.8, "severity": "MEDIUM",
                           "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N",
                           "description": "Blind SSRF"},
    "path_traversal":     {"base_score": 7.5, "severity": "HIGH",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                           "description": "Path Traversal — arbitrary file read"},
    "lfi":                {"base_score": 7.5, "severity": "HIGH",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                           "description": "Local File Inclusion"},
    "rfi":                {"base_score": 9.8, "severity": "CRITICAL",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                           "description": "Remote File Inclusion — RCE"},

    # ── Auth / Access Control ─────────────────────────────────────────────────
    "idor":               {"base_score": 6.5, "severity": "MEDIUM",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                           "description": "Insecure Direct Object Reference"},
    "broken_auth":        {"base_score": 8.1, "severity": "HIGH",
                           "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                           "description": "Broken Authentication — account takeover"},
    "priv_escalation":    {"base_score": 8.8, "severity": "HIGH",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                           "description": "Privilege Escalation"},
    "weak_password":      {"base_score": 7.5, "severity": "HIGH",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                           "description": "Weak or default credentials"},
    "jwt_none_alg":       {"base_score": 9.1, "severity": "CRITICAL",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                           "description": "JWT 'none' algorithm accepted"},

    # ── Exposure / Misconfiguration ───────────────────────────────────────────
    "exposed_admin":      {"base_score": 5.3, "severity": "MEDIUM",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                           "description": "Admin panel exposed to internet"},
    "exposed_db":         {"base_score": 9.8, "severity": "CRITICAL",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                           "description": "Database port exposed to internet"},
    "js_secret":          {"base_score": 7.5, "severity": "HIGH",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                           "description": "API key / secret hardcoded in JavaScript"},
    "cors_misconfigured": {"base_score": 6.5, "severity": "MEDIUM",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                           "description": "Permissive CORS — cross-origin data theft"},
    "info_disclosure":    {"base_score": 5.3, "severity": "MEDIUM",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                           "description": "Information disclosure (stack traces, version banners)"},
    "robots_disallow":    {"base_score": 3.7, "severity": "LOW",
                           "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                           "description": "Sensitive path leaked in robots.txt"},

    # ── File Upload ───────────────────────────────────────────────────────────
    "unrestricted_upload":{"base_score": 9.8, "severity": "CRITICAL",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                           "description": "Unrestricted file upload — webshell upload / RCE"},

    # ── Default / Unknown ─────────────────────────────────────────────────────
    "unknown":            {"base_score": 0.0, "severity": "INFORMATIONAL",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                           "description": "Unclassified finding"},
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


def score(finding_type: str) -> CVSSEntry:
    """Return CVSS entry for a finding type. Falls back to 'unknown'."""
    return CVSS_MAP.get(finding_type.lower(), CVSS_MAP["unknown"])


def score_bulk(findings: list[dict]) -> list[dict]:
    """
    Add cvss_score, cvss_severity, and cvss_vector to each finding dict.
    Each dict must have a 'type' key matching CVSS_MAP.

    Returns the same list with cvss fields added, sorted by base_score desc.
    """
    for f in findings:
        entry = score(f.get("type", "unknown"))
        f["cvss_score"]    = entry["base_score"]
        f["cvss_severity"] = entry["severity"]
        f["cvss_vector"]   = entry["vector"]
        f["cvss_desc"]     = entry["description"]
    return sorted(findings, key=lambda x: x["cvss_score"], reverse=True)


def summarize_scores(findings: list[dict]) -> dict:
    """Return count by severity for a list of scored findings."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("cvss_severity", "INFORMATIONAL")
        counts[sev] = counts.get(sev, 0) + 1
    return counts