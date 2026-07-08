"""
payloads.py — Infra Module
"""

SENSITIVE_FILES = [
    "/.env",
    "/.git/config",
    "/.svn/entries",
    "/server-status",
    "/phpinfo.php",
    "/WEB-INF/web.xml",
    "/.aws/credentials",
    "/.ssh/id_rsa",
    "/docker-compose.yml",
    "/config.php.bak",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
]
