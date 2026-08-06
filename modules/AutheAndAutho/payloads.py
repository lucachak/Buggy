"""
payloads.py — AutheAndAutho Module
"""

# ── IDOR ──────────────────────────────────────────────────────────────────────

IDOR_PARAMS = [
    "id",
    "user",
    "user_id",
    "account",
    "account_id",
    "profile",
    "profile_id",
    "uid",
    "uuid",
    "customer_id",
    "doc_id",
    "order_id",
]

# Valor para testar substituição em IDORs (se vermos id=1, testamos id=IDOR_TEST_VALUE)
IDOR_TEST_VALUE = "999999"

# Array bypass (e.g. ?id[]=1&id[]=999999)
IDOR_ARRAY_BYPASS_VALUE = "999999"

RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "retry-after",
]

# ── SSO / OAuth / SAML ───────────────────────────────────────────────────────

SSO_ENDPOINTS = [
    # OAuth / OIDC
    "/oauth/authorize",
    "/oauth2/authorize",
    "/oauth/token",
    "/oauth2/token",
    "/oauth/callback",
    "/oauth2/callback",
    "/oauth/login",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    # SAML
    "/saml/login",
    "/saml/sso",
    "/saml/acs",
    "/saml/metadata",
    "/saml2/login",
    "/saml2/sso",
    "/saml2/acs",
    "/adfs/ls",
    # Keycloak
    "/auth/realms/master/protocol/openid-connect/auth",
    "/auth/realms/master/protocol/openid-connect/token",
    "/auth/realms/master/.well-known/openid-configuration",
    # SSO genérico
    "/sso/login",
    "/sso/callback",
    "/sso/logout",
    "/login/sso",
    "/auth/sso",
    "/cas/login",
    "/cas/serviceValidate",
    # Microsoft / Azure AD
    "/common/oauth2/v2.0/authorize",
    "/common/oauth2/v2.0/token",
    "/.auth/login/aad",
    # Google
    "/o/oauth2/v2/auth",
    # Misc
    "/api/auth/signin",
    "/api/auth/callback",
    "/connect/authorize",
    "/connect/token",
    "/Account/ExternalLogin",
]

SSO_PARAMS = [
    "redirect_uri",
    "redirect_url",
    "RelayState",
    "return_to",
    "returnTo",
    "return_url",
    "returnUrl",
    "next",
    "callback",
    "callback_url",
    "post_logout_redirect_uri",
    "target",
    "destination",
    "redir",
    "continue",
    "service",                  # CAS
    "TARGET",                   # SAML / SiteMinder
]

SSO_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "https://evil.com/callback",
    "//evil.com",
    "https://evil.com@{domain}",        # {domain} substituído em runtime
    "https://{domain}.evil.com",
    "https://{domain}@evil.com",
    "/\\evil.com",
    "/.evil.com",
    "https://evil.com#@{domain}",
    "https://evil.com%23@{domain}",
    "https://evil.com%2F%2F{domain}",
    "https://{domain}%40evil.com",
]

SSO_TOKEN_PATTERNS = [
    r"access_token=([^&\s]{10,})",
    r"id_token=([^&\s]{10,})",
    r"token=([^&\s]{10,})",
    r"code=([^&\s]{6,})",
    r"SAMLResponse=([^&\s]{10,})",
    r"SAMLart=([^&\s]{10,})",
    r"jwt=([^&\s]{10,})",
    r"session_state=([^&\s]{10,})",
]

IDP_HINT_PARAMS = [
    "idp_hint",
    "kc_idp_hint",
    "idp",
    "identity_provider",
    "acr_values",
]

IDP_HINT_VALUES = [
    "google",
    "facebook",
    "github",
    "microsoft",
    "apple",
    "okta",
    "azure",
    "saml",
    "ldap",
    "internal",
    "corporate",
    "ad",
    "active-directory",
]
