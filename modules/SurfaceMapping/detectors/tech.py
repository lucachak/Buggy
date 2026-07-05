"""
tech.py — Detecta tecnologias, WAF, CMS e frameworks via HTTP.
Substitui o binário Go tech_detector.
"""

import re
import ssl
import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from typing import Dict, List

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; Buggy/1.0)"}

# Fingerprints simples: header/cookie/body → tech
SIGNATURES = {
    "waf": [
        (r"x-sucuri-id",                    "header", "Sucuri"),
        (r"x-fw-protect",                   "header", "Fortinet"),
        (r"cf-ray",                          "header", "Cloudflare"),
        (r"x-cache.*cloudfront",            "header", "AWS CloudFront"),
        (r"server.*akamai",                 "header", "Akamai"),
        (r"x-protected-by.*sqreen",         "header", "Sqreen"),
        (r"__utmz",                          "cookie", "Google Analytics WAF"),
    ],
    "cms": [
        (r"wp-content|wp-includes",         "body",   "WordPress"),
        (r"joomla",                          "body",   "Joomla"),
        (r"drupal",                          "body",   "Drupal"),
        (r"x-generator.*drupal",            "header", "Drupal"),
        (r"x-powered-by.*next\.js",         "header", "Next.js"),
        (r"__next",                          "body",   "Next.js"),
        (r"laravel_session",                 "cookie", "Laravel"),
        (r"csrftoken",                       "cookie", "Django"),
        (r"rails",                           "cookie", "Ruby on Rails"),
    ],
    "framework": [
        (r"x-powered-by.*express",          "header", "Express.js"),
        (r"x-powered-by.*php",              "header", "PHP"),
        (r"x-powered-by.*asp\.net",         "header", "ASP.NET"),
        (r"server.*nginx",                   "header", "Nginx"),
        (r"server.*apache",                  "header", "Apache"),
        (r"server.*tomcat",                  "header", "Tomcat"),
        (r"server.*gunicorn",                "header", "Gunicorn/Django"),
        (r"x-powered-by.*spring",           "header", "Spring Boot"),
    ],
}

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


def _fetch(url: str, timeout: int = 8) -> dict | None:
    try:
        req = Request(url, headers=HEADERS)
        resp = urlopen(req, timeout=timeout, context=SSL_CTX)
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        body    = resp.read(256 * 1024).decode("utf-8", errors="ignore").lower()
        cookies = headers.get("set-cookie", "").lower()
        return {"headers": headers, "body": body, "cookies": cookies,
                "status": resp.status, "url": url}
    except HTTPError as e:
        headers = {k.lower(): v.lower() for k, v in e.headers.items()} if e.headers else {}
        return {"headers": headers, "body": "", "cookies": "", "status": e.code, "url": url}
    except Exception:
        return None


def _match(data: dict, sigs: list) -> list[str]:
    found = []
    for pattern, source, name in sigs:
        text = data.get(source, "") or ""
        if re.search(pattern, text, re.I) and name not in found:
            found.append(name)
    return found


def detect(urls: list[str], threads: int = 10, timeout: float = 8.0) -> dict:
    """
    Detecta tecnologias em até `threads` URLs em paralelo.
    Retorna dict compatível com o formato que surface.py espera.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results_per_url = []

    with ThreadPoolExecutor(max_workers=min(threads, len(urls) or 1, 20)) as ex:
        futures = {ex.submit(_fetch, url, int(timeout)): url for url in urls[:20]}
        for fut in as_completed(futures):
            data = fut.result()
            if not data:
                continue
            entry = {"url": data["url"], "status": data["status"],
                     "waf": [], "cms": [], "framework": []}
            for cat, sigs in SIGNATURES.items():
                entry[cat] = _match(data, sigs)
            results_per_url.append(entry)

    # Agrega
    all_waf        = list({w for r in results_per_url for w in r["waf"]})
    all_cms        = list({c for r in results_per_url for c in r["cms"]})
    all_frameworks = list({f for r in results_per_url for f in r["framework"]})
    all_servers    = list({
        r["framework"][0] for r in results_per_url
        if r["framework"] and any(s in r["framework"][0].lower()
                                   for s in ["nginx", "apache", "tomcat", "gunicorn"])
    })

    return {
        "results": results_per_url,
        "summary": {
            "waf_detected":    bool(all_waf),
            "waf_type":        all_waf[0] if all_waf else None,
            "all_waf":         all_waf,
            "all_cms":         all_cms,
            "all_frameworks":  all_frameworks,
            "all_servers":     all_servers,
            "total_urls":      len(results_per_url),
        },
    }
