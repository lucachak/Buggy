"""
report.py — Gerador de relatório HTML final.
Consolida recon + surface mapping + CVSS num arquivo navegável standalone.

Uso:
    from modules.Report.report import generate
    generate(output_dir="output/example.com_20260705_120000")
"""

import json
import os
import glob
import html as html_lib
from datetime import datetime
from pathlib import Path


# ── Loaders ───────────────────────────────────────────────────────────────────

def _load_json(path: str) -> dict | list:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def _latest_recon(output_dir: str) -> dict:
    pattern = os.path.join(output_dir, "reports", "*_recon_*.json")
    files   = sorted(glob.glob(pattern), reverse=True)
    if not files:
        # Try recon subdir
        pattern = os.path.join(output_dir, "recon", "*_recon_*.json")
        files   = sorted(glob.glob(pattern), reverse=True)
    return _load_json(files[0]) if files else {}


def _load_surface(output_dir: str) -> dict:
    return _load_json(os.path.join(output_dir, "surface", "surface_mapping.json"))


def _load_attack(output_dir: str) -> dict:
    return _load_json(os.path.join(output_dir, "surface", "attack_surface.json"))


def _load_intelligence(output_dir: str) -> dict:
    return _load_json(os.path.join(output_dir, "intelligence", "cves.json"))


def _load_validation(output_dir: str) -> dict:
    return _load_json(os.path.join(output_dir, "validation", "execution.json"))


ATTACK_FINDING_KEYS = (
    "infra_findings", "auth_findings", "business_findings",
    "injection_findings", "xss_findings", "ssrf_findings",
)


def _all_scored_findings(attack: dict) -> list[dict]:
    """Merge the surface list with findings appended by later modules."""
    merged = []
    seen = set()
    for item in list(attack.get("scored_findings", [])) + [
        finding
        for key in ATTACK_FINDING_KEYS
        for finding in attack.get(key, [])
        if isinstance(finding, dict)
    ]:
        marker = json.dumps(item, sort_keys=True, default=str)
        if marker not in seen:
            seen.add(marker)
            merged.append(item)
    return sorted(merged, key=lambda item: item.get("cvss_score", 0), reverse=True)


# ── HTML helpers ──────────────────────────────────────────────────────────────

class _RawHtml(str):
    """HTML fragment produced internally, never from scan data."""


def _escaped(value) -> str:
    return value if isinstance(value, _RawHtml) else html_lib.escape(str(value), quote=True)

def _severity_badge(sev: str) -> str:
    colors = {
        "CRITICAL": "#c0392b", "HIGH": "#e67e22",
        "MEDIUM": "#f1c40f",   "LOW": "#27ae60",
        "INFORMATIONAL": "#7f8c8d",
    }
    color = colors.get(str(sev).upper(), "#7f8c8d")
    return _RawHtml(
        f'<span style="background:{color};color:#fff;padding:2px 8px;'
        f'border-radius:4px;font-size:12px;font-weight:600">{_escaped(sev)}</span>'
    )


def _section(title: str, content: str) -> str:
    return f"""
    <section>
      <h2>{_escaped(title)}</h2>
      {content}
    </section>
    """


def _table(headers: list[str], rows: list[list]) -> str:
    th   = "".join(f"<th>{_escaped(h)}</th>" for h in headers)
    body = ""
    for row in rows:
        td    = "".join(f"<td>{_escaped(cell)}</td>" for cell in row)
        body += f"<tr>{td}</tr>"
    return f"<table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>"


def _list_items(items: list, limit: int = 100) -> str:
    shown = items[:limit]
    extra = len(items) - len(shown)
    html  = "<ul>" + "".join(f"<li><code>{_escaped(i)}</code></li>" for i in shown) + "</ul>"
    if extra > 0:
        html += f"<p style='color:#666'>… and {extra} more</p>"
    return html


# ── Report generator ──────────────────────────────────────────────────────────

def generate(output_dir: str) -> str:
    """
    Gera relatório HTML e salva em output_dir/reports/report.html.
    Retorna o path absoluto do arquivo gerado.
    """
    recon   = _latest_recon(output_dir)
    surface = _load_surface(output_dir)
    attack  = _load_attack(output_dir)
    intelligence = _load_intelligence(output_dir)
    validation = _load_validation(output_dir)

    recon_results   = recon.get("results", {})
    surface_summary = surface.get("summary", {})
    attack_surface  = surface_summary.get("attack_surface", {})
    cvss_summary    = attack.get("cvss_summary", {})
    scored          = _all_scored_findings(attack)
    tech            = surface_summary.get("technologies", {})
    risk            = surface_summary.get("risk_indicators", {})
    high_value      = surface_summary.get("high_value_targets", {})
    cves = intelligence.get("cves", [])
    validation_results = validation.get("results", [])

    target    = recon.get("meta", {}).get("target", output_dir)
    domain    = recon.get("meta", {}).get("domain", target)
    timestamp = recon.get("meta", {}).get("timestamp", "")
    now       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Seção: Executive Summary ──────────────────────────────────────────────
    risk_rows = [
        ["WAF presente",      "✅ Sim" if risk.get("waf_present") else "❌ Não"],
        ["Rota admin observada", "⚠️ Sim" if risk.get("exposed_admin") else "✅ Não"],
        ["DB exposto",        "🔴 Sim" if risk.get("exposed_databases") else "✅ Não"],
        ["JS secrets leaked", "🔴 Sim" if risk.get("js_secrets_leaked") else "✅ Não"],
    ]

    if scored:
        cvss_summary = {
            severity: sum(
                1 for finding in scored
                if str(finding.get("cvss_severity", "")).upper() == severity
            )
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        }
    cvss_html = ""
    if cvss_summary:
        cvss_html = _table(
            ["Severity", "Count"],
            [[_severity_badge(k), v] for k, v in cvss_summary.items() if v > 0]
        )

    exec_summary = _table(["Indicador", "Status"], risk_rows) + cvss_html

    # ── Seção: Recon ──────────────────────────────────────────────────────────
    subdomains = recon_results.get("subdomains", [])
    live_ips   = recon_results.get("live_ips", [])
    paths      = recon_results.get("discovered_paths", [])

    recon_html = _table(
        ["Tipo", "Quantidade"],
        [
            ["Subdomínios", len(subdomains)],
            ["Live IPs",    len(live_ips)],
            ["Paths found", len(paths)],
        ]
    )
    if subdomains:
        recon_html += "<h3>Subdomains</h3>" + _list_items(subdomains, 50)
    if live_ips:
        recon_html += "<h3>Live IPs</h3>" + _list_items(live_ips, 30)

    # ── Seção: Surface ────────────────────────────────────────────────────────
    surface_html = _table(
        ["Tipo", "Quantidade"],
        [
            ["Endpoints",  attack_surface.get("total_endpoints", 0)],
            ["Formulários", attack_surface.get("total_forms", 0)],
            ["APIs",        attack_surface.get("total_apis", 0)],
            ["JS secrets",  attack_surface.get("js_secrets_found", 0)],
            ["Open ports",  attack_surface.get("open_ports_count", 0)],
        ]
    )

    cms_list = tech.get("cms", [])
    fw_list  = tech.get("frameworks", [])
    if cms_list or fw_list:
        surface_html += _table(
            ["Tech", "Tipo"],
            [[t, "CMS"] for t in cms_list] + [[t, "Framework"] for t in fw_list]
        )

    admin_panels = high_value.get("admin_panels", [])
    if admin_panels:
        surface_html += "<h3>Admin panels expostos</h3>" + _list_items(admin_panels)

    exposed_dbs = high_value.get("exposed_dbs", [])
    if exposed_dbs:
        surface_html += (
            "<h3 style='color:#c0392b'>⚠️ Databases expostos</h3>"
            + _list_items(exposed_dbs)
        )

    observations = surface.get("endpoints", {}).get("interesting", [])
    if observations:
        surface_html += "<h3>Observações de superfície</h3>" + _table(
            ["Severidade", "Tipo", "Alvo", "Descrição"],
            [[item.get("severity", "info"), item.get("type", "observation"),
              item.get("url", item.get("contact", "—")), item.get("description", "—")]
             for item in observations[:100]],
        )

    # Coverage is evidence about what was actually testable. Zero findings with
    # zero inputs must never be presented as a clean security result.
    js_files = surface.get("js_secrets", {}).get("summary", {}).get("total_files", 0)
    forms_count = attack_surface.get("total_forms", 0)
    api_count = attack_surface.get("total_apis", 0)
    login_count = len(attack.get("injection_targets", {}).get("login_pages", []))
    search_count = len(attack.get("injection_targets", {}).get("search_endpoints", []))
    dynamic_inputs = forms_count + api_count + login_count + search_count
    coverage_rows = [
        ["JavaScript", js_files, "analisado" if js_files else "sem bundles válidos"],
        ["Formulários", forms_count, "mapeados" if forms_count else "sem entradas para testar"],
        ["APIs", api_count, "mapeadas" if api_count else "sem entradas para testar"],
        ["Alvos dinâmicos", dynamic_inputs,
         "disponíveis" if dynamic_inputs else "módulos ativos ficaram sem tarefas"],
    ]
    coverage_html = _table(["Área", "Quantidade", "Cobertura"], coverage_rows)
    if dynamic_inputs == 0:
        coverage_html += (
            '<p style="color:#f1c40f"><strong>Resultado inconclusivo:</strong> '
            "nenhuma vulnerabilidade foi confirmada, mas os módulos dinâmicos "
            "não receberam alvos suficientes.</p>"
        )

    # ── Seção: Findings (CVSS sorted) ────────────────────────────────────────
    if scored:
        rows = [
            [
                _severity_badge(f.get("cvss_severity", "?")),
                f.get("cvss_score", "—"),
                f.get("type", "—"),
                f.get("url") or f.get("host") or "—",
                f.get("cvss_desc", "—"),
            ]
            for f in scored
        ]
        findings_html = _table(
            ["Severity", "Score", "Type", "Target", "Description"], rows
        )
    else:
        findings_html = "<p>Nenhuma vulnerabilidade confirmada nesta execução.</p>"
        if dynamic_inputs == 0:
            findings_html += (
                "<p>Este resultado não comprova ausência de vulnerabilidades: "
                "os módulos dinâmicos executaram sem formulários, APIs ou parâmetros.</p>"
            )

    if cves:
        cve_html = _table(
            ["Priority", "Score", "CVE", "Component", "CVSS", "EPSS", "KEV"],
            [[c.get("priority", "LOW"), c.get("priority_score", 0), c.get("cve_id", ""),
              f"{c.get('component', {}).get('product', '')} {c.get('component', {}).get('version', '')}",
              c.get("cvss_score", 0), c.get("epss", 0), "yes" if c.get("kev") else "no"]
             for c in cves[:100]],
        )
    else:
        cve_html = "<p>Nenhuma CVE correlacionada com versões confirmadas no inventário.</p>"

    if validation_results:
        validation_html = _table(
            ["CVE", "Validator", "Execução", "Aplicabilidade", "Confirmado", "Resumo"],
            [[item.get("result", {}).get("cve_id", item.get("cve_id", "—")),
              item.get("validator_id", "—"), item.get("status", "—"),
              item.get("result", {}).get("applicability", "—"),
              "sim" if item.get("result", {}).get("confirmed") else "não",
              item.get("result", {}).get("summary", item.get("reason", item.get("error", "—")))]
             for item in validation_results[:100]],
        )
    else:
        validation_html = "<p>Nenhuma validação de CVE executada.</p>"

    # ── HTML final ────────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Buggy Report — {_escaped(domain)}</title>
  <style>
    body   {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
              max-width: 1100px; margin: 0 auto; padding: 2rem;
              background: #0d1117; color: #c9d1d9; }}
    h1     {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: .5rem; }}
    h2     {{ color: #79c0ff; margin-top: 2rem; }}
    h3     {{ color: #d2a8ff; }}
    section {{ background: #161b22; border: 1px solid #30363d;
               border-radius: 8px; padding: 1.5rem; margin: 1.5rem 0; }}
    table  {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #21262d; }}
    th     {{ background: #21262d; color: #8b949e; font-weight: 600; }}
    tr:hover {{ background: #1f2937; }}
    code   {{ background: #1c2128; padding: 1px 6px; border-radius: 4px;
               font-size: 12px; color: #a5d6ff; }}
    ul     {{ padding-left: 1.2rem; line-height: 1.8; }}
    .meta  {{ color: #8b949e; font-size: 13px; margin-top: -.5rem; margin-bottom: 1.5rem; }}
    footer {{ color: #8b949e; font-size: 12px; margin-top: 3rem; text-align: center; }}
  </style>
</head>
<body>
  <h1>🐛 Buggy Report</h1>
  <p class="meta">Target: <code>{_escaped(target)}</code> &nbsp;|&nbsp;
     Scan: <code>{_escaped(timestamp)}</code> &nbsp;|&nbsp;
     Generated: <code>{_escaped(now)}</code></p>

  {_section("Executive Summary", exec_summary)}
  {_section("Reconnaissance", recon_html)}
  {_section("Attack Surface", surface_html)}
  {_section("Cobertura e limitações", coverage_html)}
  {_section("CVE Intelligence", cve_html)}
  {_section("CVE Validation", validation_html)}
  {_section("Findings (CVSS sorted)", findings_html)}

  <footer>Generated by Buggy — bug bounty / ethical hacking only</footer>
</body>
</html>"""

    out_dir  = os.path.join(output_dir, "reports")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "report.html")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n\033[92m  📊  Report gerado:\033[0m  {out_path}")
    return out_path
