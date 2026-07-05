
import json
import os
from datetime import datetime
from typing import Any


def _load(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _set_of(data: dict, key: str) -> set:
    return set(data.get(key, []))


def compute_delta(current: dict, previous: dict) -> dict:
    """
    Compara dois discovery_summary dicts e retorna o delta.

    Returns:
        {
            "new_subdomains": [...],
            "removed_subdomains": [...],
            "new_live_ips": [...],
            "removed_live_ips": [...],
            "new_paths": [...],
            "removed_paths": [...],
            "new_origin_ips": [...],
            "has_changes": bool,
            "timestamp": "...",
        }
    """
    fields = [
        ("subdomains",       "new_subdomains",    "removed_subdomains"),
        ("live_ips",         "new_live_ips",       "removed_live_ips"),
        ("discovered_paths", "new_paths",          "removed_paths"),
        ("origin_ips",       "new_origin_ips",     "removed_origin_ips"),
    ]

    delta: dict[str, Any] = {"timestamp": datetime.now().isoformat()}
    has_changes = False

    for key, added_key, removed_key in fields:
        cur = _set_of(current, key)
        prev = _set_of(previous, key)
        added   = sorted(cur - prev)
        removed = sorted(prev - cur)
        delta[added_key]   = added
        delta[removed_key] = removed
        if added or removed:
            has_changes = True

    delta["has_changes"] = has_changes
    return delta


def load_and_diff(output_dir: str) -> dict:
    """
    Carrega current e previous snapshots do output_dir e retorna o delta.
    Espera:
        output_dir/recon/discovery_summary.json        — atual
        output_dir/recon/discovery_summary_prev.json   — anterior (rotacionado)
    """
    recon_dir = os.path.join(output_dir, "recon")
    current_path  = os.path.join(recon_dir, "discovery_summary.json")
    previous_path = os.path.join(recon_dir, "discovery_summary_prev.json")

    current  = _load(current_path)
    previous = _load(previous_path)

    return compute_delta(current, previous)


def rotate_snapshot(output_dir: str) -> None:
    """
    Move discovery_summary.json → discovery_summary_prev.json.
    Deve ser chamado ANTES do próximo scan no watch mode.
    """
    recon_dir = os.path.join(output_dir, "recon")
    current  = os.path.join(recon_dir, "discovery_summary.json")
    previous = os.path.join(recon_dir, "discovery_summary_prev.json")
    if os.path.exists(current):
        os.replace(current, previous)


def print_delta(delta: dict) -> None:
    """Imprime o delta formatado no terminal."""
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

    if not delta.get("has_changes"):
        print(f"{GREEN}  [=] No changes detected since last scan.{RESET}")
        return

    print(f"\n{BOLD}{YELLOW}  ⚡  Changes detected  [{delta.get('timestamp', '')}]{RESET}")

    sections = [
        ("new_subdomains",    "NEW subdomains",       GREEN),
        ("removed_subdomains","REMOVED subdomains",    RED),
        ("new_live_ips",      "NEW live IPs",          GREEN),
        ("removed_live_ips",  "REMOVED live IPs",      RED),
        ("new_paths",         "NEW paths",             GREEN),
        ("removed_paths",     "REMOVED paths",         RED),
        ("new_origin_ips",    "NEW origin IPs",        CYAN),
        ("removed_origin_ips","REMOVED origin IPs",    RED),
    ]

    for key, label, color in sections:
        items = delta.get(key, [])
        if items:
            print(f"\n{color}{BOLD}  ── {label} ({len(items)}) ──{RESET}")
            for item in items:
                print(f"    {color}{'+'if 'new' in key else '-'}{RESET} {item}")