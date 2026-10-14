from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path


def _canonical(record: dict) -> bytes:
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()


def _key(validation_dir: Path) -> bytes:
    path = validation_dir / ".approval-key"
    if not path.exists():
        path.write_bytes(secrets.token_bytes(32))
        os.chmod(path, 0o600)
    return path.read_bytes()


def approve_plan(output_dir: str, item_ids: list[str], approved_by: str,
                 ttl: int = 3600) -> dict:
    validation_dir = Path(output_dir) / "validation"
    plan_path = validation_dir / "plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    known = {item["item_id"] for item in plan.get("items", [])}
    selected = sorted(set(item_ids))
    unknown = set(selected) - known
    if unknown:
        raise ValueError(f"unknown plan item(s): {', '.join(sorted(unknown))}")
    if not selected:
        raise ValueError("at least one --approve-item is required")
    if not approved_by.strip():
        raise ValueError("approved_by is required")
    now = int(time.time())
    record = {
        "schema_version": 1, "plan_id": plan["plan_id"],
        "registry_digest": plan["registry_digest"], "item_ids": selected,
        "approved_by": approved_by.strip(), "approved_at": now,
        "expires_at": now + max(60, min(int(ttl), 86400)),
    }
    record["signature"] = hmac.new(_key(validation_dir), _canonical(record), hashlib.sha256).hexdigest()
    (validation_dir / "approval.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    os.chmod(validation_dir / "approval.json", 0o600)
    return record


def verify_approval(output_dir: str, plan: dict) -> dict | None:
    validation_dir = Path(output_dir) / "validation"
    path = validation_dir / "approval.json"
    if not path.exists():
        return None
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
        expected = hmac.new(_key(validation_dir), _canonical(record), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, record.get("signature", "")):
            return None
        if record.get("plan_id") != plan.get("plan_id"):
            return None
        if record.get("registry_digest") != plan.get("registry_digest"):
            return None
        if int(record.get("expires_at", 0)) < int(time.time()):
            return None
        return record
    except (OSError, ValueError, KeyError, TypeError):
        return None
