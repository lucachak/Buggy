from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from modules.utils.http_client import validate_scoped_url


@dataclass(frozen=True)
class NucleiTemplate:
    template_id: str
    path: str
    sha256: str
    cves: tuple[str, ...]
    risk: str = "safe"
    signed_required: bool = True


class NucleiAdapter:
    def __init__(self, target: str, output_dir: str, template_root: str,
                 manifest_path: str, *, binary: str = "nuclei",
                 rate: float = 10.0, threads: int = 10, timeout: float = 10.0):
        validate_scoped_url(target)
        self.target = target
        self.output_dir = Path(output_dir)
        self.template_root = Path(template_root).resolve()
        self.manifest_path = Path(manifest_path)
        self.binary = shutil.which(binary) or ""
        self.rate = max(1, int(rate))
        self.threads = max(1, min(int(threads), 25))
        self.timeout = max(1, min(int(timeout), 60))
        self.nuclei_dir = self.output_dir / "validation" / "nuclei"
        self.nuclei_dir.mkdir(parents=True, exist_ok=True)

    def load_templates(self) -> list[Path]:
        if not self.manifest_path.is_file() or not self.template_root.is_dir():
            return []
        data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        templates = []
        for item in data.get("templates", []):
            spec = NucleiTemplate(
                template_id=item["template_id"], path=item["path"],
                sha256=item["sha256"].lower(), cves=tuple(item.get("cves", [])),
                risk=item.get("risk", "safe"),
                signed_required=item.get("signed_required", True),
            )
            path = (self.template_root / spec.path).resolve()
            if self.template_root not in path.parents or not path.is_file():
                raise ValueError(f"template path escapes trusted root: {spec.path}")
            content = path.read_bytes()
            if hashlib.sha256(content).hexdigest() != spec.sha256:
                raise ValueError(f"template checksum mismatch: {spec.template_id}")
            text = content.decode("utf-8", errors="replace").lower()
            forbidden = ("\ncode:", "\nheadless:", "\njavascript:", "\nfile:")
            if any(token in "\n" + text for token in forbidden):
                raise ValueError(f"unsafe protocol in template: {spec.template_id}")
            if spec.signed_required and "# digest:" not in text:
                raise ValueError(f"signed template required: {spec.template_id}")
            if spec.risk not in {"safe", "standard"}:
                raise ValueError(f"Nuclei risk not allowed by adapter: {spec.risk}")
            templates.append(path)
        return templates

    def build_command(self, templates: list[Path], output_file: Path) -> list[str]:
        if not self.binary:
            raise FileNotFoundError("nuclei binary not found")
        command = [
            self.binary, "-u", self.target, "-j", "-silent", "-nc",
            "-dut", "-ept", "code,headless,javascript,file", "-dr",
            "-duc", "-or", "-ot", "-rl", str(self.rate),
            "-c", str(self.threads), "-timeout", str(self.timeout),
            "-o", str(output_file),
        ]
        for template in templates:
            command.extend(["-t", str(template)])
        return command

    def _import_jsonl(self, path: Path) -> list[dict]:
        findings = []
        if not path.exists():
            return findings
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            matched = item.get("matched-at") or item.get("host") or self.target
            parsed = urllib.parse.urlparse(matched if "://" in matched else "//" + matched)
            target_host = urllib.parse.urlparse(self.target).hostname
            if parsed.hostname and parsed.hostname != target_host:
                continue
            info = item.get("info", {})
            findings.append({
                "type": "nuclei_cve", "template_id": item.get("template-id", ""),
                "url": matched, "name": info.get("name", ""),
                "severity": info.get("severity", "unknown"),
                "matcher": item.get("matcher-name", ""),
                "timestamp": item.get("timestamp", ""),
            })
        return findings

    def exec(self) -> dict:
        templates = self.load_templates()
        raw = self.nuclei_dir / "results.jsonl"
        result = {"status": "skipped", "reason": "no trusted templates",
                  "templates": len(templates), "findings": []}
        if templates and not self.binary:
            result["reason"] = "nuclei binary not found"
        elif templates:
            command = self.build_command(templates, raw)
            completed = subprocess.run(
                command, capture_output=True, text=True,
                timeout=max(30, self.timeout * len(templates) + 15),
                env={k: v for k, v in os.environ.items()
                     if k in {"PATH", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR"}},
            )
            result = {
                "status": "completed" if completed.returncode == 0 else "failed",
                "returncode": completed.returncode,
                "templates": len(templates),
                "stderr": completed.stderr[-2000:],
                "findings": self._import_jsonl(raw),
            }
        (self.nuclei_dir / "findings.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result
