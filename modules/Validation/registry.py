from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

RISK_LEVELS = ("safe", "standard", "intrusive", "lab-exploit")
HTTP_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass(frozen=True)
class ValidatorSpec:
    validator_id: str
    name: str
    cves: tuple[str, ...]
    risk: str
    description: str
    executor: str = "python"
    implementation: str = ""
    methods: tuple[str, ...] = ("GET",)
    timeout: float = 10.0
    reversible: bool = True
    requires_auth: bool = False
    enabled: bool = True
    source: str = "builtin"

    def validate(self) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,80}", self.validator_id):
            raise ValueError(f"invalid validator id: {self.validator_id!r}")
        if self.risk not in RISK_LEVELS:
            raise ValueError(f"invalid risk level: {self.risk!r}")
        if not self.cves or any(not CVE_RE.fullmatch(cve) for cve in self.cves):
            raise ValueError("validators require valid CVE identifiers")
        if not self.methods or any(method.upper() not in HTTP_METHODS for method in self.methods):
            raise ValueError("invalid or empty HTTP method set")
        if self.timeout <= 0 or self.timeout > 300:
            raise ValueError("validator timeout must be between 0 and 300 seconds")
        if self.executor not in {"python", "nuclei"}:
            raise ValueError(f"unsupported executor: {self.executor}")
        if self.executor == "python" and not self.implementation.startswith("modules.Validators."):
            raise ValueError("python validators must live under modules.Validators")

    def to_dict(self) -> dict:
        data = asdict(self)
        data["cves"], data["methods"] = list(self.cves), list(self.methods)
        return data


class ValidatorRegistry:
    def __init__(self):
        self._specs: dict[str, ValidatorSpec] = {}

    def register(self, spec: ValidatorSpec) -> None:
        spec.validate()
        if spec.validator_id in self._specs:
            raise ValueError(f"duplicate validator id: {spec.validator_id}")
        self._specs[spec.validator_id] = spec

    def all(self, *, enabled_only: bool = True) -> list[ValidatorSpec]:
        values = self._specs.values()
        return sorted((s for s in values if s.enabled or not enabled_only),
                      key=lambda s: s.validator_id)

    def for_cve(self, cve_id: str) -> list[ValidatorSpec]:
        return [spec for spec in self.all() if cve_id in spec.cves]

    def snapshot(self) -> dict:
        validators = [spec.to_dict() for spec in self.all(enabled_only=False)]
        canonical = json.dumps(validators, sort_keys=True, separators=(",", ":"))
        return {
            "schema_version": 1,
            "digest": hashlib.sha256(canonical.encode()).hexdigest(),
            "validators": validators,
        }


def builtin_registry() -> ValidatorRegistry:
    """Return validators reviewed as bounded and non-destructive."""
    registry = ValidatorRegistry()
    registry.register(ValidatorSpec(
        validator_id="apache.path-traversal-applicability",
        name="Apache HTTP path traversal applicability",
        cves=("CVE-2021-41773", "CVE-2021-42013"),
        risk="safe",
        description=("Checks the exposed Apache version only; it never sends a "
                     "path-traversal or command-execution payload."),
        implementation="modules.Validators.apache.validate_path_traversal",
        methods=("GET",), timeout=8.0,
    ))
    registry.register(ValidatorSpec(
        validator_id="tomcat.put-applicability",
        name="Tomcat PUT applicability",
        cves=("CVE-2017-12615",),
        risk="safe",
        description=("Checks the exposed Tomcat version and OPTIONS capabilities; "
                     "it never uploads or writes a file."),
        implementation="modules.Validators.tomcat.validate_put",
        methods=("GET", "OPTIONS"), timeout=8.0,
    ))
    return registry
