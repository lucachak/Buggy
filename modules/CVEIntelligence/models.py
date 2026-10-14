from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class SoftwareComponent:
    vendor: str
    product: str
    version: str = ""
    cpe: str = ""
    source: str = "surface"
    evidence: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CVECandidate:
    cve_id: str
    component: SoftwareComponent
    description: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    epss: float = 0.0
    epss_percentile: float = 0.0
    kev: bool = False
    kev_due_date: str = ""
    known_ransomware_use: str = "Unknown"
    applicability: str = "possible"
    references: list[str] = field(default_factory=list)
    priority_score: float = 0.0
    priority: str = "LOW"
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["component"] = self.component.to_dict()
        return data
