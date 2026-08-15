from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class CvePrerequisites:
    network_access: str | None = None
    authentication_required: bool | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    physical_access: bool | None = None


@dataclass(slots=True)
class CveDetailRecord:
    """Normalized per-CVE record derived from a CISA CSAF advisory."""

    document_type: str = "cve_detail"
    source_type: str = "cisa_csaf"
    advisory_id: str = ""
    cve_id: str = ""
    vendor: str | None = None
    product: str | None = None
    product_family: str | None = None
    model: str | None = None
    part_number: str | None = None
    affected_versions: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)
    affected_product_constraints: list[dict[str, str]] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    severity: str | None = None
    title: str | None = None
    description: str | None = None
    prerequisites: CvePrerequisites = field(default_factory=CvePrerequisites)
    effects: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    raw_product_ids: list[str] = field(default_factory=list)
    product_evidence: list[dict[str, Any]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def canonical_key(self) -> str:
        return self.cve_id.upper() if self.cve_id else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_type": self.document_type,
            "source_type": self.source_type,
            "advisory_id": self.advisory_id,
            "cve_id": self.cve_id,
            "vendor": self.vendor,
            "product": self.product,
            "product_family": self.product_family,
            "model": self.model,
            "part_number": self.part_number,
            "affected_versions": list(self.affected_versions),
            "affected_products": list(self.affected_products),
            "affected_product_constraints": list(self.affected_product_constraints),
            "cwe_ids": list(self.cwe_ids),
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "prerequisites": {
                "network_access": self.prerequisites.network_access,
                "authentication_required": self.prerequisites.authentication_required,
                "privileges_required": self.prerequisites.privileges_required,
                "user_interaction": self.prerequisites.user_interaction,
                "physical_access": self.prerequisites.physical_access,
            },
            "effects": list(self.effects),
            "references": list(self.references),
            "raw_product_ids": list(self.raw_product_ids),
            "product_evidence": list(self.product_evidence),
        }
