from __future__ import annotations

"""Structured CSAF remediation evidence. Not used by threat generation."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from rag.scenario.evidence import TruthValue


@dataclass(slots=True)
class RemediationAction:
    category: str
    details: str
    urls: list[str] = field(default_factory=list)
    product_ids: list[str] = field(default_factory=list)
    group_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "details": self.details,
            "urls": list(self.urls),
            "product_ids": list(self.product_ids),
            "group_ids": list(self.group_ids),
        }

    def dedupe_key(self) -> tuple[str, str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
        return (
            self.category,
            self.details,
            tuple(self.urls),
            tuple(self.product_ids),
            tuple(self.group_ids),
        )


@dataclass(slots=True)
class CveRemediationRecord:
    cve_id: str
    advisory_id: str
    source_path: str
    provenance: str
    remediations: list[RemediationAction] = field(default_factory=list)
    fixed_product_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "advisory_id": self.advisory_id,
            "source_path": self.source_path,
            "provenance": self.provenance,
            "remediations": [item.to_dict() for item in self.remediations],
            "fixed_product_ids": list(self.fixed_product_ids),
        }

    def has_remediation_evidence(self) -> bool:
        return bool(self.remediations or self.fixed_product_ids)


@dataclass(slots=True)
class StepRemediationInventory:
    step_id: str
    sequence: int
    selected_cve: str | None
    advisory_id: str | None
    records: list[CveRemediationRecord] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "sequence": self.sequence,
            "selected_cve": self.selected_cve,
            "advisory_id": self.advisory_id,
            "note": self.note,
            "records": [item.to_dict() for item in self.records],
        }


class DefenseSupportState(str, Enum):
    SUPPORTED = "supported"
    CONDITIONAL = "conditional"
    REJECTED = "rejected"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    NOT_APPLICABLE = "not_applicable"


@dataclass(slots=True)
class DefenseApplicabilityCheck:
    name: str
    status: TruthValue
    required: str = ""
    observed: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "required": self.required,
            "observed": self.observed,
            "reason": self.reason,
        }


@dataclass(slots=True)
class ValidatedRemediation:
    cve_id: str
    advisory_id: str
    source_path: str
    provenance: str
    category: str
    details: str
    urls: list[str] = field(default_factory=list)
    product_ids: list[str] = field(default_factory=list)
    group_ids: list[str] = field(default_factory=list)
    fixed_product_ids: list[str] = field(default_factory=list)
    support_state: DefenseSupportState = DefenseSupportState.INSUFFICIENT_EVIDENCE
    checks: list[DefenseApplicabilityCheck] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "advisory_id": self.advisory_id,
            "source_path": self.source_path,
            "provenance": self.provenance,
            "category": self.category,
            "details": self.details,
            "urls": list(self.urls),
            "product_ids": list(self.product_ids),
            "group_ids": list(self.group_ids),
            "fixed_product_ids": list(self.fixed_product_ids),
            "support_state": self.support_state.value,
            "checks": [item.to_dict() for item in self.checks],
        }


@dataclass(slots=True)
class StepDefenseEvidence:
    step_id: str
    sequence: int
    selected_cve: str | None
    advisory_id: str | None
    note: str = ""
    remediations: list[ValidatedRemediation] = field(default_factory=list)
    source_conflict: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "sequence": self.sequence,
            "selected_cve": self.selected_cve,
            "advisory_id": self.advisory_id,
            "note": self.note,
            "source_conflict": self.source_conflict,
            "remediations": [item.to_dict() for item in self.remediations],
        }


@dataclass(slots=True)
class AttackMitigationEvidence:
    technique_stix_id: str
    technique_external_id: str
    technique_name: str
    technique_domain: str
    mitigation_stix_id: str
    mitigation_external_id: str
    mitigation_name: str
    description: str
    urls: list[str] = field(default_factory=list)
    domain: str = ""
    relationship_stix_id: str = ""
    relationship_type: str = "mitigates"
    source_ref: str = ""
    target_ref: str = ""
    relationship_description: str = ""
    source_path: str = ""
    provenance: str = ""
    technique_revoked: bool = False
    technique_deprecated: bool = False
    mitigation_revoked: bool = False
    mitigation_deprecated: bool = False
    relationship_revoked: bool = False
    relationship_deprecated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_stix_id": self.technique_stix_id,
            "technique_external_id": self.technique_external_id,
            "technique_name": self.technique_name,
            "technique_domain": self.technique_domain,
            "mitigation_stix_id": self.mitigation_stix_id,
            "mitigation_external_id": self.mitigation_external_id,
            "mitigation_name": self.mitigation_name,
            "description": self.description,
            "urls": list(self.urls),
            "domain": self.domain,
            "relationship_stix_id": self.relationship_stix_id,
            "relationship_type": self.relationship_type,
            "source_ref": self.source_ref,
            "target_ref": self.target_ref,
            "relationship_description": self.relationship_description,
            "source_path": self.source_path,
            "provenance": self.provenance,
            "technique_revoked": self.technique_revoked,
            "technique_deprecated": self.technique_deprecated,
            "mitigation_revoked": self.mitigation_revoked,
            "mitigation_deprecated": self.mitigation_deprecated,
            "relationship_revoked": self.relationship_revoked,
            "relationship_deprecated": self.relationship_deprecated,
        }

    def dedupe_key(self) -> tuple[str, str, str, str]:
        return (self.source_path, self.source_ref, self.target_ref, self.relationship_type)


@dataclass(slots=True)
class StepAttackMitigationInventory:
    step_id: str
    sequence: int
    technique_ids: list[str] = field(default_factory=list)
    records: list[AttackMitigationEvidence] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "sequence": self.sequence,
            "technique_ids": list(self.technique_ids),
            "note": self.note,
            "records": [item.to_dict() for item in self.records],
        }


@dataclass(slots=True)
class DefenseStepContext:
    scenario_id: str
    step_id: str
    sequence: int = 0
    technique_ids: list[str] = field(default_factory=list)
    source_fields: list[str] = field(default_factory=list)
    provenance: str = ""
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "step_id": self.step_id,
            "sequence": self.sequence,
            "technique_ids": list(self.technique_ids),
            "source_fields": list(self.source_fields),
            "provenance": self.provenance,
            "note": self.note,
        }


@dataclass(slots=True)
class UnifiedStepDefenseEvidence:
    step_id: str
    sequence: int
    csaf: StepDefenseEvidence | None = None
    attack: StepAttackMitigationInventory | None = None
    attack_relationship_supported: TruthValue = TruthValue.UNKNOWN
    attack_deployment_applicability: TruthValue = TruthValue.UNKNOWN
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        attack = self._attack_dict()
        return {
            "step_id": self.step_id,
            "sequence": self.sequence,
            "notes": list(self.notes),
            "csaf": None if self.csaf is None else self.csaf.to_dict(),
            "attack": attack,
            "attack_relationship_supported": self.attack_relationship_supported.value,
            "attack_deployment_applicability": self.attack_deployment_applicability.value,
        }

    def _attack_dict(self) -> dict[str, Any] | None:
        if self.attack is None:
            return None
        payload = self.attack.to_dict()
        records = []
        for item in payload.get("records") or []:
            record = dict(item)
            record["relationship_supported"] = self.attack_relationship_supported.value
            record["deployment_applicability"] = self.attack_deployment_applicability.value
            records.append(record)
        payload["records"] = records
        payload["relationship_supported"] = self.attack_relationship_supported.value
        payload["deployment_applicability"] = self.attack_deployment_applicability.value
        return payload


class RecommendationPolicyState(str, Enum):
    ELIGIBLE = "eligible"
    CONDITIONAL = "conditional"
    SUPPRESSED = "suppressed"
    INFORMATIONAL = "informational"


@dataclass(slots=True)
class RecommendationCondition:
    name: str
    status: TruthValue
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "reason": self.reason,
        }


@dataclass(slots=True)
class RecommendationCandidate:
    step_id: str
    sequence: int
    recommendation_id: str
    source_type: str
    policy_state: RecommendationPolicyState
    category: str
    name: str = ""
    content: str = ""
    cve_id: str = ""
    advisory_id: str = ""
    technique_id: str = ""
    mitigation_id: str = ""
    support_state: str = ""
    relationship_supported: str = ""
    deployment_applicability: str = ""
    conditions: list[RecommendationCondition] = field(default_factory=list)
    policy_reason: str = ""
    provenance: str = ""
    urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "sequence": self.sequence,
            "recommendation_id": self.recommendation_id,
            "source_type": self.source_type,
            "policy_state": self.policy_state.value,
            "category": self.category,
            "name": self.name,
            "content": self.content,
            "cve_id": self.cve_id,
            "advisory_id": self.advisory_id,
            "technique_id": self.technique_id,
            "mitigation_id": self.mitigation_id,
            "support_state": self.support_state,
            "relationship_supported": self.relationship_supported,
            "deployment_applicability": self.deployment_applicability,
            "conditions": [item.to_dict() for item in self.conditions],
            "policy_reason": self.policy_reason,
            "provenance": self.provenance,
            "urls": list(self.urls),
        }


@dataclass(slots=True)
class StepRecommendationCandidates:
    step_id: str
    sequence: int
    notes: list[str] = field(default_factory=list)
    candidates: list[RecommendationCandidate] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "sequence": self.sequence,
            "notes": list(self.notes),
            "candidates": [item.to_dict() for item in self.candidates],
        }


@dataclass(slots=True)
class RenderedRecommendation:
    step_id: str
    sequence: int
    recommendation_id: str
    source_type: str
    policy_state: RecommendationPolicyState
    category: str
    rendered_text: str
    source_content: str
    name: str = ""
    conditions: list[RecommendationCondition] = field(default_factory=list)
    citation: str = ""
    provenance: str = ""
    urls: list[str] = field(default_factory=list)
    cve_id: str = ""
    advisory_id: str = ""
    technique_id: str = ""
    mitigation_id: str = ""
    deployment_applicability: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "sequence": self.sequence,
            "recommendation_id": self.recommendation_id,
            "source_type": self.source_type,
            "policy_state": self.policy_state.value,
            "category": self.category,
            "rendered_text": self.rendered_text,
            "source_content": self.source_content,
            "name": self.name,
            "conditions": [item.to_dict() for item in self.conditions],
            "citation": self.citation,
            "provenance": self.provenance,
            "urls": list(self.urls),
            "cve_id": self.cve_id,
            "advisory_id": self.advisory_id,
            "technique_id": self.technique_id,
            "mitigation_id": self.mitigation_id,
            "deployment_applicability": self.deployment_applicability,
        }


@dataclass(slots=True)
class RenderedStepRecommendations:
    step_id: str
    sequence: int
    recommendations: list[RenderedRecommendation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "sequence": self.sequence,
            "recommendations": [item.to_dict() for item in self.recommendations],
        }


@dataclass(slots=True)
class DefenseRecommendationReport:
    steps: list[RenderedStepRecommendations] = field(default_factory=list)
    informational: list[RenderedRecommendation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "steps": [item.to_dict() for item in self.steps],
            "informational": [item.to_dict() for item in self.informational],
        }
