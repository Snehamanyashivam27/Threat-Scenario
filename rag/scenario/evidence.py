from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class TruthValue(str, Enum):
    TRUE = "known_true"
    FALSE = "known_false"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"


@dataclass(slots=True)
class ApplicabilityCheck:
    name: str
    status: TruthValue
    required: str = ""
    observed: str = ""
    reason: str = ""
    provenance: str = ""


@dataclass(slots=True)
class CandidateEvidence:
    cve_id: str
    advisory_id: str | None
    disposition: str
    final_status: str = "insufficient_context"
    checks: list[ApplicabilityCheck] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)
    affected_versions: list[str] = field(default_factory=list)
    description: str = ""
    effects: list[str] = field(default_factory=list)
    vulnerability_phrase: str = ""
    version_bound: str | None = None
    unresolved_conditions: list[str] = field(default_factory=list)
    rejection_reasons: list[str] = field(default_factory=list)
    rank_score: int = 0
    gate_table: dict[str, str] = field(default_factory=dict)
    # Auditable lifecycle: RETRIEVED → VALIDATED → REJECTED|CONDITIONAL|VERIFIED
    # → SELECTED|NOT_SELECTED → NARRATOR_ELIGIBLE → NARRATED|REMOVED_BY_VALIDATOR
    lifecycle: list[str] = field(default_factory=list)
    lifecycle_reason: str = ""
    product_evidence_trace: list[dict[str, Any]] = field(default_factory=list)

    @property
    def is_usable(self) -> bool:
        return self.disposition in {"applicable", "conditional"}

    def record_lifecycle(self, stage: str, reason: str = "") -> None:
        if stage and (not self.lifecycle or self.lifecycle[-1] != stage):
            self.lifecycle.append(stage)
        if reason:
            self.lifecycle_reason = reason


@dataclass(slots=True)
class RankedHit:
    rank: int
    document_id: str
    source: str
    score: float
    cves: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RetrievalTrace:
    query: str
    vector: list[RankedHit] = field(default_factory=list)
    bm25: list[RankedHit] = field(default_factory=list)
    rrf: list[RankedHit] = field(default_factory=list)
    selected: list[RankedHit] = field(default_factory=list)


@dataclass(slots=True)
class StepEvidence:
    step_id: str
    sequence: int
    context: dict[str, Any] = field(default_factory=dict)
    queries: list[str] = field(default_factory=list)
    retrieval: list[RetrievalTrace] = field(default_factory=list)
    candidates: list[CandidateEvidence] = field(default_factory=list)
    selected_cve: str | None = None
    selected_cves: list[str] = field(default_factory=list)
    selection_reason: str = ""
    narrator_evidence: list[dict[str, Any]] = field(default_factory=list)
    vulnerable_component_id: str | None = None
    action_target_id: str | None = None
    downstream_affected_id: str | None = None
    admission_trace: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
