from __future__ import annotations

"""Select and render D3FEND-style controls from existing defense evidence.

Read-only. Does not change Stage 6 recommendation text, infer ATT&CK technique
IDs, mutate inputs, or call an LLM.
"""

import json
from pathlib import Path
from typing import Any

from rag.defense.d3fend_catalog import (
    SOURCE_ATTACK_MITIGATION,
    SOURCE_CSAF,
    SOURCE_CWE,
    SOURCE_EFFECT,
    SOURCE_OBJECTIVE,
    SOURCE_RANK,
    SOURCE_STEP_ID,
    SOURCE_TECHNIQUE,
    TACTIC_RANK,
    controls_for_csaf_category,
    controls_for_cwe,
    controls_for_effect,
    controls_for_mitigation,
    controls_for_objective,
    controls_for_step_id,
    controls_for_technique,
)
from rag.defense.models import (
    D3FendControlCandidate,
    D3FendControlReport,
    D3FendControlSpec,
    RecommendationCandidate,
    RecommendationPolicyState,
    RenderedD3FendControl,
    RenderedStepD3FendControls,
    StepRecommendationCandidates,
    UnifiedStepDefenseEvidence,
)
from rag.defense.recommendation_policy import ACTIONABLE_STATES, SOURCE_ATTACK, SOURCE_CSAF as POLICY_SOURCE_CSAF
from rag.defense.scenario_context import load_defense_step_contexts
from rag.scenario.applicability import classify_step_objective, extract_vulnerability_effects
from rag.scenario.evidence import CandidateEvidence, StepEvidence
from rag.scenario.models import AttackStep


def select_d3fend_controls(
    *,
    unified: list[UnifiedStepDefenseEvidence],
    policy: list[StepRecommendationCandidates],
    evidence: list[StepEvidence],
    scenario_dir: str | Path,
) -> D3FendControlReport:
    policy_by_step = {row.step_id: row for row in policy}
    facts = _load_step_facts(scenario_dir)
    evidence_by_step = {item.step_id: item for item in evidence}
    steps: list[RenderedStepD3FendControls] = []
    for row in unified:
        candidates = _candidates_for_step(
            row,
            policy_by_step.get(row.step_id),
            evidence_by_step.get(row.step_id),
            facts.get(row.step_id),
        )
        rendered = [_render_candidate(item) for item in _dedupe_candidates(candidates)]
        rendered.sort(key=_render_sort_key)
        if rendered:
            steps.append(
                RenderedStepD3FendControls(
                    step_id=row.step_id,
                    sequence=row.sequence,
                    controls=rendered,
                )
            )
    return D3FendControlReport(steps=steps)


def serialize_d3fend_control_report(report: D3FendControlReport) -> str:
    return json.dumps(
        report.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _candidates_for_step(
    row: UnifiedStepDefenseEvidence,
    policy_row: StepRecommendationCandidates | None,
    evidence: StepEvidence | None,
    fact: dict[str, Any] | None,
) -> list[D3FendControlCandidate]:
    candidates: list[D3FendControlCandidate] = []
    if policy_row is not None:
        for item in policy_row.candidates:
            if item.policy_state not in ACTIONABLE_STATES:
                continue
            candidates.extend(_from_policy_candidate(row, item))
    if evidence is not None:
        selected = _selected_candidate(evidence)
        if selected is not None:
            candidates.extend(_from_selected_candidate(row, selected))
    if fact:
        candidates.extend(_from_step_fact(row, fact))
    candidates.extend(_from_step_id(row))
    return candidates


def _from_policy_candidate(
    row: UnifiedStepDefenseEvidence,
    item: RecommendationCandidate,
) -> list[D3FendControlCandidate]:
    conditional = item.policy_state is RecommendationPolicyState.CONDITIONAL
    if item.source_type == SOURCE_ATTACK:
        specs = controls_for_mitigation(
            mitigation_id=item.mitigation_id,
            mitigation_name=item.name,
        )
        citation = _attack_citation(item.technique_id, item.mitigation_id)
        return [
            _candidate(
                row,
                spec,
                SOURCE_ATTACK_MITIGATION,
                citation,
                conditional=False,
                provenance=item.provenance,
            )
            for spec in specs
        ]
    if item.source_type == POLICY_SOURCE_CSAF:
        specs = controls_for_csaf_category(item.category, item.content)
        citation = _csaf_citation(item.cve_id, item.advisory_id)
        return [
            _candidate(
                row,
                spec,
                SOURCE_CSAF,
                citation,
                conditional=conditional and spec.technique_id == "D3-SU",
                provenance=item.provenance,
            )
            for spec in specs
        ]
    return []


def _from_selected_candidate(
    row: UnifiedStepDefenseEvidence,
    selected: CandidateEvidence,
) -> list[D3FendControlCandidate]:
    candidates: list[D3FendControlCandidate] = []
    effects = extract_vulnerability_effects(
        cwes=frozenset(selected.cwes),
        description=selected.description,
        effects=list(selected.effects),
    )
    for effect in sorted(effects, key=lambda item: item.value):
        citation = f"vulnerability effect {effect.value}."
        if selected.cve_id:
            citation = f"CVE: {selected.cve_id}. {citation}"
        for spec in controls_for_effect(effect):
            candidates.append(_candidate(row, spec, SOURCE_EFFECT, citation))
    for cwe_id in sorted({str(item).strip().upper() for item in selected.cwes if item}):
        specs = controls_for_cwe(cwe_id)
        if not specs:
            continue
        citation = f"CWE: {cwe_id}."
        if selected.cve_id:
            citation = f"CVE: {selected.cve_id}. {citation}"
        for spec in specs:
            candidates.append(_candidate(row, spec, SOURCE_CWE, citation))
    return candidates


def _from_step_fact(
    row: UnifiedStepDefenseEvidence,
    fact: dict[str, Any],
) -> list[D3FendControlCandidate]:
    candidates: list[D3FendControlCandidate] = []
    technique_ids = [str(item) for item in fact.get("technique_ids") or [] if item]
    for technique_id in technique_ids:
        specs = controls_for_technique(technique_id)
        citation = f"Technique: {technique_id}."
        for spec in specs:
            candidates.append(_candidate(row, spec, SOURCE_TECHNIQUE, citation))
    step = AttackStep(
        sequence=row.sequence,
        step_id=row.step_id,
        name=str(fact.get("name") or ""),
        source_component_id=None,
        target_component_id=None,
        description=str(fact.get("description") or ""),
    )
    objective = classify_step_objective(step)
    specs = controls_for_objective(objective)
    if specs:
        citation = f"scenario step objective {objective.value}."
        for spec in specs:
            candidates.append(_candidate(row, spec, SOURCE_OBJECTIVE, citation))
    return candidates


def _from_step_id(row: UnifiedStepDefenseEvidence) -> list[D3FendControlCandidate]:
    specs = controls_for_step_id(row.step_id)
    if not specs:
        return []
    citation = f"scenario step_id {row.step_id}."
    return [_candidate(row, spec, SOURCE_STEP_ID, citation) for spec in specs]


def _candidate(
    row: UnifiedStepDefenseEvidence,
    spec: D3FendControlSpec,
    source_type: str,
    citation: str,
    *,
    conditional: bool = False,
    provenance: str = "",
) -> D3FendControlCandidate:
    return D3FendControlCandidate(
        step_id=row.step_id,
        sequence=row.sequence,
        spec=spec,
        source_type=source_type,
        citation=citation,
        conditional=conditional,
        provenance=provenance,
    )


def _dedupe_candidates(candidates: list[D3FendControlCandidate]) -> list[D3FendControlCandidate]:
    best: dict[str, D3FendControlCandidate] = {}
    for item in candidates:
        key = item.spec.technique_id
        current = best.get(key)
        if current is None or _source_rank(item) < _source_rank(current):
            best[key] = item
            continue
        if _source_rank(item) == _source_rank(current) and item.citation < current.citation:
            best[key] = item
    return list(best.values())


def _render_candidate(item: D3FendControlCandidate) -> RenderedD3FendControl:
    prefix = "Conditional " if item.conditional else ""
    text = (
        f"{prefix}{item.spec.tactic} — {item.spec.technique_id} {item.spec.technique_name}: "
        f"{item.spec.summary}"
    )
    if item.conditional:
        text = f"{text} This control is conditional because the deployed version is unknown."
    return RenderedD3FendControl(
        step_id=item.step_id,
        sequence=item.sequence,
        tactic=item.spec.tactic,
        technique_id=item.spec.technique_id,
        technique_name=item.spec.technique_name,
        rendered_text=text,
        citation=item.citation,
        source_type=item.source_type,
        conditional=item.conditional,
        provenance=item.provenance,
    )


def _render_sort_key(item: RenderedD3FendControl) -> tuple:
    return (
        TACTIC_RANK.get(item.tactic, 9),
        item.technique_id,
        item.rendered_text,
    )


def _source_rank(item: D3FendControlCandidate) -> int:
    return SOURCE_RANK.get(item.source_type, 9)


def _selected_candidate(evidence: StepEvidence) -> CandidateEvidence | None:
    selected = evidence.selected_cve
    if not selected:
        return None
    for item in evidence.candidates:
        if item.cve_id == selected:
            return item
    return None


def _attack_citation(technique_id: str, mitigation_id: str) -> str:
    parts: list[str] = []
    if technique_id:
        parts.append(f"Technique: {technique_id}")
    if mitigation_id:
        parts.append(f"ATT&CK mitigation: {mitigation_id}")
    if not parts:
        return "ATT&CK mitigation."
    return ". ".join(parts) + "."


def _csaf_citation(cve_id: str, advisory_id: str) -> str:
    parts: list[str] = []
    if cve_id:
        parts.append(f"CVE: {cve_id}")
    if advisory_id:
        parts.append(f"Advisory: {advisory_id}")
    if not parts:
        return "CSAF remediation."
    return ". ".join(parts) + "."


def _load_step_facts(scenario_dir: str | Path) -> dict[str, dict[str, Any]]:
    path = Path(scenario_dir)
    if path.is_dir():
        path = path / "scenario.json"
    facts: dict[str, dict[str, Any]] = {}
    contexts = {item.step_id: item for item in load_defense_step_contexts(scenario_dir)}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        data = {}
    steps = data.get("attack_path") if isinstance(data, dict) else None
    if isinstance(steps, list):
        for item in steps:
            if not isinstance(item, dict):
                continue
            step_id = str(item.get("step_id") or "").strip()
            if not step_id:
                continue
            context = contexts.get(step_id)
            facts[step_id] = {
                "name": str(item.get("name") or ""),
                "description": str(item.get("description") or ""),
                "technique_ids": list(context.technique_ids) if context else [],
            }
    return facts
