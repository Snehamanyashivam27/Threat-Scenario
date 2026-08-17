from __future__ import annotations

"""Aggregate Stage 2 CSAF and Stage 3 ATT&CK evidence per step.

Read-only. Does not rank, merge semantically, mutate inputs, or invent
ATT&CK deployment applicability.
"""

import json

from rag.defense.models import (
    StepAttackMitigationInventory,
    StepDefenseEvidence,
    UnifiedStepDefenseEvidence,
)
from rag.scenario.evidence import StepEvidence, TruthValue

_NOTE_NO_SELECTED_CVE = "no_selected_cve"
_NOTE_NO_CSAF_REMEDIATION = "no_csaf_remediation"
_NOTE_NO_ATTACK_TECHNIQUE_ID = "no_attack_technique_id"
_NOTE_NO_ATTACK_MITIGATION = "no_attack_mitigation"
_NOTE_AMBIGUOUS_CSAF = "ambiguous_csaf_step_id"
_NOTE_AMBIGUOUS_ATTACK = "ambiguous_attack_step_id"
_NOTE_ORDER = (
    _NOTE_AMBIGUOUS_CSAF,
    _NOTE_AMBIGUOUS_ATTACK,
    _NOTE_NO_SELECTED_CVE,
    _NOTE_NO_CSAF_REMEDIATION,
    _NOTE_NO_ATTACK_TECHNIQUE_ID,
    _NOTE_NO_ATTACK_MITIGATION,
)


def unify_step_defense_evidence(
    csaf: list[StepDefenseEvidence],
    attack: list[StepAttackMitigationInventory],
    *,
    evidence: list[StepEvidence] | None = None,
) -> list[UnifiedStepDefenseEvidence]:
    """Combine CSAF and ATT&CK branches by exact step_id.

    Duplicate step_ids within a branch are not merged. Missing branches stay
    empty. `evidence`, when provided, defines step order and which step_ids
    appear; it is not mutated and is not used to infer techniques.
    """
    csaf_unique, csaf_ambiguous = _unique_by_step_id(csaf)
    attack_unique, attack_ambiguous = _unique_by_step_id(attack)
    rows: list[UnifiedStepDefenseEvidence] = []
    for step_id, sequence in _step_order(csaf, attack, evidence):
        csaf_ambiguous_hit = step_id in csaf_ambiguous
        attack_ambiguous_hit = step_id in attack_ambiguous
        csaf_row = None if csaf_ambiguous_hit else csaf_unique.get(step_id)
        attack_row = None if attack_ambiguous_hit else attack_unique.get(step_id)
        has_attack_records = bool(attack_row and attack_row.records)
        rows.append(
            UnifiedStepDefenseEvidence(
                step_id=step_id,
                sequence=sequence,
                csaf=csaf_row,
                attack=attack_row,
                attack_relationship_supported=TruthValue.TRUE if has_attack_records else TruthValue.UNKNOWN,
                attack_deployment_applicability=TruthValue.UNKNOWN,
                notes=_notes(
                    csaf_row,
                    attack_row,
                    csaf_ambiguous=csaf_ambiguous_hit,
                    attack_ambiguous=attack_ambiguous_hit,
                ),
            )
        )
    return rows


def serialize_unified_step_defense_evidence(rows: list[UnifiedStepDefenseEvidence]) -> str:
    return json.dumps(
        [row.to_dict() for row in rows],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _unique_by_step_id(rows: list) -> tuple[dict[str, object], set[str]]:
    grouped: dict[str, list] = {}
    for row in rows:
        grouped.setdefault(row.step_id, []).append(row)
    unique: dict[str, object] = {}
    ambiguous: set[str] = set()
    for step_id, items in grouped.items():
        if len(items) == 1:
            unique[step_id] = items[0]
        else:
            ambiguous.add(step_id)
    return unique, ambiguous


def _step_order(
    csaf: list[StepDefenseEvidence],
    attack: list[StepAttackMitigationInventory],
    evidence: list[StepEvidence] | None,
) -> list[tuple[str, int]]:
    if evidence is not None:
        return [(step.step_id, step.sequence) for step in evidence]
    ordered: list[tuple[str, int]] = []
    seen: set[str] = set()
    for row in csaf:
        if row.step_id in seen:
            continue
        seen.add(row.step_id)
        ordered.append((row.step_id, row.sequence))
    for row in attack:
        if row.step_id in seen:
            continue
        seen.add(row.step_id)
        ordered.append((row.step_id, row.sequence))
    return ordered


def _notes(
    csaf: StepDefenseEvidence | None,
    attack: StepAttackMitigationInventory | None,
    *,
    csaf_ambiguous: bool,
    attack_ambiguous: bool,
) -> list[str]:
    selected: list[str] = []
    if csaf_ambiguous:
        selected.append(_NOTE_AMBIGUOUS_CSAF)
    if attack_ambiguous:
        selected.append(_NOTE_AMBIGUOUS_ATTACK)
    if csaf is None or not csaf.selected_cve or csaf.note == _NOTE_NO_SELECTED_CVE:
        selected.append(_NOTE_NO_SELECTED_CVE)
    if csaf is None or not csaf.remediations:
        selected.append(_NOTE_NO_CSAF_REMEDIATION)
    if attack is None or not attack.technique_ids or attack.note in {
        "no_technique_id",
        "no_step_mapping",
        "ambiguous_step_id",
    }:
        selected.append(_NOTE_NO_ATTACK_TECHNIQUE_ID)
    if attack is None or not attack.records:
        selected.append(_NOTE_NO_ATTACK_MITIGATION)
    return [item for item in _NOTE_ORDER if item in selected]
