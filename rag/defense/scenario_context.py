from __future__ import annotations

"""Read exact ATT&CK technique IDs from original scenario JSON.

Defense-only. Does not mutate threat models or infer techniques from prose,
tactics, retrieval, or LLM output.
"""

import json
import re
from pathlib import Path
from typing import Any

from rag.defense.attack_mitigation import lookup_attack_mitigations
from rag.defense.models import AttackMitigationEvidence, DefenseStepContext, StepAttackMitigationInventory
from rag.scenario.evidence import StepEvidence
from rag.utils.text import dedupe_preserve_order

_TECHNIQUE_EXTERNAL_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_STIX_ATTACK_PATTERN_RE = re.compile(r"^attack-pattern--[0-9a-f-]+$", re.IGNORECASE)
_STRUCTURED_TECHNIQUE_KEYS = (
    "technique_id",
    "attack_id",
    "attack_pattern_id",
    "technique_ids",
    "attack_ids",
)


def load_defense_step_contexts(source: str | Path) -> list[DefenseStepContext]:
    """Extract exact technique IDs from scenario.json attack_path entries."""
    path = _scenario_json_path(source)
    if path is None:
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    scenario_id = str(data.get("scenario_id") or "").strip()
    steps = data.get("attack_path")
    if not isinstance(steps, list):
        return []
    source_path = str(path.resolve())
    rows: list[DefenseStepContext] = []
    for item in steps:
        if not isinstance(item, dict):
            continue
        step_id = str(item.get("step_id") or "").strip()
        if not step_id:
            continue
        technique_ids, source_fields = _technique_ids_from_step_object(item)
        sequence = _sequence(item.get("sequence"))
        provenance = f"{source_path}::{step_id}"
        if source_fields:
            provenance = f"{provenance}::{','.join(source_fields)}"
        rows.append(
            DefenseStepContext(
                scenario_id=scenario_id,
                step_id=step_id,
                sequence=sequence,
                technique_ids=technique_ids,
                source_fields=source_fields,
                provenance=provenance,
                note="" if technique_ids else "no_technique_id",
            )
        )
    return rows


def align_defense_contexts(
    contexts: list[DefenseStepContext],
    evidence: list[StepEvidence],
) -> list[DefenseStepContext]:
    """Match contexts to evidence by exact step_id. No positional fallback."""
    scenario_id = next((item.scenario_id for item in contexts if item.scenario_id), "")
    grouped: dict[str, list[DefenseStepContext]] = {}
    for context in contexts:
        grouped.setdefault(context.step_id, []).append(context)
    aligned: list[DefenseStepContext] = []
    for step in evidence:
        matches = grouped.get(step.step_id) or []
        if len(matches) == 1:
            aligned.append(matches[0])
            continue
        note = "ambiguous_step_id" if len(matches) > 1 else "no_step_mapping"
        aligned.append(
            DefenseStepContext(
                scenario_id=scenario_id,
                step_id=step.step_id,
                sequence=step.sequence,
                technique_ids=[],
                source_fields=[],
                provenance="",
                note=note,
            )
        )
    return aligned


def inventory_attack_mitigations_from_contexts(
    contexts: list[DefenseStepContext],
    sources: str | Path,
) -> list[StepAttackMitigationInventory]:
    """Pass exact context technique IDs to the Stage 3 STIX reader."""
    rows: list[StepAttackMitigationInventory] = []
    for context in contexts:
        if not context.technique_ids:
            rows.append(
                StepAttackMitigationInventory(
                    step_id=context.step_id,
                    sequence=context.sequence,
                    technique_ids=[],
                    records=[],
                    note=context.note or "no_technique_id",
                )
            )
            continue
        records: list[AttackMitigationEvidence] = []
        seen: set[tuple[str, str, str, str]] = set()
        for technique_id in context.technique_ids:
            for record in lookup_attack_mitigations(sources, technique_id=technique_id):
                key = record.dedupe_key()
                if key in seen:
                    continue
                seen.add(key)
                records.append(record)
        records.sort(
            key=lambda item: (
                item.source_path,
                item.technique_domain,
                item.technique_external_id or item.technique_stix_id,
                item.mitigation_external_id or item.mitigation_stix_id,
                item.relationship_stix_id,
            )
        )
        rows.append(
            StepAttackMitigationInventory(
                step_id=context.step_id,
                sequence=context.sequence,
                technique_ids=list(context.technique_ids),
                records=records,
                note="" if records else "technique_not_found",
            )
        )
    return rows


def serialize_defense_step_contexts(rows: list[DefenseStepContext]) -> str:
    return json.dumps(
        [row.to_dict() for row in rows],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _scenario_json_path(source: str | Path) -> Path | None:
    path = Path(source)
    if path.is_dir():
        path = path / "scenario.json"
    if not path.is_file():
        return None
    return path


def _technique_ids_from_step_object(item: dict[str, Any]) -> tuple[list[str], list[str]]:
    values: list[str] = []
    source_fields: list[str] = []
    for key in _STRUCTURED_TECHNIQUE_KEYS:
        raw = item.get(key)
        extracted: list[str] = []
        if isinstance(raw, str):
            extracted.append(raw)
        elif isinstance(raw, list):
            extracted.extend(str(entry) for entry in raw if entry)
        else:
            continue
        accepted = [_normalize_technique_id(entry) for entry in extracted]
        accepted = [entry for entry in accepted if entry]
        if not accepted:
            continue
        values.extend(accepted)
        source_fields.append(key)
    return dedupe_preserve_order(values), source_fields


def _normalize_technique_id(raw: str) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if _STIX_ATTACK_PATTERN_RE.match(text):
        return text.lower()
    if _TECHNIQUE_EXTERNAL_RE.match(text):
        return text.upper()
    return ""


def _sequence(value: Any) -> int:
    try:
        sequence = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return sequence if sequence > 0 else 0
