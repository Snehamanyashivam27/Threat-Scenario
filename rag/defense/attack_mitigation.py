from __future__ import annotations

"""Extract ATT&CK course-of-action evidence from STIX bundles.

Reads source JSON directly. Uses exact `mitigates` relationships only.
Does not query retrieval indexes, mutate scenario objects, or use an LLM.
"""

import json
import re
from pathlib import Path
from typing import Any, Iterable

from rag.defense.models import AttackMitigationEvidence, StepAttackMitigationInventory
from rag.scenario.evidence import StepEvidence
from rag.scenario.models import ScenarioNarrativeResult
from rag.utils.text import dedupe_preserve_order

_TECHNIQUE_EXTERNAL_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_MITIGATION_EXTERNAL_RE = re.compile(r"^M\d{4}$", re.IGNORECASE)
_STIX_ATTACK_PATTERN_RE = re.compile(r"^attack-pattern--[0-9a-f-]+$", re.IGNORECASE)
_STRUCTURED_TECHNIQUE_KEYS = (
    "attack_id",
    "technique_id",
    "attack_pattern_id",
    "attack_ids",
    "technique_ids",
)
_MITRE_SOURCE_NAMES = frozenset({"mitre-attack", "mitre-ics-attack"})


def lookup_attack_mitigations(
    sources: str | Path,
    *,
    technique_id: str,
) -> list[AttackMitigationEvidence]:
    """Return mitigations linked by exact STIX `mitigates` relationships.

    `technique_id` must be an external ATT&CK ID (Txxxx / Txxxx.xxx) or a STIX
    `attack-pattern--` object ID. Inactive (revoked/deprecated) techniques,
    mitigations, and relationships are excluded from the default inventory.
    """
    query = _normalize_technique_query(technique_id)
    if not query:
        return []
    found: list[AttackMitigationEvidence] = []
    seen: set[tuple[str, str, str, str]] = set()
    for path in _source_paths(sources):
        for record in _records_from_bundle(path, query):
            key = record.dedupe_key()
            if key in seen:
                continue
            seen.add(key)
            found.append(record)
    found.sort(key=_record_sort_key)
    return found


def inventory_scenario_attack_mitigations(
    result: ScenarioNarrativeResult,
    sources: str | Path,
) -> list[StepAttackMitigationInventory]:
    return inventory_step_attack_mitigations(result.evidence, sources)


def inventory_step_attack_mitigations(
    evidence: list[StepEvidence],
    sources: str | Path,
) -> list[StepAttackMitigationInventory]:
    rows: list[StepAttackMitigationInventory] = []
    for step in evidence:
        technique_ids = _technique_ids_from_step(step)
        if not technique_ids:
            rows.append(
                StepAttackMitigationInventory(
                    step_id=step.step_id,
                    sequence=step.sequence,
                    technique_ids=[],
                    records=[],
                    note="no_technique_id",
                )
            )
            continue
        records: list[AttackMitigationEvidence] = []
        notes: list[str] = []
        for technique_id in technique_ids:
            matched = lookup_attack_mitigations(sources, technique_id=technique_id)
            if matched:
                records.extend(matched)
                continue
            if _technique_is_inactive(sources, technique_id):
                notes.append("technique_inactive")
            else:
                notes.append("technique_not_found")
        records = _dedupe_records(records)
        records.sort(key=_record_sort_key)
        note = ""
        if not records:
            note = notes[0] if notes else "technique_not_found"
        rows.append(
            StepAttackMitigationInventory(
                step_id=step.step_id,
                sequence=step.sequence,
                technique_ids=list(technique_ids),
                records=records,
                note=note,
            )
        )
    return rows


def serialize_attack_mitigation_inventory(rows: list[StepAttackMitigationInventory]) -> str:
    return json.dumps(
        [row.to_dict() for row in rows],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def serialize_attack_mitigations(records: list[AttackMitigationEvidence]) -> str:
    return json.dumps(
        [item.to_dict() for item in records],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _source_paths(sources: str | Path) -> list[Path]:
    root = Path(sources)
    if not root.exists():
        return []
    if root.is_file():
        return [root]
    return sorted(root.glob("*.json"), key=lambda item: item.as_posix())


def _records_from_bundle(path: Path, query: str) -> list[AttackMitigationEvidence]:
    objects = _load_objects(path)
    if not objects:
        return []
    by_id: dict[str, dict[str, Any]] = {}
    for obj in objects:
        obj_id = str(obj.get("id") or "").strip()
        if obj_id and obj_id not in by_id:
            by_id[obj_id] = obj
    techniques = [
        obj
        for obj in objects
        if obj.get("type") == "attack-pattern" and _object_matches_technique(obj, query)
    ]
    records: list[AttackMitigationEvidence] = []
    seen: set[tuple[str, str, str, str]] = set()
    source_path = str(path.resolve())
    for technique in techniques:
        if _is_inactive(technique):
            continue
        technique_id = str(technique.get("id") or "")
        for rel in objects:
            if rel.get("type") != "relationship":
                continue
            if str(rel.get("relationship_type") or "") != "mitigates":
                continue
            if _is_inactive(rel):
                continue
            source_ref = str(rel.get("source_ref") or "")
            target_ref = str(rel.get("target_ref") or "")
            if target_ref != technique_id:
                continue
            mitigation = by_id.get(source_ref)
            if not isinstance(mitigation, dict) or mitigation.get("type") != "course-of-action":
                continue
            if _is_inactive(mitigation):
                continue
            record = _evidence_record(
                technique=technique,
                mitigation=mitigation,
                relationship=rel,
                source_path=source_path,
                path=path,
            )
            key = record.dedupe_key()
            if key in seen:
                continue
            seen.add(key)
            records.append(record)
    return records


def _evidence_record(
    *,
    technique: dict[str, Any],
    mitigation: dict[str, Any],
    relationship: dict[str, Any],
    source_path: str,
    path: Path,
) -> AttackMitigationEvidence:
    technique_stix = str(technique.get("id") or "")
    mitigation_stix = str(mitigation.get("id") or "")
    relationship_stix = str(relationship.get("id") or "")
    technique_external = _mitre_external_id(technique.get("external_references"))
    mitigation_external = _mitre_external_id(mitigation.get("external_references"))
    technique_domain = _domain(technique, path)
    mitigation_domain = _domain(mitigation, path)
    provenance = "::".join(
        [
            technique_domain,
            technique_external or technique_stix,
            mitigation_stix,
            relationship_stix,
            source_path,
        ]
    )
    return AttackMitigationEvidence(
        technique_stix_id=technique_stix,
        technique_external_id=technique_external,
        technique_name=_optional_text(technique.get("name")),
        technique_domain=technique_domain,
        mitigation_stix_id=mitigation_stix,
        mitigation_external_id=mitigation_external,
        mitigation_name=_optional_text(mitigation.get("name")),
        description=_optional_text(mitigation.get("description"), collapse=False),
        urls=_urls(mitigation.get("external_references")),
        domain=mitigation_domain,
        relationship_stix_id=relationship_stix,
        relationship_type="mitigates",
        source_ref=str(relationship.get("source_ref") or ""),
        target_ref=str(relationship.get("target_ref") or ""),
        relationship_description=_optional_text(relationship.get("description"), collapse=False),
        source_path=source_path,
        provenance=provenance,
        technique_revoked=_flag(technique.get("revoked")),
        technique_deprecated=_flag(technique.get("x_mitre_deprecated")),
        mitigation_revoked=_flag(mitigation.get("revoked")),
        mitigation_deprecated=_flag(mitigation.get("x_mitre_deprecated")),
        relationship_revoked=_flag(relationship.get("revoked")),
        relationship_deprecated=_flag(relationship.get("x_mitre_deprecated")),
    )


def _technique_is_inactive(sources: str | Path, technique_id: str) -> bool:
    query = _normalize_technique_query(technique_id)
    if not query:
        return False
    for path in _source_paths(sources):
        for obj in _load_objects(path):
            if obj.get("type") != "attack-pattern":
                continue
            if _object_matches_technique(obj, query) and _is_inactive(obj):
                return True
    return False


def _load_objects(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    objects: list[dict[str, Any]] = []
    for item in data.get("objects") or []:
        if isinstance(item, dict):
            objects.append(item)
    return objects


def _object_matches_technique(obj: dict[str, Any], query: str) -> bool:
    stix_id = str(obj.get("id") or "").strip().lower()
    if query.startswith("attack-pattern--") and stix_id == query:
        return True
    external_id = _mitre_external_id(obj.get("external_references"))
    return bool(external_id) and external_id == query


def _technique_ids_from_step(step: StepEvidence) -> list[str]:
    context = step.context if isinstance(step.context, dict) else {}
    values: list[str] = []
    for key in _STRUCTURED_TECHNIQUE_KEYS:
        raw = context.get(key)
        if isinstance(raw, str):
            values.append(raw)
        elif isinstance(raw, list):
            values.extend(str(item) for item in raw if item)
    normalized = [_normalize_technique_query(item) for item in values]
    return dedupe_preserve_order([item for item in normalized if item])


def _normalize_technique_query(raw: str) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if _STIX_ATTACK_PATTERN_RE.match(text):
        return text.lower()
    if _TECHNIQUE_EXTERNAL_RE.match(text):
        return text.upper()
    return ""


def _mitre_external_id(references: Any) -> str:
    if not isinstance(references, list):
        return ""
    for reference in references:
        if not isinstance(reference, dict):
            continue
        source = str(reference.get("source_name") or "").strip().lower()
        external_id = str(reference.get("external_id") or "").strip()
        if external_id and source in _MITRE_SOURCE_NAMES:
            return _canonical_external_id(external_id)
    for reference in references:
        if not isinstance(reference, dict):
            continue
        external_id = str(reference.get("external_id") or "").strip()
        if external_id and (
            _TECHNIQUE_EXTERNAL_RE.match(external_id) or _MITIGATION_EXTERNAL_RE.match(external_id)
        ):
            return _canonical_external_id(external_id)
    return ""


def _canonical_external_id(value: str) -> str:
    return value.upper()


def _urls(references: Any) -> list[str]:
    if not isinstance(references, list):
        return []
    values: list[str] = []
    for reference in references:
        if not isinstance(reference, dict):
            continue
        url = str(reference.get("url") or "").strip()
        if url:
            values.append(url)
    return dedupe_preserve_order(values)


def _domain(obj: dict[str, Any], path: Path) -> str:
    raw = obj.get("x_mitre_domains")
    if isinstance(raw, list):
        for item in raw:
            text = str(item or "").strip()
            if text:
                return text
    elif isinstance(raw, str) and raw.strip():
        return raw.strip()
    name = path.name.lower()
    if "ics" in name:
        return "ics-attack"
    if "enterprise" in name:
        return "enterprise-attack"
    return path.stem


def _is_inactive(obj: dict[str, Any]) -> bool:
    return _flag(obj.get("revoked")) or _flag(obj.get("x_mitre_deprecated"))


def _flag(value: Any) -> bool:
    return value is True


def _optional_text(value: Any, *, collapse: bool = True) -> str:
    if value is None:
        return ""
    text = str(value)
    if collapse:
        return text.strip()
    return text


def _dedupe_records(records: Iterable[AttackMitigationEvidence]) -> list[AttackMitigationEvidence]:
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[AttackMitigationEvidence] = []
    for record in records:
        key = record.dedupe_key()
        if key in seen:
            continue
        seen.add(key)
        unique.append(record)
    return unique


def _record_sort_key(record: AttackMitigationEvidence) -> tuple[str, ...]:
    return (
        record.source_path,
        record.technique_domain,
        record.technique_external_id or record.technique_stix_id,
        record.mitigation_external_id or record.mitigation_stix_id,
        record.relationship_stix_id,
    )
