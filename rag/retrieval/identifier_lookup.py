from __future__ import annotations

import json
import re
from dataclasses import dataclass

from rag.models.document import ChunkDocument, RetrievedChunk
from rag.retrieval.document_fields import extract_attack_id, extract_cves, extract_fields


CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
CWE_PATTERN = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
ATTACK_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
ADVISORY_ID_PATTERN = re.compile(r"\b(?:ICSA|ICSMA|ICSALERT)-[\dA-Z-]+\b", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class QueryIdentifiers:
    cves: frozenset[str]
    cwes: frozenset[str]
    attack_ids: frozenset[str]
    advisory_ids: frozenset[str]


def extract_query_identifiers(query: str) -> QueryIdentifiers:
    return QueryIdentifiers(
        cves=frozenset(extract_cves(query)),
        cwes=frozenset(extract_cwes(query)),
        attack_ids=frozenset(match.upper() for match in ATTACK_ID_PATTERN.findall(query)),
        advisory_ids=frozenset(match.upper() for match in ADVISORY_ID_PATTERN.findall(query)),
    )


def extract_cwes(query: str) -> set[str]:
    return {match.upper() for match in CWE_PATTERN.findall(query)}


def has_query_identifiers(query: str) -> bool:
    identifiers = extract_query_identifiers(query)
    return bool(identifiers.cves or identifiers.cwes or identifiers.attack_ids or identifiers.advisory_ids)


def lookup_by_identifiers(chunks: list[ChunkDocument], query: str) -> list[RetrievedChunk]:
    identifiers = extract_query_identifiers(query)
    if not has_query_identifiers(query):
        return []

    scored: list[tuple[float, ChunkDocument]] = []
    for chunk in chunks:
        score = _identifier_match_score(chunk, identifiers)
        if score > 0.0:
            scored.append((score, chunk))

    scored.sort(
        key=lambda item: (
            -item[0],
            -_identifier_source_priority(item[1], identifiers),
            item[1].chunk_id,
        )
    )
    return [_to_retrieved_chunk(chunk, score) for score, chunk in scored]


def chunk_cves(chunk: ChunkDocument | RetrievedChunk) -> set[str]:
    values = _chunk_identifier_values(chunk, "CVE", ("cves",))
    return _split_cve_identifiers(values)


def chunk_cwes(chunk: ChunkDocument | RetrievedChunk) -> set[str]:
    values = _chunk_identifier_values(chunk, "CWE", ("cwes",))
    return _split_cwe_identifiers(values)


def chunk_matches_cves(chunk: ChunkDocument | RetrievedChunk, query_cves: set[str]) -> bool:
    if not query_cves:
        return False
    return bool(chunk_cves(chunk) & query_cves)


def chunk_matches_cwes(chunk: ChunkDocument | RetrievedChunk, query_cwes: set[str]) -> bool:
    if not query_cwes:
        return False
    return bool(chunk_cwes(chunk) & query_cwes)


def _identifier_match_score(chunk: ChunkDocument, identifiers: QueryIdentifiers) -> float:
    if identifiers.attack_ids:
        attack_id = _chunk_attack_id(chunk)
        if attack_id and attack_id in identifiers.attack_ids:
            return 10.0
        return 0.0

    if identifiers.cves:
        if chunk_cves(chunk) & identifiers.cves:
            return 10.0
        return 0.0

    if identifiers.cwes:
        if chunk_cwes(chunk) & identifiers.cwes:
            return 10.0
        return 0.0

    if identifiers.advisory_ids:
        advisory_id = _chunk_advisory_id(chunk)
        if advisory_id and advisory_id in identifiers.advisory_ids:
            return 10.0
        return 0.0

    return 0.0


def _identifier_source_priority(
    chunk: ChunkDocument,
    identifiers: QueryIdentifiers,
) -> int:
    if not identifiers.cves:
        return 0
    kind = str(chunk.metadata.get("kind") or chunk.metadata.get("meta_kind") or "").lower()
    source = str(chunk.source or "").lower()
    if kind == "cisa-csaf-cve" or source == "cisa_csaf":
        return 2
    if "cisa" in source:
        return 1
    return 0


def _chunk_attack_id(chunk: ChunkDocument) -> str:
    attack_id = chunk.attack_id or chunk.metadata.get("attack_id") or chunk.metadata.get("meta_attack_id") or ""
    if attack_id:
        return str(attack_id).upper()
    return extract_attack_id(_as_retrieved_chunk(chunk))


def _chunk_advisory_id(chunk: ChunkDocument) -> str:
    metadata_advisory = str(chunk.metadata.get("advisory_id") or chunk.metadata.get("meta_advisory_id") or "").upper()
    if metadata_advisory and ADVISORY_ID_PATTERN.fullmatch(metadata_advisory):
        return metadata_advisory

    document_id = str(chunk.document_id or "").upper()
    if document_id and ADVISORY_ID_PATTERN.fullmatch(document_id):
        return document_id
    # CSAF per-CVE docs use "{advisory}::{cve}" document IDs.
    if "::" in document_id:
        prefix = document_id.split("::", 1)[0]
        if ADVISORY_ID_PATTERN.fullmatch(prefix):
            return prefix

    fields = extract_fields(chunk.original_text)
    for key in ("Identifier", "Advisory"):
        value = str(fields.get(key) or "").upper()
        if value and ADVISORY_ID_PATTERN.fullmatch(value):
            return value

    sections = _chunk_sections(chunk)
    for key in ("headline", "advisory_id"):
        advisory_id = str(sections.get(key) or "").upper()
        if advisory_id and ADVISORY_ID_PATTERN.fullmatch(advisory_id):
            return advisory_id
    return ""


def _chunk_identifier_values(chunk: ChunkDocument | RetrievedChunk, field_label: str, section_keys: tuple[str, ...]) -> str:
    text = chunk.original_text if isinstance(chunk, ChunkDocument) else chunk.text
    fields = extract_fields(text)
    values = [fields.get(field_label, "")]
    sections = _chunk_sections(chunk)
    for key in section_keys:
        values.append(str(sections.get(key) or ""))
    metadata = chunk.metadata if isinstance(chunk, ChunkDocument) else chunk.metadata
    values.append(str(metadata.get(field_label.lower()) or metadata.get(f"meta_{field_label.lower()}") or ""))
    if field_label == "CVE":
        values.append(str(metadata.get("cve_id") or metadata.get("meta_cve_id") or ""))
    if field_label == "CWE":
        values.append(str(metadata.get("cwes") or metadata.get("meta_cwes") or ""))
    return " ".join(value for value in values if value)


def _chunk_sections(chunk: ChunkDocument | RetrievedChunk) -> dict[str, str]:
    metadata = chunk.metadata
    sections = metadata.get("sections")
    if isinstance(sections, dict):
        return {str(key): str(value) for key, value in sections.items() if value}
    sections_json = metadata.get("sections_json") or metadata.get("meta_sections_json")
    if not sections_json:
        return {}
    try:
        parsed = json.loads(str(sections_json))
    except json.JSONDecodeError:
        return {}
    return {str(key): str(value) for key, value in parsed.items() if value} if isinstance(parsed, dict) else {}


def _split_cve_identifiers(value: str) -> set[str]:
    return {match.upper() for match in CVE_PATTERN.findall(value)}


def _split_cwe_identifiers(value: str) -> set[str]:
    return {match.upper() for match in CWE_PATTERN.findall(value)}


def _as_retrieved_chunk(chunk: ChunkDocument) -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id=chunk.chunk_id,
        score=0.0,
        source=chunk.source,
        document_id=chunk.document_id,
        metadata=dict(chunk.metadata),
        text=chunk.original_text,
        contextual_text=chunk.contextual_text,
    )


def _to_retrieved_chunk(chunk: ChunkDocument, score: float) -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id=chunk.chunk_id,
        score=score,
        source=chunk.source,
        document_id=chunk.document_id,
        metadata={**dict(chunk.metadata), "retrieval_method": "identifier"},
        text=chunk.original_text,
        contextual_text=chunk.contextual_text,
    )
