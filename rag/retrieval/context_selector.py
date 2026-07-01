from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from rag.models.document import RetrievedChunk
from rag.utils.text import strip_markdown_links


class QueryIntent(str, Enum):
    ATTACK_TECHNIQUE_LOOKUP = "attack_technique_lookup"
    ATTACK_ID_LOOKUP = "attack_id_lookup"
    CVE_LOOKUP = "cve_lookup"
    VENDOR_LOOKUP = "vendor_lookup"
    ADVISORY_LOOKUP = "advisory_lookup"
    THREAT_SCENARIO_QUERY = "threat_scenario_query"
    GENERAL_SECURITY_QUESTION = "general_security_question"


WEAK_OVERLAP_TOKENS = {
    "a", "an", "the", "is", "are", "what", "explain", "describe", "show", "how", "does", "do",
    "attack", "technique", "threat", "exploit", "public", "facing", "application", "applications",
    "adversary", "adversaries", "mitre", "att", "ck", "ics", "enterprise", "security", "system", "systems",
}

ATTACK_INTENTS = {QueryIntent.ATTACK_TECHNIQUE_LOOKUP, QueryIntent.ATTACK_ID_LOOKUP}
ADVISORY_INTENTS = {QueryIntent.CVE_LOOKUP, QueryIntent.VENDOR_LOOKUP, QueryIntent.ADVISORY_LOOKUP}


@dataclass(slots=True)
class ScoredChunk:
    chunk: RetrievedChunk
    relevance_score: float
    signals: dict[str, float]


class ContextSelector:
    def __init__(self, max_results: int = 3, min_results: int = 2, retrieval_pool_size: int = 10):
        self.max_results = max_results
        self.min_results = min_results
        self.retrieval_pool_size = retrieval_pool_size

    def select(self, query: str, retrieved_chunks: Iterable[RetrievedChunk]) -> list[RetrievedChunk]:
        chunks = list(retrieved_chunks)[: self.retrieval_pool_size]
        if not chunks:
            return []

        intent = detect_query_intent(query)
        technique_phrase = extract_technique_phrase(query)
        query_attack_ids = extract_attack_ids(query)
        query_cves = extract_cves(query)

        scored = [
            self._score_chunk(
                chunk=chunk,
                query=query,
                intent=intent,
                technique_phrase=technique_phrase,
                query_attack_ids=query_attack_ids,
                query_cves=query_cves,
            )
            for chunk in chunks
        ]
        scored.sort(key=lambda item: item.relevance_score, reverse=True)
        filtered = self._filter_scored(scored, intent=intent, technique_phrase=technique_phrase, query_attack_ids=query_attack_ids)
        limit = self.max_results if len(filtered) >= self.min_results else max(self.min_results, len(filtered))
        return [item.chunk for item in filtered[:limit]]

    def _score_chunk(
        self,
        chunk: RetrievedChunk,
        query: str,
        intent: QueryIntent,
        technique_phrase: str,
        query_attack_ids: set[str],
        query_cves: set[str],
    ) -> ScoredChunk:
        attack_id = extract_attack_id(chunk)
        title = extract_title(chunk)
        normalized_query = normalize_text(query)
        normalized_title = normalize_text(title)
        normalized_technique = normalize_text(technique_phrase)
        source_group = source_group_for(chunk)
        rrf_score = float(chunk.metadata.get("rrf_score", chunk.score))

        signals: dict[str, float] = {}

        if attack_id and attack_id.upper() in query_attack_ids:
            signals["attack_id_match"] = 5.0
        elif attack_id and attack_id.upper() in normalized_query.upper():
            signals["attack_id_match"] = 4.5

        title_match = classify_title_match(normalized_title, normalized_query, normalized_technique)
        if title_match == "exact":
            signals["title_exact_match"] = 4.0
        elif title_match == "partial":
            signals["title_partial_match"] = 1.5
        else:
            signals["title_similarity"] = title_similarity(normalized_title, normalized_query, normalized_technique)

        signals["semantic_score"] = min(max(rrf_score, chunk.score), 1.0) * 1.5
        signals["metadata_similarity"] = metadata_similarity(chunk, query, query_cves)
        signals["source_intent"] = source_intent_score(source_group, intent)

        if intent in ATTACK_INTENTS and title_match == "none" and "attack_id_match" not in signals:
            if weak_token_overlap_only(normalized_title, normalized_query, normalized_technique):
                signals["noise_penalty"] = -4.0

        relevance_score = sum(signals.values())
        return ScoredChunk(chunk=chunk, relevance_score=relevance_score, signals=signals)

    def _filter_scored(
        self,
        scored: list[ScoredChunk],
        intent: QueryIntent,
        technique_phrase: str,
        query_attack_ids: set[str],
    ) -> list[ScoredChunk]:
        if not scored:
            return []

        if intent in ATTACK_INTENTS and (technique_phrase or query_attack_ids):
            direct_matches = [
                item
                for item in scored
                if self._is_direct_attack_match(item, technique_phrase, query_attack_ids)
            ]
            if direct_matches:
                return self._dedupe_by_framework(direct_matches)

        if intent in ADVISORY_INTENTS:
            advisory_matches = [item for item in scored if source_group_for(item.chunk) == "cisa"]
            if advisory_matches:
                return advisory_matches

        top_score = scored[0].relevance_score
        threshold = top_score * 0.55
        filtered = [item for item in scored if item.relevance_score >= threshold]
        return filtered or scored[: self.max_results]

    @staticmethod
    def _is_direct_attack_match(item: ScoredChunk, technique_phrase: str, query_attack_ids: set[str]) -> bool:
        attack_id = extract_attack_id(item.chunk)
        title = extract_title(item.chunk)
        normalized_title = normalize_text(title)
        normalized_technique = normalize_text(technique_phrase)

        if attack_id and attack_id.upper() in query_attack_ids:
            return True
        if normalized_technique and normalized_title == normalized_technique:
            return True
        if normalized_technique and normalized_technique in normalized_title:
            return True
        return item.signals.get("title_exact_match", 0.0) >= 4.0

    @staticmethod
    def _dedupe_by_framework(scored: list[ScoredChunk]) -> list[ScoredChunk]:
        seen_groups: set[str] = set()
        deduped: list[ScoredChunk] = []
        for item in scored:
            group = source_group_for(item.chunk)
            if group in {"enterprise", "ics"}:
                key = f"{group}:{extract_attack_id(item.chunk) or extract_title(item.chunk)}"
                if key in seen_groups:
                    continue
                seen_groups.add(key)
            deduped.append(item)
        return deduped


def detect_query_intent(query: str) -> QueryIntent:
    lowered = query.lower()
    if re.search(r"\bT\d{4}(?:\.\d{3})?\b", query, flags=re.IGNORECASE):
        return QueryIntent.ATTACK_ID_LOOKUP
    if re.search(r"\bCVE-\d{4}-\d+\b", query, flags=re.IGNORECASE):
        return QueryIntent.CVE_LOOKUP
    if "threat scenario" in lowered or ("generate" in lowered and "scenario" in lowered):
        return QueryIntent.THREAT_SCENARIO_QUERY
    if any(term in lowered for term in ("advisory", "advisories", "cisa")):
        return QueryIntent.ADVISORY_LOOKUP
    if any(term in lowered for term in ("vendor", "vendors", "siemens", "schneider", "abb", "rockwell")):
        return QueryIntent.VENDOR_LOOKUP
    if re.search(r"\b(what is|explain|describe|tell me about)\b", lowered):
        if not any(term in lowered for term in ("advisory", "advisories", "cve", "vendor")):
            return QueryIntent.ATTACK_TECHNIQUE_LOOKUP
    if re.search(r"\b(technique|attack pattern|att&ck)\b", lowered):
        return QueryIntent.ATTACK_TECHNIQUE_LOOKUP
    return QueryIntent.GENERAL_SECURITY_QUESTION


def extract_technique_phrase(query: str) -> str:
    patterns = [
        r"\bwhat is\s+(.+?)\??$",
        r"\bexplain\s+(.+?)\??$",
        r"\bdescribe\s+(.+?)\??$",
        r"\btell me about\s+(.+?)\??$",
    ]
    for pattern in patterns:
        match = re.search(pattern, query.strip(), flags=re.IGNORECASE)
        if match:
            phrase = clean_query_phrase(match.group(1))
            if phrase:
                return phrase
    attack_ids = extract_attack_ids(query)
    if attack_ids:
        return ""
    return clean_query_phrase(query)


def clean_query_phrase(phrase: str) -> str:
    phrase = re.sub(r"\bT\d{4}(?:\.\d{3})?\b", "", phrase, flags=re.IGNORECASE)
    phrase = re.sub(r"\b(att&ck|mitre|technique|attack pattern)\b", "", phrase, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", phrase).strip(" ?.,!")


def extract_attack_ids(query: str) -> set[str]:
    return {match.upper() for match in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", query, flags=re.IGNORECASE)}


def extract_cves(query: str) -> set[str]:
    return {match.upper() for match in re.findall(r"\bCVE-\d{4}-\d+\b", query, flags=re.IGNORECASE)}


def extract_attack_id(chunk: RetrievedChunk) -> str:
    attack_id = chunk.metadata.get("attack_id") or chunk.metadata.get("meta_attack_id") or ""
    if attack_id:
        return str(attack_id).upper()
    fields = extract_fields(chunk.text)
    field_id = fields.get("ATT&CK ID", "")
    return field_id.upper() if field_id else ""


def extract_title(chunk: RetrievedChunk) -> str:
    title = str(chunk.metadata.get("title") or "")
    if title:
        return title
    fields = extract_fields(chunk.text)
    return fields.get("Technique Name") or fields.get("Technique") or fields.get("Advisory") or ""


def extract_fields(text: str) -> dict[str, str]:
    labels = [
        "Technique Name", "Technique", "ATT&CK ID", "Tactic", "Platforms", "Platform", "Description",
        "Detection", "Mitigations", "Advisory", "Identifier", "Vendor", "Product", "Affected Products",
        "CVE", "CWE", "Severity", "Sector",
    ]
    label_pattern = "|".join(re.escape(label) for label in labels)
    pattern = re.compile(rf"({label_pattern}):\s*(.*?)(?=\s+(?:{label_pattern}):|$)", flags=re.IGNORECASE | re.DOTALL)
    fields: dict[str, str] = {}
    canonical = {label.lower(): label for label in labels}
    for match in pattern.finditer(text):
        label = canonical.get(match.group(1).lower(), match.group(1))
        fields[label] = strip_markdown_links(re.sub(r"\s+", " ", match.group(2)).strip())
    return fields


def source_group_for(chunk: RetrievedChunk) -> str:
    source = str(chunk.source or chunk.metadata.get("source") or chunk.metadata.get("meta_source_type") or "").lower()
    if "enterprise-attack" in source:
        return "enterprise"
    if "ics-attack" in source:
        return "ics"
    if "cisa" in source or "ics_adv" in source:
        return "cisa"
    return "other"


def source_intent_score(source_group: str, intent: QueryIntent) -> float:
    if intent in ATTACK_INTENTS:
        if source_group in {"enterprise", "ics"}:
            return 0.75
        if source_group == "cisa":
            return -1.0
    if intent in ADVISORY_INTENTS or intent == QueryIntent.VENDOR_LOOKUP:
        if source_group == "cisa":
            return 0.75
        if source_group in {"enterprise", "ics"}:
            return -0.5
    if intent == QueryIntent.THREAT_SCENARIO_QUERY:
        if source_group in {"enterprise", "ics"}:
            return 0.4
        if source_group == "cisa":
            return 0.2
    return 0.0


def metadata_similarity(chunk: RetrievedChunk, query: str, query_cves: set[str]) -> float:
    score = 0.0
    fields = extract_fields(chunk.text)
    chunk_cves = {part.strip().upper() for part in re.split(r"[,;]", fields.get("CVE", "")) if part.strip()}
    if query_cves and chunk_cves & query_cves:
        score += 1.5

    vendor = normalize_text(fields.get("Vendor", ""))
    if vendor and vendor in normalize_text(query):
        score += 1.0

    tactic = normalize_text(fields.get("Tactic", chunk.metadata.get("tactic", "")))
    if tactic:
        query_tokens = set(normalize_text(query).split())
        tactic_tokens = set(tactic.split())
        if query_tokens & tactic_tokens:
            score += 0.5
    return score


def classify_title_match(normalized_title: str, normalized_query: str, normalized_technique: str) -> str:
    if not normalized_title:
        return "none"
    if normalized_technique and normalized_title == normalized_technique:
        return "exact"
    if normalized_technique and normalized_technique in normalized_title:
        return "exact"
    if normalized_title == normalized_query or normalized_title in normalized_query or normalized_query in normalized_title:
        return "exact"
    overlap = set(normalized_title.split()) & set((normalized_technique or normalized_query).split())
    if len(overlap) >= max(2, len(normalized_title.split()) // 2):
        return "partial"
    return "none"


def title_similarity(normalized_title: str, normalized_query: str, normalized_technique: str) -> float:
    if not normalized_title:
        return 0.0
    target = normalized_technique or normalized_query
    title_tokens = set(normalized_title.split())
    target_tokens = set(target.split())
    if not title_tokens or not target_tokens:
        return 0.0
    overlap = title_tokens & target_tokens
    meaningful = {token for token in overlap if token not in WEAK_OVERLAP_TOKENS}
    if not meaningful:
        return 0.0
    return len(meaningful) / max(len(target_tokens - WEAK_OVERLAP_TOKENS), 1)


def weak_token_overlap_only(normalized_title: str, normalized_query: str, normalized_technique: str) -> bool:
    target = normalized_technique or normalized_query
    title_tokens = set(normalized_title.split()) - WEAK_OVERLAP_TOKENS
    target_tokens = set(target.split()) - WEAK_OVERLAP_TOKENS
    overlap = title_tokens & target_tokens
    if not overlap:
        return True
    if normalized_technique and normalized_technique not in normalized_title:
        return True
    return False


def normalize_text(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(text).lower()).strip()
