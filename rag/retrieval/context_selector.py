from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from rag.models.document import RetrievedChunk
from rag.retrieval.query_understanding import (
    concept_match_score,
    concept_technique_hints,
    has_security_concept,
    is_concept_definition_query,
    is_scenario_style_query,
)
from rag.retrieval.document_fields import extract_attack_id, extract_attack_ids, extract_cves, extract_fields, extract_title
from rag.retrieval.identifier_lookup import chunk_matches_cves, chunk_matches_cwes, extract_cwes


class QueryIntent(str, Enum):
    ATTACK_TECHNIQUE_LOOKUP = "attack_technique_lookup"
    ATTACK_TACTIC_LOOKUP = "attack_tactic_lookup"
    ATTACK_ID_LOOKUP = "attack_id_lookup"
    CVE_LOOKUP = "cve_lookup"
    VENDOR_LOOKUP = "vendor_lookup"
    ADVISORY_LOOKUP = "advisory_lookup"
    GENERAL_CONCEPT_QUERY = "general_concept_query"
    THREAT_SCENARIO_QUERY = "threat_scenario_query"
    GENERAL_SECURITY_QUESTION = "general_security_question"


WEAK_OVERLAP_TOKENS = {
    "a", "an", "the", "is", "are", "what", "explain", "describe", "show", "how", "does", "do",
    "attack", "technique", "threat", "exploit", "public", "facing", "application", "applications",
    "adversary", "adversaries", "mitre", "att", "ck", "ics", "enterprise", "security", "system", "systems",
}

ATTACK_INTENTS = {QueryIntent.ATTACK_TECHNIQUE_LOOKUP, QueryIntent.ATTACK_ID_LOOKUP, QueryIntent.ATTACK_TACTIC_LOOKUP}
ADVISORY_INTENTS = {QueryIntent.CVE_LOOKUP, QueryIntent.VENDOR_LOOKUP, QueryIntent.ADVISORY_LOOKUP}
CONCEPT_INTENTS = {QueryIntent.GENERAL_CONCEPT_QUERY}

PRODUCT_QUERY_PATTERNS = (
    r"\bscalance\b",
    r"\bsimatic\b",
    r"\bsinamics\b",
    r"\bwincc\b",
    r"\bmodicon\b",
    r"\bcontrollogix\b",
    r"\bfx5\b",
    r"\bx\d{3,4}\b",
    r"\bs7[- ]?\d",
)


@dataclass(slots=True)
class ScoredChunk:
    chunk: RetrievedChunk
    relevance_score: float
    signals: dict[str, float]


class ContextSelector:
    CONCEPT_MAX_RESULTS = 6
    TACTIC_MAX_RESULTS = 6

    def __init__(self, max_results: int = 3, min_results: int = 2, retrieval_pool_size: int = 10):
        self.max_results = max_results
        self.min_results = min_results
        self.retrieval_pool_size = retrieval_pool_size

    def select(
        self,
        query: str,
        retrieved_chunks: Iterable[RetrievedChunk],
        pool_size: int | None = None,
    ) -> list[RetrievedChunk]:
        # pool_size lets the caller pass the full hybrid pool (e.g. 15 for concept queries).
        effective_pool = pool_size if pool_size is not None else self.retrieval_pool_size
        chunks = list(retrieved_chunks)[:effective_pool]
        if not chunks:
            return []

        intent = detect_query_intent(query)
        technique_phrase = extract_technique_phrase(query)
        query_attack_ids = extract_attack_ids(query)
        query_cves = extract_cves(query)
        query_cwes = extract_cwes(query)

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
        scored.sort(key=lambda item: (-item.relevance_score, item.chunk.chunk_id))
        filtered = self._filter_scored(
            scored,
            intent=intent,
            query=query,
            technique_phrase=technique_phrase,
            query_attack_ids=query_attack_ids,
            query_cves=query_cves,
            query_cwes=query_cwes,
        )
        limit = self._result_limit(intent, filtered)
        return [item.chunk for item in filtered[:limit]]

    def _result_limit(self, intent: QueryIntent, filtered: list[ScoredChunk]) -> int:
        if intent in {QueryIntent.GENERAL_CONCEPT_QUERY, QueryIntent.ATTACK_TACTIC_LOOKUP}:
            max_for_intent = self.CONCEPT_MAX_RESULTS if intent == QueryIntent.GENERAL_CONCEPT_QUERY else self.TACTIC_MAX_RESULTS
            return min(max_for_intent, len(filtered))
        if len(filtered) >= self.min_results:
            return self.max_results
        return max(self.min_results, len(filtered))

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
        signals["metadata_similarity"] = metadata_similarity(chunk, query, query_cves, intent=intent)
        signals["source_intent"] = source_intent_score(source_group, intent)
        signals["concept_match"] = concept_match_score(query, chunk)
        if intent == QueryIntent.GENERAL_CONCEPT_QUERY and signals["concept_match"] > 0:
            signals["concept_match"] *= 1.25

        noise_intents = ATTACK_INTENTS | {QueryIntent.THREAT_SCENARIO_QUERY, QueryIntent.GENERAL_CONCEPT_QUERY}
        if intent in noise_intents and title_match == "none" and "attack_id_match" not in signals:
            if weak_token_overlap_only(normalized_title, normalized_query, normalized_technique):
                signals["noise_penalty"] = -4.0
        if intent == QueryIntent.THREAT_SCENARIO_QUERY and signals["concept_match"] <= -3.0:
            signals["concept_noise_penalty"] = -5.0

        relevance_score = sum(signals.values())
        return ScoredChunk(chunk=chunk, relevance_score=relevance_score, signals=signals)

    def _filter_scored(
        self,
        scored: list[ScoredChunk],
        intent: QueryIntent,
        query: str,
        technique_phrase: str,
        query_attack_ids: set[str],
        query_cves: set[str] | None = None,
        query_cwes: set[str] | None = None,
    ) -> list[ScoredChunk]:
        query_cves = query_cves or set()
        query_cwes = query_cwes or set()
        if not scored:
            return []

        if intent in ATTACK_INTENTS and (technique_phrase or query_attack_ids):
            direct_matches = [
                item
                for item in scored
                if self._is_direct_attack_match(item, technique_phrase, query_attack_ids)
            ]
            if direct_matches:
                if intent == QueryIntent.ATTACK_TACTIC_LOOKUP:
                    return self._dedupe_by_attack_id(direct_matches)
                return self._dedupe_by_framework(direct_matches)

        if intent == QueryIntent.ATTACK_TACTIC_LOOKUP:
            tactic_phrase = normalize_text(extract_technique_phrase(query) or query)
            tactic_matches = [item for item in scored if tactic_match_score(item.chunk, tactic_phrase) > 0]
            if tactic_matches:
                return self._dedupe_by_attack_id(tactic_matches)

        if intent in ADVISORY_INTENTS:
            if query_cves:
                cve_matches = [item for item in scored if chunk_matches_cves(item.chunk, query_cves)]
                if cve_matches:
                    return cve_matches
            if query_cwes:
                cwe_matches = [item for item in scored if chunk_matches_cwes(item.chunk, query_cwes)]
                if cwe_matches:
                    return cwe_matches
            advisory_matches = [item for item in scored if source_group_for(item.chunk) == "cisa"]
            if advisory_matches:
                return advisory_matches

        if intent == QueryIntent.GENERAL_CONCEPT_QUERY:
            concept_matches = [item for item in scored if item.signals.get("concept_match", 0.0) > 0]
            if concept_matches:
                return self._select_concept_techniques(concept_matches, query)
            hinted = [item for item in scored if self._matches_concept_hints(item, query)]
            if hinted:
                return self._select_concept_techniques(hinted, query)
            if technique_phrase:
                phrase_matches = [
                    item
                    for item in scored
                    if self._is_direct_attack_match(item, technique_phrase, query_attack_ids)
                    or item.signals.get("title_partial_match", 0.0) > 0
                    or item.signals.get("title_exact_match", 0.0) >= 4.0
                ]
                if phrase_matches:
                    return self._dedupe_by_attack_id(phrase_matches)[: self.CONCEPT_MAX_RESULTS]

        if intent == QueryIntent.THREAT_SCENARIO_QUERY:
            concept_matches = [item for item in scored if item.signals.get("concept_match", 0.0) > 0]
            if concept_matches:
                return self._dedupe_by_framework(concept_matches)

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
    def _dedupe_by_attack_id(scored: list[ScoredChunk]) -> list[ScoredChunk]:
        seen_ids: set[str] = set()
        deduped: list[ScoredChunk] = []
        for item in scored:
            attack_id = extract_attack_id(item.chunk)
            key = attack_id.upper() if attack_id else item.chunk.chunk_id
            if key in seen_ids:
                continue
            seen_ids.add(key)
            deduped.append(item)
        return deduped

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

    @staticmethod
    def _matches_concept_hints(item: ScoredChunk, query: str) -> bool:
        attack_id = extract_attack_id(item.chunk)
        if not attack_id:
            return False
        return attack_id.upper() in concept_technique_hints(query)

    @staticmethod
    def _select_concept_techniques(scored: list[ScoredChunk], query: str) -> list[ScoredChunk]:
        hints = concept_technique_hints(query)
        selected: list[ScoredChunk] = []
        seen_ids: set[str] = set()

        for item in scored:
            attack_id = extract_attack_id(item.chunk)
            if not attack_id or attack_id.upper() not in hints or attack_id.upper() in seen_ids:
                continue
            selected.append(item)
            seen_ids.add(attack_id.upper())

        for item in scored:
            attack_id = extract_attack_id(item.chunk)
            key = attack_id.upper() if attack_id else item.chunk.chunk_id
            if key in seen_ids:
                continue
            if item.signals.get("concept_match", 0.0) <= 0 and not ContextSelector._matches_concept_hints(item, query):
                continue
            selected.append(item)
            seen_ids.add(key)
            if len(selected) >= ContextSelector.CONCEPT_MAX_RESULTS:
                break

        # Prefer at least one Enterprise and one ICS technique when both are available.
        represented = {source_group_for(item.chunk) for item in selected}
        for framework in ("enterprise", "ics"):
            if framework in represented or len(selected) >= ContextSelector.CONCEPT_MAX_RESULTS:
                continue
            for item in scored:
                if source_group_for(item.chunk) != framework:
                    continue
                attack_id = extract_attack_id(item.chunk)
                key = attack_id.upper() if attack_id else item.chunk.chunk_id
                if key in seen_ids:
                    continue
                if item.signals.get("concept_match", 0.0) <= 0 and not ContextSelector._matches_concept_hints(item, query):
                    continue
                selected.append(item)
                seen_ids.add(key)
                represented.add(framework)
                break

        return selected or scored[: ContextSelector.CONCEPT_MAX_RESULTS]


def is_explicit_technique_request(query: str) -> bool:
    lowered = query.lower()
    if re.search(r"\bT\d{4}(?:\.\d{3})?\b", query, flags=re.IGNORECASE):
        return True
    if re.search(r"\b(attack pattern|technique id|technique identifier)\b", lowered):
        return True
    if re.search(r"\batt&ck\s+(technique|id)\b", lowered):
        return True
    if re.search(r"\bthe\s+.+\s+technique\b", lowered):
        return True
    if re.search(r"\btechnique\s+(named|called)\b", lowered):
        return True
    return False


def is_ambiguous_definition_query(query: str) -> bool:
    lowered = query.lower()
    return bool(re.search(r"\b(what is|explain|describe|tell me about)\b", lowered))


def detect_query_intent(query: str) -> QueryIntent:
    lowered = query.lower()
    if re.search(r"\bT\d{4}(?:\.\d{3})?\b", query, flags=re.IGNORECASE):
        return QueryIntent.ATTACK_ID_LOOKUP
    if re.search(r"\bCVE-\d{4}-\d+\b", query, flags=re.IGNORECASE):
        return QueryIntent.CVE_LOOKUP
    if "threat scenario" in lowered or ("generate" in lowered and "scenario" in lowered):
        return QueryIntent.THREAT_SCENARIO_QUERY
    if re.search(r"\b(what is|explain|describe|tell me about)\b", lowered) and re.search(r"\btactic\b", lowered):
        return QueryIntent.ATTACK_TACTIC_LOOKUP
    if is_concept_definition_query(query):
        return QueryIntent.GENERAL_CONCEPT_QUERY
    if is_scenario_style_query(query) or has_security_concept(query):
        return QueryIntent.THREAT_SCENARIO_QUERY
    if any(term in lowered for term in ("advisory", "advisories", "cisa")):
        return QueryIntent.ADVISORY_LOOKUP
    if any(term in lowered for term in ("vendor", "vendors", "siemens", "schneider", "abb", "rockwell")):
        return QueryIntent.VENDOR_LOOKUP
    if re.search(r"\b(what is|explain|describe|tell me about)\b", lowered):
        if not any(term in lowered for term in ("advisory", "advisories", "cve", "vendor")):
            phrase = extract_technique_phrase(query)
            if looks_like_product_query(phrase):
                return QueryIntent.VENDOR_LOOKUP
            if is_explicit_technique_request(query):
                return QueryIntent.ATTACK_TECHNIQUE_LOOKUP
            return QueryIntent.GENERAL_CONCEPT_QUERY
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
    phrase = re.sub(r"\b(att&ck|mitre|technique|attack pattern|tactic)\b", "", phrase, flags=re.IGNORECASE)
    phrase = re.sub(r"\bthe\b", "", phrase, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", phrase).strip(" ?.,!")


def looks_like_product_query(phrase: str) -> bool:
    normalized = normalize_text(phrase)
    if not normalized:
        return False
    return any(re.search(pattern, normalized) for pattern in PRODUCT_QUERY_PATTERNS)


def tactic_match_score(chunk: RetrievedChunk, tactic_phrase: str) -> float:
    if not tactic_phrase:
        return 0.0
    fields = extract_fields(chunk.text)
    tactic = normalize_text(fields.get("Tactic", chunk.metadata.get("tactic", "")))
    if not tactic:
        return 0.0
    if tactic_phrase in tactic or tactic in tactic_phrase:
        return 2.0
    phrase_tokens = set(tactic_phrase.split())
    tactic_tokens = set(tactic.split())
    overlap = phrase_tokens & tactic_tokens
    if len(overlap) >= max(1, min(2, len(phrase_tokens))):
        return 1.0
    return 0.0


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
    if intent == QueryIntent.GENERAL_CONCEPT_QUERY:
        if source_group in {"enterprise", "ics"}:
            return 0.5
        if source_group == "cisa":
            return -0.25
    return 0.0


def metadata_similarity(chunk: RetrievedChunk, query: str, query_cves: set[str], intent: QueryIntent | None = None) -> float:
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
        resolved_intent = intent if intent is not None else detect_query_intent(query)
        if resolved_intent == QueryIntent.ATTACK_TACTIC_LOOKUP:
            score += tactic_match_score(chunk, normalize_text(extract_technique_phrase(query) or query))
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
