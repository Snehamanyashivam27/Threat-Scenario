from __future__ import annotations

import re
from dataclasses import dataclass

from rag.models.document import RetrievedChunk

WEAK_CONCEPT_TOKENS = {
    "a", "an", "the", "in", "on", "of", "and", "or", "to", "for", "with", "from", "by",
    "unauthorized", "industrial", "control", "systems", "system", "ics", "could", "can",
    "would", "might", "how", "lead", "into", "through", "using", "use", "used",
}


@dataclass(frozen=True, slots=True)
class SecurityConcept:
    name: str
    query_patterns: tuple[str, ...]
    match_phrases: tuple[str, ...]
    technique_hints: frozenset[str]
    expansion_terms: tuple[str, ...]


SECURITY_CONCEPTS: tuple[SecurityConcept, ...] = (
    SecurityConcept(
        name="remote_code_execution",
        query_patterns=(
            r"\bremote code execution\b",
            r"\brce\b",
            r"\barbitrary code execution\b",
            r"\bunauthorized code execution\b",
        ),
        match_phrases=(
            "remote code execution",
            "arbitrary code execution",
            "execute arbitrary code",
            "execute code remotely",
        ),
        technique_hints=frozenset({"T0819", "T1190", "T1203", "T0866", "T0890", "T0872"}),
        expansion_terms=(
            "exploit public-facing application",
            "remote code execution",
            "vulnerability",
            "unauthorized",
            "initial access",
        ),
    ),
    SecurityConcept(
        name="sql_injection",
        query_patterns=(r"\bsql injection\b", r"\bsqli\b"),
        match_phrases=("sql injection", "inject sql", "database query"),
        technique_hints=frozenset({"T1190", "T0819", "T1505"}),
        expansion_terms=("sql injection", "application exploit", "web application"),
    ),
    SecurityConcept(
        name="phishing",
        query_patterns=(r"\bphishing\b", r"\bspearphishing\b", r"\bspear phishing\b"),
        match_phrases=("phishing", "spearphishing", "malicious email", "spear phishing"),
        technique_hints=frozenset(
            {
                "T0865",
                "T0832",
                "T1566",
                "T1566.001",
                "T1566.002",
                "T1566.003",
                "T1598",
            }
        ),
        expansion_terms=("phishing", "spearphishing attachment", "social engineering", "email"),
    ),
)


def has_security_concept(query: str) -> bool:
    return bool(extract_security_concepts(query))


def is_scenario_style_query(query: str) -> bool:
    lowered = query.lower()
    return bool(re.search(r"\bhow (could|can|would|might)\b", lowered))


def extract_security_concepts(query: str) -> list[SecurityConcept]:
    lowered = query.lower()
    matched: list[SecurityConcept] = []
    for concept in SECURITY_CONCEPTS:
        if any(re.search(pattern, lowered) for pattern in concept.query_patterns):
            matched.append(concept)
    return matched


CONCEPT_DEFINITION_PATTERNS = (
    r"\bwhat is\b",
    r"\bexplain\b",
    r"\bdescribe\b",
    r"\btell me about\b",
)


def is_concept_definition_query(query: str) -> bool:
    if not has_security_concept(query):
        return False
    if is_scenario_style_query(query):
        return False
    lowered = query.lower()
    return any(re.search(pattern, lowered) for pattern in CONCEPT_DEFINITION_PATTERNS)


def concept_technique_hints(query: str) -> set[str]:
    hints: set[str] = set()
    for concept in extract_security_concepts(query):
        hints |= set(concept.technique_hints)
    return hints


def expand_query_for_retrieval(query: str) -> str:
    from rag.retrieval.context_selector import ADVISORY_INTENTS, QueryIntent, detect_query_intent

    intent = detect_query_intent(query)
    # Lookup-style queries should not be biased by concept expansion terms.
    if intent in {
        QueryIntent.GENERAL_CONCEPT_QUERY,
        QueryIntent.ATTACK_TECHNIQUE_LOOKUP,
        QueryIntent.ATTACK_TACTIC_LOOKUP,
        QueryIntent.ATTACK_ID_LOOKUP,
        *ADVISORY_INTENTS,
    }:
        return query

    concepts = extract_security_concepts(query)
    if not concepts:
        return query

    if intent == QueryIntent.THREAT_SCENARIO_QUERY:
        extra_terms = [term for concept in concepts for term in concept.expansion_terms]
        return f"{query} {' '.join(extra_terms)}"

    extra_terms = [phrase for concept in concepts for phrase in concept.match_phrases]
    deduped_terms = list(dict.fromkeys(extra_terms))
    if not deduped_terms:
        return query
    return f"{query} {' '.join(deduped_terms)}"


def chunk_search_text(chunk: RetrievedChunk) -> str:
    from rag.retrieval.context_selector import extract_fields, extract_title

    fields = extract_fields(chunk.text)
    parts = [
        extract_title(chunk),
        fields.get("Description", ""),
        fields.get("Detection", ""),
        fields.get("Mitigations", ""),
        fields.get("CVE", ""),
        fields.get("Advisory", ""),
    ]
    return _normalize_text(" ".join(part for part in parts if part))


def concept_match_score(query: str, chunk: RetrievedChunk) -> float:
    from rag.retrieval.context_selector import extract_attack_id

    concepts = extract_security_concepts(query)
    if not concepts:
        return 0.0

    text = chunk_search_text(chunk)
    attack_id = (extract_attack_id(chunk) or "").upper()
    score = 0.0

    for concept in concepts:
        concept_score = 0.0
        if attack_id and attack_id in concept.technique_hints:
            concept_score = max(concept_score, 2.5)

        for phrase in concept.match_phrases:
            normalized_phrase = _normalize_text(phrase)
            if normalized_phrase and normalized_phrase in text:
                concept_score = max(concept_score, 3.0)

        if concept_score > 0:
            score += concept_score
            continue

        for phrase in concept.match_phrases:
            phrase_tokens = set(_normalize_text(phrase).split()) - WEAK_CONCEPT_TOKENS
            if not phrase_tokens:
                continue
            text_tokens = set(text.split())
            overlap = phrase_tokens & text_tokens
            if overlap and len(overlap) < len(phrase_tokens):
                score -= 4.0
                break
        else:
            score -= 2.0

    return score


def _normalize_text(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(text).lower()).strip()
