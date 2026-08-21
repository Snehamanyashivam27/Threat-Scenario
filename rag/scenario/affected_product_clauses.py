from __future__ import annotations

"""Parse unstructured affected-product clauses into identity + dimensions.

Validation-time only. Does not change indexed chunk text.
Does not guess: unparseable prose stays WEAK_DISCOVERY at the caller.
"""

import re
from dataclasses import dataclass

from rag.scenario.canonical_cve import ApplicabilityConstraint, parse_constraint_text
from rag.scenario.product_evidence import (
    ORIGIN_SOURCE_STATED,
    SCOPE_CVE_SPECIFIC,
    STRONG_IDENTITY,
    ProductEvidence,
    source_rank,
)

_RESERVED_ID_PREFIXES = ("CVE-", "CWE-", "ICSA-", "ICSMA-", "ICSALERT-")
_VERSION_LIKE_RE = re.compile(r"^v?\d+(?:\.\d+)*$", flags=re.IGNORECASE)
_PART_LABEL_RE = re.compile(r"\bpart(?:\s+numbers?)?\b", flags=re.IGNORECASE)
_DISCRETE_ID = (
    r"(?:[A-Za-z][A-Za-z0-9]*[-_][A-Za-z0-9][-A-Za-z0-9.]*|"
    r"[A-Za-z]*\d[A-Za-z0-9.-]*|"
    r"\d+[A-Za-z][A-Za-z0-9.-]*)"
)
_DISCRETE_ID_RE = re.compile(rf"(?P<id>{_DISCRETE_ID})")
_BARE_PRODUCT = r"[A-Z][A-Za-z][A-Za-z0-9]+"
_CLAUSE_LEFT = rf"(?:{_DISCRETE_ID}|{_BARE_PRODUCT})(?:\s*/\s*(?:{_DISCRETE_ID}|{_BARE_PRODUCT}))*"
_CLAUSE_CONSTRAINT = (
    r"(?:All\s+serial\s+numbers"
    r"|serial\s+numbers?\s+\S+(?:\s+and\s+(?:prior|later))?"
    r"|firmware(?:\s+versions?)?\s+(?:prior\s+to\s+|before\s+)?V?\d+(?:\.\d+)*"
    r"|software(?:\s+versions?)?\s+(?:prior\s+to\s+|before\s+)?V?\d+(?:\.\d+)*"
    r"|All\s+versions?(?:\s+prior\s+to\s+V?\d+(?:\.\d+)*)?"
    r"|Versions?\s+\"?V?\d+(?:\.\d+)*\"?(?:\s+and\s+prior)?"
    r"|version\s+V?\d+(?:\.\d+)*)"
)
_CLAUSE_RE = re.compile(
    rf"(?P<left>{_CLAUSE_LEFT})\s*:\s*(?P<constraint>(?i:{_CLAUSE_CONSTRAINT}))"
)
_SPACED_IDENTITY = r"[A-Z][A-Za-z0-9.+-]*(?:\s+[A-Z][A-Za-z0-9.+-]*){1,5}"
_SPACED_CLAUSE_RE = re.compile(
    rf"(?P<left>{_SPACED_IDENTITY})\s*:\s*(?P<constraint>(?i:{_CLAUSE_CONSTRAINT}))"
)
_SPACED_IDENTITY_STOPWORDS = frozenset(
    {
        "THE",
        "FOLLOWING",
        "VERSIONS",
        "AFFECTED",
        "PRODUCTS",
        "SERIES",
        "SYSTEM",
        "SOFTWARE",
        "OPERATING",
        "VERSION",
        "CONTROLLER",
        "AND",
        "OR",
        "INCLUDING",
        "PLUS",
        "ALL",
        "ARE",
        "IS",
        "OF",
        "AN",
        "A",
    }
)
_AMBIGUOUS_JOIN_RE = re.compile(r"\b(?:and|or|including|plus)\b", flags=re.IGNORECASE)
_VERSION_JOIN_RE = re.compile(r"\band\s+(?:prior|later)\b", flags=re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class ParsedAffectedProductClause:
    identity: str
    identity_kind: str
    constraint_text: str
    constraints: tuple[ApplicabilityConstraint, ...]
    source_field: str
    original_text: str


def is_discrete_identity_token(value: str) -> bool:
    text = (value or "").strip()
    if not text or " " in text:
        return False
    if any(text.upper().startswith(prefix) for prefix in _RESERVED_ID_PREFIXES):
        return False
    if _VERSION_LIKE_RE.fullmatch(text):
        return False
    if text.isdigit():
        return False
    return bool(_DISCRETE_ID_RE.fullmatch(text))


def parse_affected_product_clauses(
    text: str,
    *,
    source_field: str = "affected_products",
    cve_id: str = "",
    advisory_id: str = "",
    source: str = "",
) -> list[ParsedAffectedProductClause]:
    """Extract unambiguous `IDENTITY: constraint` clauses.

    Family/series/vendor prose and multi-product sentences without this syntax
    yield nothing (caller keeps WEAK_DISCOVERY).
    """
    blob = text or ""
    if not blob.strip():
        return []
    found: list[ParsedAffectedProductClause] = []
    seen: set[tuple[str, str]] = set()

    def _accept(
        *,
        constraint: str,
        start: int,
        end: int,
        original: str,
        identities: list[str],
        kind: str,
    ) -> None:
        constraint = " ".join((constraint or "").split()).strip().rstrip(".,")
        if not constraint or not identities:
            return
        if _clause_is_ambiguous(blob, start, end, identities):
            return
        parsed = tuple(
            parse_constraint_text(
                constraint,
                cve_id=cve_id,
                advisory_id=advisory_id,
                source=source,
            )
        )
        if not parsed:
            return
        for identity in identities:
            key = (identity.upper(), constraint.lower())
            if key in seen:
                continue
            seen.add(key)
            found.append(
                ParsedAffectedProductClause(
                    identity=identity,
                    identity_kind=kind,
                    constraint_text=constraint,
                    constraints=parsed,
                    source_field=source_field,
                    original_text=original.strip(),
                )
            )

    for match in _CLAUSE_RE.finditer(blob):
        left = match.group("left") or ""
        prefix = blob[max(0, match.start() - 24) : match.start()]
        _accept(
            constraint=match.group("constraint") or "",
            start=match.start(),
            end=match.end(),
            original=match.group(0),
            identities=_split_clause_identities(left),
            kind="part_number" if _PART_LABEL_RE.search(prefix) else "model",
        )
    for match in _SPACED_CLAUSE_RE.finditer(blob):
        left = match.group("left") or ""
        identities = _split_spaced_identities(left)
        if not identities:
            continue
        prefix = blob[max(0, match.start() - 24) : match.start()]
        _accept(
            constraint=match.group("constraint") or "",
            start=match.start(),
            end=match.end(),
            original=match.group(0),
            identities=identities,
            kind="part_number" if _PART_LABEL_RE.search(prefix) else "model",
        )
    return found


def evidence_from_affected_product_text(
    *,
    texts: list[tuple[str, str]],
    cve_id: str = "",
    advisory_id: str = "",
    source_type: str = "cisa_csv",
    vendor: str = "",
) -> list[ProductEvidence]:
    """Build STRONG_IDENTITY evidence from parseable affected-product clauses."""
    items: list[ProductEvidence] = []
    seen: set[tuple[str, str, str]] = set()
    for source_field, text in texts:
        for clause in parse_affected_product_clauses(
            text,
            source_field=source_field,
            cve_id=cve_id,
            advisory_id=advisory_id,
            source=source_type,
        ):
            key = (clause.identity.upper(), clause.identity_kind, clause.constraint_text.lower())
            if key in seen:
                continue
            seen.add(key)
            dimension = clause.constraints[0].dimension if clause.constraints else ""
            items.append(
                ProductEvidence(
                    cve_id=cve_id,
                    product_name=clause.identity,
                    vendor=vendor,
                    model=clause.identity if clause.identity_kind == "model" else "",
                    part_number=clause.identity if clause.identity_kind == "part_number" else "",
                    identity_kind=clause.identity_kind,
                    source=source_type,
                    provenance=advisory_id,
                    identity_origin=ORIGIN_SOURCE_STATED,
                    evidence_strength=STRONG_IDENTITY,
                    version_constraint=clause.constraint_text,
                    scope=SCOPE_CVE_SPECIFIC if cve_id else "",
                    specificity_notes=["parsed_affected_product_clause", clause.source_field],
                    source_rank=source_rank(source_type),
                    applicability_dimension=dimension,
                    source_field=clause.source_field,
                )
            )
    return items


def _is_bare_product_token(value: str) -> bool:
    text = (value or "").strip()
    if not text or " " in text:
        return False
    if text.upper() in _SPACED_IDENTITY_STOPWORDS:
        return False
    return bool(re.fullmatch(_BARE_PRODUCT, text))


def _split_clause_identities(left: str) -> list[str]:
    parts = [part.strip() for part in (left or "").split("/") if part.strip()]
    if not parts:
        return []
    if any(not (is_discrete_identity_token(part) or _is_bare_product_token(part)) for part in parts):
        return []
    return list(dict.fromkeys(parts))
    parts = [part.strip() for part in (left or "").split("/") if part.strip()]
    if not parts:
        return []
    if any(not is_discrete_identity_token(part) for part in parts):
        return []
    return list(dict.fromkeys(parts))


def _split_spaced_identities(left: str) -> list[str]:
    text = " ".join((left or "").split())
    if not text or is_discrete_identity_token(text):
        return []
    tokens = [part for part in text.split() if part]
    if len(tokens) < 2:
        return []
    if any(token.upper() in _SPACED_IDENTITY_STOPWORDS for token in tokens):
        return []
    if any(not token[:1].isalpha() for token in tokens):
        return []
    return [text]


def _clause_is_ambiguous(blob: str, start: int, end: int, identities: list[str]) -> bool:
    # Neighboring `IDENTITY: constraint` clauses are not a join. Only the prefix
    # before this clause can make the identity assignment ambiguous.
    prefix = blob[max(0, start - 40) : start]
    prefix = _VERSION_JOIN_RE.sub(" ", prefix)
    if _AMBIGUOUS_JOIN_RE.search(prefix) and "/" not in blob[start:end]:
        extras = [
            match.group("id")
            for match in _DISCRETE_ID_RE.finditer(prefix)
            if is_discrete_identity_token(match.group("id")) and match.group("id") not in identities
        ]
        if extras:
            return True
    return False
