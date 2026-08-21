from __future__ import annotations

"""Exact product-binding and conservative remediation actionability.

Defense-only. Does not rank threats, mutate scenario evidence, or use an LLM.
UNKNOWN product binding is not equivalent to UNKNOWN version.
"""

import re
from typing import Any

from rag.scenario.evidence import CandidateEvidence, TruthValue
from rag.utils.text import clean_text, dedupe_preserve_order

SCOPE_PRODUCT_SPECIFIC = "product_specific"
SCOPE_ADVISORY_LEVEL = "advisory_level"

BINDING_MATCH = "match"
BINDING_MISMATCH = "mismatch"
BINDING_UNKNOWN = "unknown"
BINDING_NOT_APPLICABLE = "not_applicable"

ACTIONABLE = "actionable"
INFORMATIONAL = "informational"
SUPPRESS = "suppress"

_EXACT_MATCH_DIMENSIONS = frozenset({"model", "part_number", "product_name", "relationship"})
_VERSION_SUFFIX_RE = re.compile(
    r"\s*:\s*(?:vers:[^\s]+|(?:all\s+)?versions?\b.*|(?:<=?|>=?|=)?\s*v?\d[\d.]*"
    r"(?:\s+and\s+prior.*)?)\s*$",
    flags=re.IGNORECASE,
)
_LEAD_IN_RE = re.compile(
    r"(?:has released the following|take the following|the following"
    r"\s+(?:mitigation|remediation|update|fix)s?(?:\s+measures?|\s+actions?)?"
    r"(?:\s+to\b|:)|recommends that users).*:?\s*$",
    flags=re.IGNORECASE,
)
_BOILERPLATE_RE = re.compile(
    r"best practices|encouraged to apply|apply the risk mitigations|"
    r"for more information|see .{0,120}advisory|suggested security|"
    r"minimize the risk of (?:exploit|exploiting|this vulnerability)",
    flags=re.IGNORECASE,
)
_CONCRETE_ACTION_RE = re.compile(
    r"\b(?:update|upgrade|patch|install|apply|restrict|disable|block|use|"
    r"encrypt|isolate|locate|filter|segment)\b",
    flags=re.IGNORECASE,
)
_PORT_RE = re.compile(r"\bport\s*\(?\s*(\d{1,5})\b", flags=re.IGNORECASE)
_NAMED_FEATURE_RE = re.compile(
    r"\bthe\s+([a-z0-9][a-z0-9_+-]{1,40}(?:\s+[a-z0-9][a-z0-9_+-]{1,40})?)\s+"
    r"(?:object|service|protocol|port|feature)\b",
    flags=re.IGNORECASE,
)


def classify_remediation_scope(product_ids: list[str] | None, scope: str = "") -> str:
    if any(item for item in (product_ids or []) if item):
        return SCOPE_PRODUCT_SPECIFIC
    if scope == SCOPE_PRODUCT_SPECIFIC:
        return SCOPE_PRODUCT_SPECIFIC
    if scope == SCOPE_ADVISORY_LEVEL:
        return SCOPE_ADVISORY_LEVEL
    return SCOPE_ADVISORY_LEVEL


def is_product_scoped(product_ids: list[str] | None, scope: str = "") -> bool:
    return classify_remediation_scope(product_ids, scope) == SCOPE_PRODUCT_SPECIFIC


def canonical_product_identity(value: str | None) -> str:
    text = clean_text(value)
    if not text:
        return ""
    stripped = _VERSION_SUFFIX_RE.sub("", text).strip() or text
    return re.sub(r"\s+", " ", stripped).casefold()


def selected_canonical_identities(candidate: CandidateEvidence | None) -> set[str]:
    if candidate is None:
        return set()
    identities: list[str] = []
    for check in candidate.checks:
        if check.name in {"product", "model", "part_number", "product_name"}:
            identities.extend(_split_identity_label(check.observed))
            if check.name in {"part_number", "model"}:
                identities.extend(_split_identity_label(check.required))
    for trace in candidate.product_evidence_trace:
        if not isinstance(trace, dict):
            continue
        for key in ("product_name", "model", "part_number"):
            identities.extend(_split_identity_label(str(trace.get(key) or "")))
    return {item for item in (canonical_product_identity(value) for value in identities) if item}


def bindable_selected_product_ids(
    candidate: CandidateEvidence | None,
    product_index: dict[str, dict[str, Any]] | None,
) -> list[str]:
    raw = _trace_product_ids(candidate)
    identities = selected_canonical_identities(candidate)
    if not identities or not product_index:
        return raw
    bindable: list[str] = []
    for product_id in raw:
        entry = product_index.get(product_id)
        if entry is None:
            bindable.append(product_id)
            continue
        if entry_matches_selected_identity(entry, identities):
            bindable.append(product_id)
    return dedupe_preserve_order(bindable)


def entry_matches_selected_identity(
    entry: dict[str, Any],
    selected_identities: set[str],
) -> bool:
    if not selected_identities:
        return False
    resolved = resolved_identities(entry)
    return bool(resolved & selected_identities)


def resolved_identities(entry: dict[str, Any] | None) -> set[str]:
    if not entry:
        return set()
    values = [
        entry.get("product"),
        entry.get("model"),
        entry.get("part_number"),
        entry.get("source_stated_model"),
        entry.get("source_stated_part"),
        entry.get("name"),
    ]
    return {item for item in (canonical_product_identity(str(value or "")) for value in values) if item}


def bind_product_scope(
    *,
    product_ids: list[str],
    selected_ids: list[str],
    product_index: dict[str, dict[str, Any]] | None,
    candidate: CandidateEvidence | None,
    scope: str = "",
) -> tuple[str, TruthValue, str]:
    """Return (binding, truth value, reason) for a remediation row."""
    if not is_product_scoped(product_ids, scope):
        return (
            BINDING_NOT_APPLICABLE,
            TruthValue.TRUE,
            "remediation is not product-scoped",
        )
    scoped = dedupe_preserve_order([item for item in product_ids if item])
    if not scoped:
        return (
            BINDING_UNKNOWN,
            TruthValue.UNKNOWN,
            "product-specific remediation has no bound product identifiers",
        )
    bindable = dedupe_preserve_order([item for item in selected_ids if item])
    if _ids_overlap(scoped, bindable):
        return (
            BINDING_MATCH,
            TruthValue.TRUE,
            "remediation product_ids overlap selected product evidence",
        )
    identities = selected_canonical_identities(candidate)
    index = product_index or {}
    matched_ids = [
        product_id
        for product_id in scoped
        if entry_matches_selected_identity(index.get(product_id) or {}, identities)
    ]
    if matched_ids:
        return (
            BINDING_MATCH,
            TruthValue.TRUE,
            "remediation product identity matches selected product",
        )
    if identities and index:
        sibling_ids = [
            product_id
            for product_id, entry in index.items()
            if product_id not in scoped and entry_matches_selected_identity(entry, identities)
        ]
        if sibling_ids:
            return (
                BINDING_MISMATCH,
                TruthValue.FALSE,
                "remediation product_ids conflict with selected product evidence",
            )
    if bindable:
        return (
            BINDING_MISMATCH,
            TruthValue.FALSE,
            "remediation product_ids conflict with selected product evidence",
        )
    return (
        BINDING_UNKNOWN,
        TruthValue.UNKNOWN,
        "remediation product_ids cannot be related to selected product evidence",
    )


def deployment_context(candidate: CandidateEvidence | None) -> str:
    if candidate is None:
        return ""
    parts: list[str] = []
    for check in candidate.checks:
        parts.extend([check.observed, check.required])
    for trace in candidate.product_evidence_trace:
        if not isinstance(trace, dict):
            continue
        for key in ("product_name", "model", "part_number", "version_constraint"):
            parts.append(str(trace.get(key) or ""))
    return " ".join(part for part in parts if part)


def feature_scope_status(details: str, context: str, *, product_scoped: bool) -> tuple[TruthValue, str]:
    features = _feature_tokens(details)
    if not features:
        return TruthValue.TRUE, "remediation is not feature-scoped"
    if not product_scoped:
        return TruthValue.TRUE, "advisory-level remediation does not require feature binding"
    blob = canonical_product_identity(context)
    if any(_feature_in_deployment(token, blob, context) for token in features):
        return TruthValue.TRUE, "feature or service is present in the selected deployment"
    return (
        TruthValue.UNKNOWN,
        "feature or service binding to the selected deployment is unknown",
    )


def classify_actionability(
    *,
    details: str,
    category: str,
    scope: str,
    product_ids: list[str] | None = None,
    deployment: str = "",
) -> str:
    text = clean_text(details)
    if not text:
        return SUPPRESS
    if _is_lead_in(text) or _is_boilerplate(text):
        return INFORMATIONAL
    product_scoped = is_product_scoped(product_ids, scope)
    feature_status, _reason = feature_scope_status(text, deployment, product_scoped=product_scoped)
    if product_scoped and feature_status == TruthValue.UNKNOWN:
        return SUPPRESS
    if category == "vendor_fix" and _CONCRETE_ACTION_RE.search(text):
        return ACTIONABLE
    if _CONCRETE_ACTION_RE.search(text):
        return ACTIONABLE
    return INFORMATIONAL


def normalize_details(details: str) -> str:
    return re.sub(r"\s+", " ", clean_text(details)).casefold()


def _trace_product_ids(candidate: CandidateEvidence | None) -> list[str]:
    if candidate is None:
        return []
    ids: list[str] = []
    for trace in candidate.product_evidence_trace:
        if not isinstance(trace, dict):
            continue
        product_id = str(trace.get("product_id") or "").strip()
        if not product_id:
            continue
        polarity = str(trace.get("polarity") or "POSITIVE")
        strength = str(trace.get("evidence_strength") or "")
        if polarity == "NEGATIVE" or strength == "NEGATIVE":
            continue
        if str(trace.get("conflicting_evidence") or ""):
            continue
        matched = str(trace.get("matched_dimension") or "")
        if matched not in _EXACT_MATCH_DIMENSIONS:
            continue
        ids.append(product_id)
    return dedupe_preserve_order(ids)


def _split_identity_label(value: str | None) -> list[str]:
    text = clean_text(value)
    if not text:
        return []
    return [part.strip() for part in text.split("|") if part.strip()]


def _ids_overlap(left: list[str], right: list[str]) -> bool:
    right_set = set(right)
    return any(item in right_set for item in left)


def _is_lead_in(text: str) -> bool:
    stripped = text.strip()
    if stripped.endswith(":") and not re.search(r"[.!?].+", stripped):
        return True
    return bool(_LEAD_IN_RE.search(stripped))


def _is_boilerplate(text: str) -> bool:
    if not _BOILERPLATE_RE.search(text):
        return False
    if _CONCRETE_ACTION_RE.search(text) and not _is_lead_in(text):
        # Concrete control plus a boilerplate clause stays actionable unless
        # the whole paragraph is only encouragement/see-also text.
        if re.search(r"\b(?:restrict|disable|block|encrypt|isolate|update|upgrade|patch|install)\b", text, flags=re.I):
            return False
        if re.search(r"\buse\b.+\b(?:firewall|vpn|lan|network)\b", text, flags=re.I):
            return False
    return True


def _feature_tokens(details: str) -> list[str]:
    tokens: list[str] = []
    for match in _PORT_RE.finditer(details or ""):
        tokens.append(f"port {match.group(1)}")
    for match in _NAMED_FEATURE_RE.finditer(details or ""):
        tokens.append(match.group(1).strip())
    return dedupe_preserve_order(tokens)


def _feature_in_deployment(token: str, canonical_blob: str, raw_context: str) -> bool:
    needle = canonical_product_identity(token)
    if not needle:
        return False
    blob = f"{canonical_blob} {canonical_product_identity(raw_context)}".strip()
    if needle in blob:
        return True
    compact = re.sub(r"[^a-z0-9]+", "", needle)
    compact_blob = re.sub(r"[^a-z0-9]+", "", blob)
    return bool(compact) and compact in compact_blob
