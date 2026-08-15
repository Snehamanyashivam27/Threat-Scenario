from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Iterable

from rag.scenario.evidence import TruthValue
from rag.scenario.models import ComponentModel

STRONG_IDENTITY = "STRONG_IDENTITY"
SOURCE_MEMBERSHIP = "SOURCE_MEMBERSHIP"
WEAK_DISCOVERY = "WEAK_DISCOVERY"
NEGATIVE = "NEGATIVE"
NONE = "NONE"

POLARITY_POSITIVE = "POSITIVE"
POLARITY_NEGATIVE = "NEGATIVE"

ORIGIN_PRODUCT_TREE = "product_tree_resolved"
ORIGIN_VULNERABILITY_LOCAL = "vulnerability_local"
ORIGIN_ADVISORY_AGGREGATE = "advisory_aggregate"
ORIGIN_SOURCE_STATED = "source_stated"

SCOPE_CVE_SPECIFIC = "cve_specific"
SCOPE_ADVISORY_AGGREGATE = "advisory_aggregate"

NOTE_VECTOR_SHARED = "product_status_vector_shared"

POSITIVE_MEMBERSHIP_STATUS = frozenset({"known_affected", "first_affected", "last_affected"})
NEGATIVE_MEMBERSHIP_STATUS = frozenset({"known_not_affected"})

_WEAK_IDENTITY_TOKENS = frozenset(
    {
        "firmware",
        "variant",
        "variants",
        "version",
        "versions",
        "series",
        "device",
        "devices",
        "system",
        "module",
        "modules",
        "product",
        "products",
        "software",
        "component",
        "components",
        "family",
        "line",
        "all",
        "central",
        "processing",
        "communication",
        "controller",
        "firmware",
        "base",
        "guest",
        "role",
        "slave",
        "master",
        "industrial",
        "ethernet",
        "switch",
        "affected",
        "prior",
        "later",
        "vendor",
        "brand",
    }
)
_VERSION_LIKE_RE = re.compile(r"^v?\d+(?:\.\d+)*$")

EXPLICIT_RELATIONSHIPS = frozenset(
    {
        "contains",
        "contained-in",
        "contained_in",
        "installed-on",
        "installed_on",
        "includes",
        "is",
    }
)

_EVIDENCE_BLOCK_RE = re.compile(
    r"--- Product Evidence ---\s*(.*?)\s*--- End Product Evidence ---",
    flags=re.DOTALL | re.IGNORECASE,
)
_COMPACT_EVIDENCE_RE = re.compile(r"ProductEvidence\[(.*?)\]")
_EVIDENCE_FIELD_LABELS = (
    "Source",
    "Provenance",
    "Scope",
    "Product ID",
    "Identity Origin",
    "Evidence Strength",
    "Polarity",
    "Relationship Type",
    "Version Constraint",
    "Product Name",
    "Vendor",
    "Family",
    "Model",
    "Part Number",
    "Specificity",
)
_RELATIONSHIP_IN_TEXT_RE = re.compile(
    r"\b(contains|contained\s+in|installed[-_ ]on|includes)\b",
    flags=re.IGNORECASE,
)
_IS_RELATIONSHIP_RE = re.compile(
    r"\bis\s+(?!affected\b|vulnerable\b|required\b|disabled\b|enabled\b|used\b)",
    flags=re.IGNORECASE,
)


@dataclass(slots=True)
class ProductEvidence:
    cve_id: str = ""
    product_name: str = ""
    vendor: str = ""
    family: str = ""
    model: str = ""
    part_number: str = ""
    product_id: str = ""
    relationship_type: str = ""
    identity_kind: str = ""
    source: str = ""
    provenance: str = ""
    identity_origin: str = ""
    evidence_strength: str = NONE
    polarity: str = POLARITY_POSITIVE
    version_constraint: str = ""
    scope: str = ""
    specificity_notes: list[str] = field(default_factory=list)
    source_rank: int = 100

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ProductEvidence:
        if not data:
            return cls()
        notes = data.get("specificity_notes") or []
        if isinstance(notes, str):
            notes = [item.strip() for item in notes.split(",") if item.strip()]
        return cls(
            cve_id=str(data.get("cve_id") or ""),
            product_name=str(data.get("product_name") or ""),
            vendor=str(data.get("vendor") or ""),
            family=str(data.get("family") or ""),
            model=str(data.get("model") or ""),
            part_number=str(data.get("part_number") or ""),
            product_id=str(data.get("product_id") or ""),
            relationship_type=str(data.get("relationship_type") or ""),
            identity_kind=str(data.get("identity_kind") or ""),
            source=str(data.get("source") or ""),
            provenance=str(data.get("provenance") or ""),
            identity_origin=str(data.get("identity_origin") or ""),
            evidence_strength=str(data.get("evidence_strength") or NONE),
            polarity=str(data.get("polarity") or POLARITY_POSITIVE),
            version_constraint=str(data.get("version_constraint") or ""),
            scope=str(data.get("scope") or ""),
            specificity_notes=list(notes),
            source_rank=int(data.get("source_rank") or 100),
        )


@dataclass(slots=True)
class ProductEvidenceTrace:
    source: str
    provenance: str
    scope: str
    identity_origin: str
    evidence_strength: str
    polarity: str
    matched_dimension: str
    corroborating_evidence: str
    conflicting_evidence: str
    final_product_state: str
    product_id: str = ""
    relationship_type: str = ""
    version_constraint: str = ""
    specificity_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ProductApplicabilityDecision:
    product_match: TruthValue
    family_match: TruthValue
    model_match: TruthValue
    part_number_match: TruthValue
    product_name_match: TruthValue
    relationship_match: TruthValue
    source_affected_products: list[str]
    input_identity: str
    matched_source_product: str = ""
    matched_dimension: str = ""
    rejection_reason: str = ""
    has_conflicting_evidence: bool = False
    traces: list[ProductEvidenceTrace] = field(default_factory=list)
    corroborating: list[str] = field(default_factory=list)
    conflicting: list[str] = field(default_factory=list)


Matcher = Callable[[str, str, ComponentModel], tuple[bool, str, str]]


def source_rank(source: str) -> int:
    ranks = {
        "cisa_csaf": 0,
        "cisa_ics_advisory": 1,
        "cisa_csv": 2,
    }
    return ranks.get((source or "").lower(), 50)


def normalize_relationship_type(value: str) -> str:
    text = re.sub(r"\s+", "-", (value or "").strip().lower().replace("_", "-"))
    if text in EXPLICIT_RELATIONSHIPS:
        return text
    return (value or "").strip()


def relationship_type_from_text(text: str) -> str:
    match = _RELATIONSHIP_IN_TEXT_RE.search(text or "")
    if match:
        return normalize_relationship_type(match.group(1))
    if _IS_RELATIONSHIP_RE.search(text or ""):
        return "is"
    return ""


def match_blob(item: ProductEvidence) -> str:
    parts = [item.product_name]
    if item.model and item.model not in (item.product_name or ""):
        parts.append(item.model)
    if item.relationship_type:
        parts.append(item.relationship_type.replace("_", "-"))
    return " ".join(part for part in parts if part).strip()


def format_product_evidence_blocks(items: Iterable[ProductEvidence | dict[str, Any]]) -> str:
    blocks: list[str] = []
    for raw in items:
        item = raw if isinstance(raw, ProductEvidence) else ProductEvidence.from_dict(raw)
        fields = [
            f"source={item.source}",
            f"provenance={item.provenance}",
            f"scope={item.scope}",
            f"product_id={item.product_id}",
            f"identity_origin={item.identity_origin}",
            f"evidence_strength={item.evidence_strength}",
            f"polarity={item.polarity}",
            f"relationship_type={item.relationship_type}",
            f"version_constraint={item.version_constraint}",
            f"product_name={item.product_name}",
            f"vendor={item.vendor}",
            f"family={item.family}",
            f"model={item.model}",
            f"part_number={item.part_number}",
            f"specificity={','.join(item.specificity_notes)}",
        ]
        blocks.append("ProductEvidence[" + "||".join(fields) + "]")
    return " ".join(blocks)


def _evidence_from_field_map(fields: dict[str, str], default_cve: str) -> ProductEvidence:
    notes = [part.strip() for part in (fields.get("specificity") or "").split(",") if part.strip()]
    return ProductEvidence(
        cve_id=default_cve,
        product_name=fields.get("product name") or fields.get("product_name") or fields.get("product") or "",
        vendor=fields.get("vendor") or "",
        family=fields.get("family") or "",
        model=fields.get("model") or "",
        part_number=fields.get("part number") or fields.get("part_number") or "",
        product_id=fields.get("product id") or fields.get("product_id") or "",
        relationship_type=normalize_relationship_type(
            fields.get("relationship type") or fields.get("relationship_type") or ""
        ),
        source=fields.get("source") or "",
        provenance=fields.get("provenance") or "",
        identity_origin=fields.get("identity origin") or fields.get("identity_origin") or "",
        evidence_strength=fields.get("evidence strength") or fields.get("evidence_strength") or NONE,
        polarity=fields.get("polarity") or POLARITY_POSITIVE,
        version_constraint=fields.get("version constraint") or fields.get("version_constraint") or "",
        scope=fields.get("scope") or "",
        specificity_notes=notes,
        source_rank=source_rank(fields.get("source") or ""),
    )


def _fields_from_labeled_text(raw: str) -> dict[str, str]:
    label_pattern = "|".join(re.escape(label) for label in _EVIDENCE_FIELD_LABELS)
    pattern = re.compile(
        rf"({label_pattern}):\s*(.*?)(?=\s+(?:{label_pattern}):|$)",
        flags=re.IGNORECASE | re.DOTALL,
    )
    fields: dict[str, str] = {}
    for match in pattern.finditer(raw or ""):
        fields[match.group(1).strip().lower()] = re.sub(r"\s+", " ", match.group(2)).strip()
    return fields


def parse_product_evidence_blocks(text: str, *, default_cve: str = "") -> list[ProductEvidence]:
    items: list[ProductEvidence] = []
    for raw in _COMPACT_EVIDENCE_RE.findall(text or ""):
        fields: dict[str, str] = {}
        for part in raw.split("||"):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            fields[key.strip().lower()] = value.strip()
        items.append(_evidence_from_field_map(fields, default_cve))
    for raw in _EVIDENCE_BLOCK_RE.findall(text or ""):
        items.append(_evidence_from_field_map(_fields_from_labeled_text(raw), default_cve))
    return items


def membership_binding_provenance(advisory_id: str, status_key: str) -> str:
    key = re.sub(r"[^a-z_]+", "", (status_key or "").strip().lower().replace("-", "_"))
    binding = f"product_status.{key}" if key else ""
    advisory = (advisory_id or "").strip()
    if advisory and binding:
        return f"{advisory}::{binding}"
    return binding or advisory


def membership_status_from_provenance(text: str) -> str:
    blob = (text or "").lower().replace("-", "_")
    for key in (*NEGATIVE_MEMBERSHIP_STATUS, *POSITIVE_MEMBERSHIP_STATUS):
        if f"product_status.{key}" in blob:
            return key
        if re.search(rf"(?<![a-z_]){key}(?![a-z_])", blob):
            return key
    return ""


def evidence_from_csaf_product(
    *,
    cve_id: str,
    advisory_id: str,
    product: dict[str, Any],
    polarity: str,
    strength: str,
    relationship_type: str = "",
    version_constraint: str = "",
    specificity_notes: list[str] | None = None,
    status_key: str = "",
) -> ProductEvidence:
    helper_model = str(product.get("source_stated_model") or "")
    helper_part = str(product.get("source_stated_part") or "")
    rel = normalize_relationship_type(relationship_type or str(product.get("relationship_type") or ""))
    item_strength = strength
    if polarity == POLARITY_NEGATIVE:
        item_strength = NEGATIVE
    elif rel in EXPLICIT_RELATIONSHIPS:
        item_strength = STRONG_IDENTITY
    return ProductEvidence(
        cve_id=cve_id,
        product_name=str(product.get("name") or product.get("product") or ""),
        vendor=str(product.get("vendor") or ""),
        family=str(product.get("product_family") or ""),
        model=helper_model,
        part_number=helper_part,
        product_id=str(product.get("product_id") or ""),
        relationship_type=rel,
        identity_kind="relationship" if rel else "product",
        source="cisa_csaf",
        provenance=membership_binding_provenance(advisory_id, status_key) or advisory_id,
        identity_origin=ORIGIN_PRODUCT_TREE,
        evidence_strength=item_strength,
        polarity=polarity,
        version_constraint=version_constraint or str(product.get("version") or ""),
        scope=SCOPE_CVE_SPECIFIC,
        specificity_notes=list(specificity_notes or []),
        source_rank=source_rank("cisa_csaf"),
    )


def evidence_from_csv_product(
    *,
    cve_id: str,
    advisory_id: str,
    product_name: str,
    vendor: str = "",
    family: str = "",
    source: str = "cisa_csv",
) -> ProductEvidence:
    return ProductEvidence(
        cve_id=cve_id,
        product_name=product_name,
        vendor=vendor,
        family=family,
        source=source,
        provenance=advisory_id,
        identity_origin=ORIGIN_ADVISORY_AGGREGATE,
        evidence_strength=WEAK_DISCOVERY,
        polarity=POLARITY_POSITIVE,
        scope=SCOPE_ADVISORY_AGGREGATE,
        source_rank=source_rank(source),
    )


def synthesize_evidence_from_fields(
    *,
    cve_id: str,
    advisory_id: str,
    source_type: str,
    vendor: str,
    product: str,
    product_family: str,
    model: str,
    part_number: str,
    affected_products: list[str],
    constraints: list[tuple[str, str, str]],
) -> list[ProductEvidence]:
    """Fallback when serialized Product Evidence blocks are absent."""
    items: list[ProductEvidence] = []
    names = [name for name in affected_products if name]
    if product and product not in names:
        names.insert(0, product)
    if not names and (model or part_number):
        names = [product or model or part_number]
    is_csaf = source_type == "cisa_csaf"
    constraint_map = {name: (version, part) for name, version, part in constraints if name}
    for name in names:
        version, constraint_part = constraint_map.get(name, ("", ""))
        rel = relationship_type_from_text(name)
        stated_model = model if model and (model.lower() in name.lower() or not names or name == product) else ""
        stated_part = part_number or constraint_part
        if rel:
            strength = STRONG_IDENTITY
            origin = ORIGIN_SOURCE_STATED
        elif stated_model or stated_part:
            strength = STRONG_IDENTITY
            origin = ORIGIN_SOURCE_STATED
        elif is_csaf:
            strength = SOURCE_MEMBERSHIP
            origin = ORIGIN_SOURCE_STATED
        else:
            strength = WEAK_DISCOVERY
            origin = ORIGIN_ADVISORY_AGGREGATE
        items.append(
            ProductEvidence(
                cve_id=cve_id,
                product_name=name,
                vendor=vendor,
                family=product_family,
                model=stated_model,
                part_number=stated_part,
                relationship_type=rel,
                identity_kind="relationship" if rel else "product",
                source=source_type,
                provenance=advisory_id,
                identity_origin=origin,
                evidence_strength=strength,
                polarity=POLARITY_POSITIVE,
                version_constraint=version,
                scope=SCOPE_CVE_SPECIFIC if is_csaf else SCOPE_ADVISORY_AGGREGATE,
                source_rank=source_rank(source_type),
            )
        )
    return items


def merge_product_evidence(*groups: Iterable[ProductEvidence]) -> list[ProductEvidence]:
    merged: list[ProductEvidence] = []
    seen: set[tuple[str, str, str, str, str, str]] = set()
    for group in groups:
        for item in group:
            key = (
                item.source,
                item.provenance,
                item.product_id,
                item.product_name,
                item.evidence_strength,
                item.polarity,
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)
    return merged


def _same_dimension(item: ProductEvidence, match_kind: str) -> bool:
    if match_kind == "part_number":
        return bool(item.part_number)
    if match_kind == "model":
        return bool(item.model)
    if match_kind == "relationship":
        return normalize_relationship_type(item.relationship_type) in EXPLICIT_RELATIONSHIPS
    if match_kind == "product_name":
        return item.evidence_strength == STRONG_IDENTITY and bool(item.product_name)
    return False


def _specific_identity_tokens(*texts: str | None) -> set[str]:
    tokens: set[str] = set()
    for text in texts:
        for raw in re.findall(r"[A-Za-z0-9][A-Za-z0-9._-]*", text or ""):
            norm = re.sub(r"[^a-z0-9]+", "", raw.lower())
            if len(norm) < 2 or norm in _WEAK_IDENTITY_TOKENS:
                continue
            if not re.search(r"\d", norm):
                continue
            if _VERSION_LIKE_RE.fullmatch(norm):
                continue
            tokens.add(norm)
    return tokens


def _sufficiently_specific_product_match(
    component: ComponentModel,
    item: ProductEvidence,
    match_kind: str,
) -> bool:
    if match_kind not in {"product_name", "model", "part_number"}:
        return False
    if match_kind == "part_number":
        needed = _specific_identity_tokens(component.part_number)
    elif match_kind == "model":
        needed = _specific_identity_tokens(component.model)
    else:
        needed = _specific_identity_tokens(component.name)
    if not needed:
        needed = _specific_identity_tokens(
            component.name,
            component.model,
            component.part_number,
        )
    if not needed:
        return False
    evidence_tokens = _specific_identity_tokens(
        item.product_name,
        item.model,
        item.part_number,
        match_blob(item),
    )
    evidence_blob = re.sub(
        r"[^a-z0-9]+",
        "",
        " ".join([item.product_name, item.model, item.part_number, match_blob(item)]).lower(),
    )
    return all(token in evidence_tokens or token in evidence_blob for token in needed)


def _has_explicit_positive_affected_membership(item: ProductEvidence) -> bool:
    if item.scope != SCOPE_CVE_SPECIFIC:
        return False
    if (item.polarity or POLARITY_POSITIVE) != POLARITY_POSITIVE:
        return False
    if (item.evidence_strength or NONE) not in {SOURCE_MEMBERSHIP, STRONG_IDENTITY}:
        return False
    status = membership_status_from_provenance(
        " ".join([item.provenance, *item.specificity_notes])
    )
    return status in POSITIVE_MEMBERSHIP_STATUS


def _independent_corroboration(
    item: ProductEvidence,
    match_kind: str,
    positive_hits: list[tuple[ProductEvidence, str]],
) -> str:
    reasons: list[str] = []
    other_sources = {
        other.source
        for other, _kind in positive_hits
        if other.source and other.source != item.source
    }
    if other_sources:
        reasons.append(f"independent_source:{sorted(other_sources)[0]}")
    if (
        normalize_relationship_type(item.relationship_type) in EXPLICIT_RELATIONSHIPS
        and match_kind == "relationship"
    ):
        reasons.append(f"explicit_relationship:{item.relationship_type}")
    if item.identity_origin == ORIGIN_VULNERABILITY_LOCAL and match_kind in {"model", "part_number"}:
        reasons.append("vulnerability_local_identifier")
    return "; ".join(reasons)


def decide_product_applicability(
    component: ComponentModel | None,
    evidence_items: list[ProductEvidence],
    matcher: Matcher,
    *,
    input_identity: str = "",
    family_match: TruthValue = TruthValue.UNKNOWN,
) -> ProductApplicabilityDecision:
    source_products = [item.product_name for item in evidence_items if item.product_name]
    if component is None:
        return ProductApplicabilityDecision(
            product_match=TruthValue.UNKNOWN,
            family_match=TruthValue.UNKNOWN,
            model_match=TruthValue.UNKNOWN,
            part_number_match=TruthValue.UNKNOWN,
            product_name_match=TruthValue.UNKNOWN,
            relationship_match=TruthValue.UNKNOWN,
            source_affected_products=source_products,
            input_identity=input_identity,
            rejection_reason="The target component is unavailable.",
        )

    strong_hits: list[tuple[ProductEvidence, str, str]] = []
    membership_hits: list[tuple[ProductEvidence, str, str]] = []
    weak_hits: list[tuple[ProductEvidence, str, str]] = []
    negative_hits: list[tuple[ProductEvidence, str, str]] = []
    mismatches: list[tuple[ProductEvidence, str]] = []
    insufficient: list[ProductEvidence] = []
    traces: list[ProductEvidenceTrace] = []

    for item in evidence_items:
        blob = match_blob(item)
        matched, match_kind, matched_product = matcher(blob, item.part_number, component)
        polarity = item.polarity or POLARITY_POSITIVE
        strength = item.evidence_strength or NONE
        if polarity == POLARITY_NEGATIVE or strength == NEGATIVE:
            if matched:
                negative_hits.append((item, match_kind, matched_product))
            continue
        if matched:
            if strength == STRONG_IDENTITY and _same_dimension(item, match_kind):
                strong_hits.append((item, match_kind, matched_product))
            elif strength == SOURCE_MEMBERSHIP:
                membership_hits.append((item, match_kind, matched_product))
            elif strength == WEAK_DISCOVERY:
                weak_hits.append((item, match_kind, matched_product))
            elif strength == STRONG_IDENTITY:
                membership_hits.append((item, match_kind, matched_product))
        elif match_kind == "conflict":
            mismatches.append((item, matched_product))
        elif match_kind == "insufficient":
            insufficient.append(item)

    positive_hits = [
        (item, kind)
        for item, kind, _product in strong_hits + membership_hits + weak_hits
    ]
    corroborating: list[str] = []
    corroborated_membership: list[tuple[ProductEvidence, str, str]] = []
    specific_membership: list[tuple[ProductEvidence, str, str]] = []
    for item, kind, product in membership_hits:
        specific = _sufficiently_specific_product_match(component, item, kind)
        if _has_explicit_positive_affected_membership(item) and specific:
            specific_membership.append((item, kind, product))
            corroborating.append("cve_specific_affected_product_membership")
        reason = _independent_corroboration(item, kind, positive_hits)
        if reason and specific:
            corroborating.append(reason)
            corroborated_membership.append((item, kind, product))

    conflicting_labels = [
        f"{item.source}:{item.polarity}:{item.product_name}"
        for item, _kind, _product in negative_hits
    ]
    authoritative_positive = bool(strong_hits or corroborated_membership or specific_membership)
    has_conflict = bool(authoritative_positive and negative_hits)

    model_match = TruthValue.UNKNOWN
    part_match = TruthValue.UNKNOWN
    name_match = TruthValue.UNKNOWN
    relationship_match = TruthValue.UNKNOWN
    matched_source = ""
    matched_dimension = ""

    winning = strong_hits or specific_membership or corroborated_membership or membership_hits or weak_hits
    if winning:
        matched_source = winning[0][2]
        matched_dimension = winning[0][1]
        kinds = {kind for _item, kind, _product in winning}
        if "model" in kinds:
            model_match = TruthValue.TRUE
        if "part_number" in kinds:
            part_match = TruthValue.TRUE
        if "product_name" in kinds:
            name_match = TruthValue.TRUE
        if "relationship" in kinds:
            relationship_match = TruthValue.TRUE
    elif mismatches:
        model_match = TruthValue.FALSE

    if has_conflict:
        product_match = TruthValue.CONFLICT
        rejection_reason = "Positive authoritative product evidence conflicts with known_not_affected evidence."
    elif negative_hits and not (strong_hits or corroborated_membership or membership_hits):
        product_match = TruthValue.FALSE
        rejection_reason = "Source lists the deployed product as known_not_affected."
        matched_source = negative_hits[0][2]
        matched_dimension = negative_hits[0][1]
    elif strong_hits:
        product_match = TruthValue.TRUE
        rejection_reason = ""
    elif specific_membership:
        product_match = TruthValue.TRUE
        rejection_reason = ""
    elif corroborated_membership:
        product_match = TruthValue.TRUE
        rejection_reason = ""
    elif membership_hits:
        product_match = TruthValue.UNKNOWN
        rejection_reason = "Source membership matched without a sufficiently specific product identity."
    elif weak_hits:
        product_match = TruthValue.UNKNOWN
        rejection_reason = "Only weak discovery product evidence was available."
    elif insufficient:
        product_match = TruthValue.UNKNOWN
        rejection_reason = "Shared firmware or component label is not exact product identity."
    elif mismatches:
        product_match = TruthValue.FALSE
        rejection_reason = "Scenario model/part/product does not match the advisory affected product."
    elif family_match == TruthValue.TRUE:
        product_match = TruthValue.UNKNOWN
        rejection_reason = "Only vendor or family evidence matched; exact product identity is required."
    else:
        product_match = TruthValue.UNKNOWN
        rejection_reason = "Scenario product identity is missing or unproven."

    # Family/vendor-only evidence must never become TRUE.
    if product_match == TruthValue.TRUE and not (
        strong_hits or corroborated_membership or specific_membership
    ):
        product_match = TruthValue.UNKNOWN

    final_label = {
        TruthValue.TRUE: "TRUE",
        TruthValue.FALSE: "FALSE",
        TruthValue.UNKNOWN: "UNKNOWN",
        TruthValue.CONFLICT: "CONFLICTING_EVIDENCE",
    }[product_match]

    for item in evidence_items:
        hit = next(
            (
                (kind, product)
                for other, kind, product in strong_hits + membership_hits + weak_hits + negative_hits
                if other is item
            ),
            ("", ""),
        )
        item_corroboration = next(
            (
                _independent_corroboration(other, kind, positive_hits)
                or (
                    "cve_specific_affected_product_membership"
                    if _has_explicit_positive_affected_membership(other)
                    and _sufficiently_specific_product_match(component, other, kind)
                    else ""
                )
                for other, kind, _product in membership_hits
                if other is item
            ),
            "",
        )
        item_conflict = ""
        if any(other is item for other, _kind, _product in negative_hits) and authoritative_positive:
            item_conflict = "contradictory_negative"
        elif any(other is item for other, _product in mismatches):
            item_conflict = "sibling_or_identity_mismatch"
        traces.append(
            ProductEvidenceTrace(
                source=item.source,
                provenance=item.provenance,
                scope=item.scope,
                identity_origin=item.identity_origin,
                evidence_strength=item.evidence_strength,
                polarity=item.polarity,
                matched_dimension=hit[0],
                corroborating_evidence=item_corroboration,
                conflicting_evidence=item_conflict,
                final_product_state=final_label,
                product_id=item.product_id,
                relationship_type=item.relationship_type,
                version_constraint=item.version_constraint,
                specificity_notes=list(item.specificity_notes),
            )
        )

    return ProductApplicabilityDecision(
        product_match=product_match,
        family_match=family_match,
        model_match=model_match,
        part_number_match=part_match,
        product_name_match=name_match,
        relationship_match=relationship_match,
        source_affected_products=source_products,
        input_identity=input_identity,
        matched_source_product=matched_source,
        matched_dimension=matched_dimension,
        rejection_reason=rejection_reason,
        has_conflicting_evidence=has_conflict,
        traces=traces,
        corroborating=corroborating,
        conflicting=conflicting_labels,
    )


def format_product_evidence_debug(traces: list[ProductEvidenceTrace]) -> str:
    if not traces:
        return "Product Evidence:\n- (none)"
    lines = ["Product Evidence:"]
    for item in traces:
        lines.extend(
            [
                f"- source: {item.source or '-'}",
                f"  provenance: {item.provenance or '-'}",
                f"  scope: {item.scope or '-'}",
                f"  identity_origin: {item.identity_origin or '-'}",
                f"  evidence_strength: {item.evidence_strength or '-'}",
                f"  polarity: {item.polarity or '-'}",
                f"  matched dimension: {item.matched_dimension or '-'}",
                f"  corroborating evidence: {item.corroborating_evidence or '-'}",
                f"  conflicting evidence: {item.conflicting_evidence or '-'}",
                f"  final product state: {item.final_product_state}",
            ]
        )
    return "\n".join(lines)
