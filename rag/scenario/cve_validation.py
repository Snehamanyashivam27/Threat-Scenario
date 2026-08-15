from __future__ import annotations

# RETRIEVAL FINDS CANDIDATES.
# CANONICAL EVIDENCE DEFINES FACTS.
# VALIDATION DETERMINES APPLICABILITY.
# EFFECT COMPATIBILITY DETERMINES WHETHER A CVE EXPLAINS A STEP.
# STEP SELECTION CHOOSES THE BEST CANDIDATE.
# THE LLM ONLY NARRATES THE RESULT.
#
# PRODUCT MATCH != STEP APPLICABILITY.
# UNKNOWN != FALSE.
# UNKNOWN EFFECT != PROOF OF A SPECIFIC ATTACK CAPABILITY.
#
# CVE METADATA MUST NEVER LEAK BETWEEN CVES.
# A SELECTED CVE MUST NEVER DISAPPEAR WITHOUT AN AUDITABLE REASON.

import re
from dataclasses import dataclass, field

from rag.models.answer import SourceReference
from rag.retrieval.document_fields import extract_cves, extract_fields
from rag.retrieval.identifier_lookup import extract_cwes
from rag.scenario.canonical_cve import (
    condition_text_for_constraint,
    isolate_cwes_for_cve,
    parse_constraint_text,
)
from rag.scenario.applicability import (
    FinalStatus,
    classify_step_objective,
    compute_final_status,
    compute_rank_score,
    disposition_from_final_status,
    effect_supports_objective,
    enrich_auth_from_description,
    effect_blocked_for_objective,
    extract_required_service,
    extract_vulnerability_effects,
    gate_table,
)
from rag.scenario.evidence import ApplicabilityCheck, CandidateEvidence, TruthValue
from rag.scenario.models import AttackStep, ComponentModel, ScenarioBundle, StepEnrichment
from rag.scenario.product_evidence import (
    ProductEvidence,
    _EVIDENCE_BLOCK_RE,
    decide_product_applicability,
    merge_product_evidence,
    parse_product_evidence_blocks,
    source_rank,
    synthesize_evidence_from_fields,
)

INSUFFICIENT_ANSWER_MARKERS = (
    "does not contain enough information",
    "could not derive a concise answer",
    "the retrieved context does not contain",
)

CWE_EFFECT_TERMS: dict[str, frozenset[str]] = {
    "CWE-20": frozenset({"input validation", "validation"}),
    "CWE-120": frozenset({"buffer overflow", "memory corruption", "code execution", "execute code"}),
    "CWE-121": frozenset({"buffer overflow", "memory corruption", "code execution"}),
    "CWE-122": frozenset({"buffer overflow", "memory corruption", "code execution"}),
    "CWE-200": frozenset({"information disclosure", "information exposure"}),
    "CWE-269": frozenset({"privilege escalation", "incorrect authorization", "authorization", "elevate privileges"}),
    "CWE-287": frozenset({"authentication", "auth bypass", "improper authentication", "unauthorized access"}),
    "CWE-290": frozenset({"authentication bypass", "spoofing", "mitm"}),
    "CWE-306": frozenset({"missing authentication", "unauthenticated access", "unauthenticated"}),
    "CWE-319": frozenset({"cleartext", "unencrypted", "information disclosure"}),
    "CWE-354": frozenset({"ssh", "integrity check", "connection integrity", "downgrade", "terrapin", "mitm"}),
    "CWE-400": frozenset({"resource exhaustion", "denial of service"}),
    "CWE-77": frozenset({"command injection", "command execution", "code execution", "remote code"}),
    "CWE-78": frozenset({"command injection", "command execution", "code execution"}),
    "CWE-522": frozenset({"insufficiently protected credentials", "credential exposure", "password exposure"}),
    "CWE-770": frozenset({"resource exhaustion", "denial of service", "availability impact"}),
    "CWE-862": frozenset({"missing authorization", "authorization", "unauthorized access"}),
    "CWE-863": frozenset({"incorrect authorization", "authorization", "privilege escalation", "unauthorized modification"}),
    "CWE-924": frozenset({"message integrity", "integrity check", "mitm"}),
}

STEP_REQUIRED_EFFECT_TERMS: dict[str, frozenset[str]] = {
    "network_segmentation_bypass": frozenset(
        {
            "segmentation",
            "access control",
            "access-control",
            "network configuration",
            "network control",
            "network settings",
            "acl",
            "bypass network",
            "modify network",
            "unauthorized modification of network",
            "modify configuration",
        }
    ),
    "component_compromise": frozenset(
        {
            "code execution",
            "remote code",
            "command execution",
            "authentication bypass",
            "unauthorized access",
            "unauthenticated access",
            "compromise",
            "buffer overflow",
            "memory corruption",
            "execute code",
            "control component",
            "take control",
            "privilege escalation",
            "remote compromise",
        }
    ),
    "session_compromise": frozenset(
        {
            "mitm",
            "message integrity",
            "integrity check",
            "connection integrity",
            "session integrity",
            "session confidentiality",
            "observe traffic",
            "modify traffic",
            "intercept",
            "spoofing",
            "cleartext",
            "downgrade",
        }
    ),
    "availability": frozenset({"denial of service", "resource exhaustion", "availability impact"}),
    "information_disclosure": frozenset(
        {"information disclosure", "information exposure", "credential exposure", "cleartext"}
    ),
    "privilege_escalation": frozenset(
        {"privilege escalation", "elevate privileges", "incorrect authorization"}
    ),
}

# Effects that are too weak / wrong for hard matching unless accompanied by stronger terms.
WEAK_EFFECT_TERMS = frozenset({"unauthorized access", "authorization", "compromise"})

NEGATIVE_EFFECT_TERMS: dict[str, frozenset[str]] = {
    "network_segmentation_bypass": frozenset(
        {
            "denial of service",
            "resource exhaustion",
            "clearing the local system log",
            "clear system log",
            "information disclosure only",
            "physical access",
            "spi bus",
        }
    ),
    "component_compromise": frozenset(
        {
            "denial of service only",
            "clearing the local system log",
            "clear system log",
            "physical access",
            "spi bus",
        }
    ),
    "session_compromise": frozenset(
        {
            "buffer overflow",
            "memory corruption",
            "denial of service only",
            "resource exhaustion",
            "physical access",
            "spi bus",
        }
    ),
}

@dataclass(slots=True)
class AdvisoryRecord:
    advisory_id: str
    vendor: str
    product: str
    affected_products: str
    cves: list[str]
    cwes: frozenset[str]
    raw_text: str
    source_type: str = "cisa_csv"
    part_number: str = ""
    model: str = ""
    product_family: str = ""
    affected_versions: list[str] = field(default_factory=list)
    affected_product_constraints: list[tuple[str, str, str]] = field(default_factory=list)
    description: str = ""
    effects: list[str] = field(default_factory=list)
    network_access: str | None = None
    authentication_required: bool | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    physical_access: bool | None = None
    product_evidence: list[ProductEvidence] = field(default_factory=list)


GENERIC_PRODUCT_TOKENS = frozenset(
    {
        "com",
        "modules",
        "module",
        "central",
        "processing",
        "communication",
        "firmware",
        "variants",
        "variant",
        "version",
        "versions",
        "all",
        "series",
        "device",
        "devices",
        "system",
        "base",
        "rtu",
        "rtus",
        "with",
        "the",
        "and",
        "for",
        "prior",
        "later",
        "guest",
        "role",
        "slave",
        "master",
        "industrial",
        "ethernet",
        "switch",
        "controller",
        "product",
        "products",
        "affected",
    }
)

FIRMWARE_VARIANT_RE = re.compile(r"^[A-Za-z]{2,5}\d{2}[A-Za-z]?\d?$")


@dataclass(slots=True)
class ProductIdentityResolution:
    family_match: TruthValue
    model_match: TruthValue
    part_number_match: TruthValue
    product_name_match: TruthValue
    relationship_match: TruthValue
    product_match: TruthValue
    source_affected_products: list[str]
    input_identity: str
    matched_source_product: str = ""
    rejection_reason: str = ""
    has_conflicting_evidence: bool = False
    traces: list = field(default_factory=list)
    matched_dimension: str = ""
    corroborating: list[str] = field(default_factory=list)
    conflicting: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ValidatedCve:
    cve_id: str
    advisory_id: str | None
    cwes: frozenset[str]
    enablement: str
    vulnerability_phrase: str = ""
    affected_version_bound: str | None = None
    firmware_status: str = "unknown"  # unknown | affected | not_affected
    applicability_status: str = "potentially_applicable_prerequisites_unconfirmed"
    unresolved_prerequisites: list[str] = field(default_factory=list)


def evaluate_cve_candidates(
    enrichment: StepEnrichment,
    component: ComponentModel | None,
    step: AttackStep,
    bundle: ScenarioBundle | None = None,
) -> list[CandidateEvidence]:
    seen_parts: set[str] = set()
    unique_parts: list[str] = []
    for part in (enrichment.advisory_context or "", enrichment.retrieved_text or ""):
        cleaned = part.strip()
        if not cleaned or cleaned in seen_parts:
            continue
        seen_parts.add(cleaned)
        unique_parts.append(cleaned)
    evidence_text = "\n".join(unique_parts)
    if not evidence_text and enrichment.advisory_answer and not _answer_is_insufficient(
        enrichment.advisory_answer
    ):
        evidence_text = enrichment.advisory_answer
    if not evidence_text:
        return []

    records = _collect_candidates(evidence_text)
    union_by_cve: dict[str, AdvisoryRecord] = {}
    for record in records:
        if len(record.cves) != 1:
            continue
        cve_id = record.cves[0]
        union_by_cve[cve_id] = _union_advisory_records(union_by_cve.get(cve_id), record)

    evaluated = [
        _evaluate_candidate(component, step, cve_id, record, bundle)
        for cve_id, record in union_by_cve.items()
    ]
    disposition_order = {"applicable": 0, "conditional": 1, "rejected": 2}
    return sorted(
        evaluated,
        key=lambda item: (
            disposition_order.get(item.disposition, 3),
            -item.rank_score,
            len(item.unresolved_conditions),
            item.cve_id,
        ),
    )


def extract_validated_cve(
    enrichment: StepEnrichment,
    component: ComponentModel | None,
    step: AttackStep,
    used_cves: set[str] | None = None,
    bundle: ScenarioBundle | None = None,
) -> ValidatedCve | None:
    validated = extract_validated_cves(
        enrichment,
        component,
        step,
        used_cves=used_cves,
        bundle=bundle,
        limit=1,
    )
    return validated[0] if validated else None


def extract_validated_cves(
    enrichment: StepEnrichment,
    component: ComponentModel | None,
    step: AttackStep,
    used_cves: set[str] | None = None,
    bundle: ScenarioBundle | None = None,
    limit: int = 1,
) -> list[ValidatedCve]:
    """Consume StepCVESelection / selected evidence — never a divergent candidate pool."""
    from rag.scenario.step_cve_selection import select_best_step_candidate

    results: list[ValidatedCve] = []
    if enrichment.evidence and (enrichment.evidence.selected_cve or enrichment.evidence.selected_cves):
        selected_ids = (
            enrichment.evidence.selected_cves
            or ([enrichment.evidence.selected_cve] if enrichment.evidence.selected_cve else [])
        )
        for selected_id in selected_ids:
            if used_cves and selected_id in used_cves:
                continue
            selected = next(
                (
                    candidate
                    for candidate in enrichment.evidence.candidates
                    if candidate.cve_id == selected_id and candidate.is_usable
                ),
                None,
            )
            if selected:
                results.append(_validated_from_candidate(selected, enrichment))
                if len(results) >= limit:
                    return results
        return results

    if enrichment.evidence and enrichment.evidence.candidates:
        candidates = enrichment.evidence.candidates
    else:
        candidates = evaluate_cve_candidates(enrichment, component, step, bundle)

    selection = select_best_step_candidate(
        step.step_id,
        candidates,
        step=step,
        component=component,
        used_cves=used_cves,
    )
    if selection.selected is None:
        return []
    results.append(_validated_from_candidate(selection.selected, enrichment))
    return results[:limit]

def _validated_from_candidate(
    candidate: CandidateEvidence,
    enrichment: StepEnrichment,
) -> ValidatedCve:
    return ValidatedCve(
        cve_id=candidate.cve_id,
        advisory_id=candidate.advisory_id or _advisory_id_from_sources(enrichment.sources),
        cwes=frozenset(candidate.cwes),
        enablement=candidate.vulnerability_phrase,
        vulnerability_phrase=candidate.vulnerability_phrase,
        affected_version_bound=candidate.version_bound,
        firmware_status=_firmware_label(candidate.checks),
        applicability_status=(
            "verified_applicable"
            if candidate.disposition == "applicable"
            else "potentially_applicable_prerequisites_unconfirmed"
        ),
        unresolved_prerequisites=list(candidate.unresolved_conditions),
    )


def _evaluate_candidate(
    component: ComponentModel | None,
    step: AttackStep,
    cve_id: str,
    record: AdvisoryRecord,
    bundle: ScenarioBundle | None,
) -> CandidateEvidence:
    _enrich_record_requirements_from_description(record)
    identity = _resolve_product_identity(component, record)
    checks = [
        _vendor_check(component, record),
        _identity_check("family", identity.family_match, record.product_family, identity.input_identity),
        _identity_check("model", identity.model_match, identity.matched_source_product, identity.input_identity),
        _identity_check(
            "part_number",
            identity.part_number_match,
            "; ".join(
                part
                for _, _, part in _source_product_entries(record)
                if part
            )
            or record.part_number,
            (component.part_number or "") if component else "",
        ),
        _identity_check(
            "product_name",
            identity.product_name_match,
            identity.matched_source_product or record.product,
            identity.input_identity,
        ),
        _identity_check(
            "relationship",
            identity.relationship_match,
            identity.matched_source_product,
            identity.input_identity,
        ),
        ApplicabilityCheck(
            "product",
            identity.product_match,
            "; ".join(identity.source_affected_products) or record.product,
            identity.input_identity,
            identity.rejection_reason,
        ),
        _version_check(component, record),
    ]
    if identity.product_match == TruthValue.TRUE:
        checks.extend(_prerequisite_checks(component, step, record, bundle))
        checks.append(_effect_check(step, cve_id, record))
    else:
        checks.append(
            ApplicabilityCheck(
                "technical_effect",
                TruthValue.UNKNOWN,
                step.description,
                "",
                "Effect validation skipped until product identity is confirmed.",
            )
        )

    informational_checks = {
        "family",
        "model",
        "part_number",
        "product_name",
        "relationship",
    }
    false_checks = [
        check
        for check in checks
        if check.status == TruthValue.FALSE and check.name not in informational_checks
    ]
    product_check = next(check for check in checks if check.name == "product")
    if product_check.status == TruthValue.UNKNOWN:
        false_checks.append(
            ApplicabilityCheck(
                name="product_evidence",
                status=TruthValue.FALSE,
                reason="No exact or sufficiently specific product binding was available.",
            )
        )
    unknown_checks = [
        check
        for check in checks
        if check.status == TruthValue.UNKNOWN
        and check.name not in {"vendor", "part_number", *informational_checks}
    ]

    unresolved = [
        _condition_for_check(check)
        for check in unknown_checks
        if _condition_for_check(check)
    ]
    if any("web interface" in condition and "authenticated" in condition for condition in unresolved):
        unresolved = [
            condition
            for condition in unresolved
            if condition != "the device's web interface is reachable"
        ]
    phrase = _build_vulnerability_phrase(record)
    matching_versions = _matching_version_constraints(component, record)
    final_status = compute_final_status(
        checks,
        has_conflicting_evidence=identity.has_conflicting_evidence
        or identity.product_match == TruthValue.CONFLICT,
    )
    disposition = disposition_from_final_status(final_status)
    rank_score = compute_rank_score(checks, len(unresolved))
    candidate = CandidateEvidence(
        cve_id=cve_id,
        advisory_id=record.advisory_id or None,
        disposition=disposition,
        final_status=final_status.value,
        checks=checks,
        cwes=sorted(record.cwes),
        affected_versions=matching_versions,
        description=record.description,
        effects=list(record.effects),
        vulnerability_phrase=phrase or _build_enablement(cve_id, record),
        version_bound=_extract_bound_from_values(matching_versions) or _extract_version_bound(record),
        unresolved_conditions=unresolved,
        rejection_reasons=[check.reason or f"{check.name} did not match" for check in false_checks],
        rank_score=rank_score,
        gate_table=gate_table(checks),
        lifecycle=["RETRIEVED", "VALIDATED"],
        product_evidence_trace=[
            item.to_dict() if hasattr(item, "to_dict") else item
            for item in identity.traces
        ],
    )
    if disposition == "rejected":
        candidate.record_lifecycle("REJECTED", reason="; ".join(candidate.rejection_reasons[:2]))
    elif disposition == "conditional":
        candidate.record_lifecycle("CONDITIONAL")
    else:
        candidate.record_lifecycle("VERIFIED")
    return candidate

def _vendor_check(component: ComponentModel | None, record: AdvisoryRecord) -> ApplicabilityCheck:
    observed = (component.vendor or component.manufacturer or "").strip() if component else ""
    required = (record.vendor or "").strip()
    if not observed or not required:
        return ApplicabilityCheck(
            "vendor", TruthValue.UNKNOWN, required, observed, "Vendor evidence is incomplete."
        )
    matches = _normalize_token(observed) in _normalize_blob(required)
    return ApplicabilityCheck(
        "vendor",
        TruthValue.TRUE if matches else TruthValue.FALSE,
        required,
        observed,
        "" if matches else "Scenario vendor does not match the advisory vendor.",
    )


def _identity_check(
    name: str,
    status: TruthValue,
    required: str,
    observed: str,
    reason: str = "",
) -> ApplicabilityCheck:
    return ApplicabilityCheck(name, status, required, observed, reason)


def _product_check(component: ComponentModel | None, record: AdvisoryRecord) -> ApplicabilityCheck:
    identity = _resolve_product_identity(component, record)
    return ApplicabilityCheck(
        "product",
        identity.product_match,
        "; ".join(identity.source_affected_products) or record.product,
        identity.input_identity,
        identity.rejection_reason,
    )


def _part_number_check(component: ComponentModel | None, record: AdvisoryRecord) -> ApplicabilityCheck:
    identity = _resolve_product_identity(component, record)
    required = "; ".join(part for _, _, part in _source_product_entries(record) if part) or record.part_number
    observed = (component.part_number or "").strip() if component else ""
    reason = ""
    if identity.part_number_match == TruthValue.FALSE:
        reason = "Part number conflicts with the affected product."
    return ApplicabilityCheck(
        "part_number",
        identity.part_number_match,
        required,
        observed,
        reason,
    )


def _component_deployed_version(component: ComponentModel | None) -> str:
    if component is None:
        return ""
    firmware = (component.firmware_version or "").strip()
    if firmware:
        return firmware
    for entry in component.software or []:
        if isinstance(entry, dict):
            version = str(entry.get("version") or "").strip()
            if version:
                return version
        text = str(entry)
        match = re.search(r"['\"]version['\"]\s*:\s*['\"]([^'\"]+)['\"]", text)
        if match:
            return match.group(1).strip()
        match = re.search(r"\bversion\s+(\d+(?:\.\d+)*)", text, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return ""


def _version_check(component: ComponentModel | None, record: AdvisoryRecord) -> ApplicabilityCheck:
    observed = _component_deployed_version(component)
    constraints = _matching_version_constraints(component, record)
    serial_all = any(
        "all serial" in value.lower()
        for value in ([record.affected_products, record.raw_text] + constraints)
        if value
    )
    if serial_all and not constraints:
        return ApplicabilityCheck(
            "version",
            TruthValue.TRUE,
            "all serial numbers",
            observed or "serial applicability",
            provenance="serial_constraint",
        )
    required = "; ".join(constraints)
    if not required:
        if serial_all:
            return ApplicabilityCheck(
                "version",
                TruthValue.TRUE,
                "all serial numbers",
                observed or "serial applicability",
                provenance="serial_constraint",
            )
        return ApplicabilityCheck(
            "version", TruthValue.UNKNOWN, "", observed, "The advisory has no machine-readable version constraint."
        )
    if not observed:
        return ApplicabilityCheck(
            "version", TruthValue.UNKNOWN, required, "", "The deployed version is unknown."
        )
    if any(value.strip().lower() in {"all versions", "all", "*"} for value in constraints):
        return ApplicabilityCheck("version", TruthValue.TRUE, required, observed)
    if any("all serial" in value.lower() for value in constraints):
        return ApplicabilityCheck("version", TruthValue.TRUE, required, observed)
    status = _firmware_status(component, record)
    if status == "affected":
        return ApplicabilityCheck("version", TruthValue.TRUE, required, observed)
    if status == "not_affected":
        return ApplicabilityCheck(
            "version",
            TruthValue.FALSE,
            required,
            observed,
            "The deployed version is outside the affected range.",
        )
    return ApplicabilityCheck(
        "version",
        TruthValue.UNKNOWN,
        required,
        observed,
        "The version constraint could not be compared safely.",
    )


def _effect_check(step: AttackStep, cve_id: str, record: AdvisoryRecord) -> ApplicabilityCheck:
    """Evaluate technical-effect compatibility with three-valued logic.

    PRODUCT MATCH != STEP APPLICABILITY.
    Taxonomy/CWE matrix match establishes a validated technical effect (TRUE).
    UNKNOWN effect must not authorize a specific attack-step claim.
    """
    del cve_id  # reserved for provenance / audit extensions
    objective = classify_step_objective(step)
    vulnerability_effects = extract_vulnerability_effects(
        cwes=record.cwes,
        description=record.description,
        effects=record.effects,
    )
    effect_labels = ", ".join(sorted(effect.value for effect in vulnerability_effects))
    if objective.value == "other":
        return ApplicabilityCheck(
            "technical_effect",
            TruthValue.UNKNOWN,
            objective.value,
            effect_labels,
            "The attack-step objective could not be classified.",
            provenance="step_objective_taxonomy",
        )
    if not vulnerability_effects:
        return ApplicabilityCheck(
            "technical_effect",
            TruthValue.UNKNOWN,
            objective.value,
            "",
            "No vulnerability effect could be derived from canonical CVE-local evidence.",
            provenance="cve_local_description",
        )
    if effect_blocked_for_objective(record.description, record.effects, objective):
        return ApplicabilityCheck(
            "technical_effect",
            TruthValue.FALSE,
            objective.value,
            effect_labels,
            "The vulnerability effect does not enable this attack step.",
            provenance="effect_objective_matrix",
        )
    if not effect_supports_objective(vulnerability_effects, objective):
        return ApplicabilityCheck(
            "technical_effect",
            TruthValue.FALSE,
            objective.value,
            effect_labels,
            "The vulnerability effect does not enable this attack step.",
            provenance="effect_objective_matrix",
        )
    return ApplicabilityCheck(
        "technical_effect",
        TruthValue.TRUE,
        objective.value,
        effect_labels,
        provenance="effect_objective_matrix",
    )


def _firmware_label(checks: list[ApplicabilityCheck]) -> str:
    check = next((item for item in checks if item.name == "version"), None)
    if check is None or check.status == TruthValue.UNKNOWN:
        return "unknown"
    return "affected" if check.status == TruthValue.TRUE else "not_affected"


def _condition_for_check(check: ApplicabilityCheck) -> str:
    if check.name == "version":
        required = (check.required or "").lower()
        if "serial" in required:
            if "all serial" in required:
                return ""
            return "the device serial number is within the affected range"
        constraints = parse_constraint_text(check.required or "")
        if constraints:
            text = condition_text_for_constraint(constraints[0])
            if text:
                return text
        if "software" in required:
            bound = _extract_bound_from_values([check.required or ""])
            if bound:
                return f"the deployed software version is earlier than {bound}"
            return "the deployed software version is within the affected range"
        if "hardware" in required:
            bound = _extract_bound_from_values([check.required or ""])
            if bound:
                return f"the deployed hardware version is earlier than {bound}"
            return "the deployed hardware version is within the affected range"
        bound = _extract_bound_from_values([check.required or ""])
        if bound:
            return f"the deployed firmware version is earlier than {bound}"
        return "the deployed firmware version is within the affected range"
    if check.name == "vendor":
        return ""
    if check.name == "part_number":
        return ""
    if check.name == "authentication":
        return check.required or "the required authentication condition is satisfied"
    if check.name == "privileges":
        return check.required or "the attacker has the required privileges"
    if check.name == "service":
        return check.required or "the required service is available and reachable"
    if check.name == "network_position":
        return check.required or "the required network position is established"
    if check.name == "user_interaction":
        return check.required or "the required user interaction occurs"
    if check.name == "technical_effect":
        return ""
    return check.required


def _significant_tokens(value: str) -> set[str]:
    generic = {
        "the",
        "and",
        "for",
        "with",
        "device",
        "system",
        "controller",
        "switch",
        "plc",
        "rtu",
        "product",
        "series",
        "industrial",
        "ethernet",
    }
    return {
        token.lower()
        for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9._-]*", value)
        if len(_normalize_token(token)) >= 3 and token.lower() not in generic
    }


def _source_product_entries(record: AdvisoryRecord) -> list[tuple[str, str, str]]:
    if record.affected_product_constraints:
        return list(record.affected_product_constraints)
    products: list[tuple[str, str, str]] = []
    for item in _split_listish(record.affected_products):
        products.append((item, "", record.part_number or ""))
    if record.product and not products:
        products.append((record.product, "", record.part_number or ""))
    return products


def _split_listish(value: str) -> list[str]:
    if not value:
        return []
    parts = re.split(r"[;|]", value)
    return [part.strip() for part in parts if part.strip()]


def _input_identity_label(component: ComponentModel | None) -> str:
    if component is None:
        return ""
    parts = [
        value
        for value in (
            component.part_number,
            component.model,
            component.name,
            component.product_family,
        )
        if value
    ]
    return " | ".join(dict.fromkeys(parts))


def _family_tokens(*values: str | None) -> set[str]:
    tokens: set[str] = set()
    for value in values:
        if not value:
            continue
        for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9._-]*", value):
            norm = _normalize_token(token)
            if len(norm) >= 4:
                tokens.add(norm)
    return tokens


def _normalized_word_tokens(*texts: str | None) -> list[str]:
    tokens: list[str] = []
    for text in texts:
        if not text:
            continue
        for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9._-]*", text):
            norm = _normalize_token(token)
            if norm:
                tokens.append(norm)
    return tokens


def _is_digit_identity_token(token: str) -> bool:
    return bool(re.search(r"\d", token))


def _brand_tokens_from_name(name: str, exclude: set[str]) -> set[str]:
    """Alphabetic name tokens are brand/family when a more specific token is present."""
    parts = [
        token
        for token in _normalized_word_tokens(name)
        if token not in exclude and token not in GENERIC_PRODUCT_TOKENS
    ]
    if not any(_is_digit_identity_token(token) and len(token) >= 3 for token in parts):
        return set()
    return {
        token
        for token in parts
        if not _is_digit_identity_token(token) and len(token) >= 4
    }


def _alphabetic_family_tokens(*values: str | None) -> set[str]:
    return {token for token in _family_tokens(*values) if not _is_digit_identity_token(token)}


def _structured_model_tokens(model: str, vendor_exclude: set[str]) -> list[str]:
    words = [
        token
        for token in _normalized_word_tokens(model)
        if token not in GENERIC_PRODUCT_TOKENS and token not in vendor_exclude
    ]
    digit_tokens = [token for token in words if _is_digit_identity_token(token)]
    if digit_tokens:
        return digit_tokens
    return [token for token in words if len(token) >= 2]


def _name_specific_tokens(name: str, exclude: set[str]) -> set[str]:
    tokens: set[str] = set()
    for token in _normalized_word_tokens(name):
        if token in exclude or token in GENERIC_PRODUCT_TOKENS:
            continue
        if _is_digit_identity_token(token) and len(token) >= 3:
            tokens.add(token)
    return tokens


def _entry_word_set(*texts: str | None) -> set[str]:
    return {token for token in _normalized_word_tokens(*texts) if token}


def _entry_contains_token(token: str, entry_words: set[str]) -> bool:
    return bool(token) and token in entry_words


def _product_core_name(product: str) -> str:
    return _normalize_token(re.sub(r"\([^)]*\)", "", product))


_FIRMWARE_CONTEXT_NEIGHBORS = frozenset(
    {
        "firmware",
        "variant",
        "variants",
        "version",
        "versions",
        "prior",
        "later",
        "vers",
    }
)
_RELATIONSHIP_RE = re.compile(
    r"\b(?:contains|contained\s+in|installed[-_ ]on|includes)\b",
    flags=re.IGNORECASE,
)
_IS_RELATIONSHIP_RE = re.compile(
    r"\bis\s+(?!affected\b|vulnerable\b|required\b|disabled\b|enabled\b|used\b)",
    flags=re.IGNORECASE,
)


def _has_canonical_relationship(product: str) -> bool:
    text = product or ""
    return bool(_RELATIONSHIP_RE.search(text) or _IS_RELATIONSHIP_RE.search(text))


def _token_spans(text: str) -> list[tuple[str, int, int]]:
    spans: list[tuple[str, int, int]] = []
    for match in re.finditer(r"[A-Za-z0-9][A-Za-z0-9._-]*", text or ""):
        norm = _normalize_token(match.group(0))
        if norm:
            spans.append((norm, match.start(), match.end()))
    return spans


def _parenthetical_spans(text: str) -> list[tuple[int, int]]:
    return [(match.start(), match.end()) for match in re.finditer(r"\([^)]*\)", text or "")]


def _span_in_parentheses(start: int, end: int, paren_spans: list[tuple[int, int]]) -> bool:
    return any(left <= start and end <= right for left, right in paren_spans)


def _is_version_like_token(token: str) -> bool:
    return bool(re.fullmatch(r"v?\d+(?:\.\d+)*", token))


def _neighbor_tokens(spans: list[tuple[str, int, int]], index: int) -> set[str]:
    tokens: set[str] = set()
    for offset in (-2, -1, 1, 2):
        other = index + offset
        if 0 <= other < len(spans):
            tokens.add(spans[other][0])
    return tokens


def _token_only_in_firmware_context(token: str, text: str) -> bool:
    spans = _token_spans(text)
    indexes = [index for index, (value, _, _) in enumerate(spans) if value == token]
    if not indexes:
        return False
    return all(
        bool(_neighbor_tokens(spans, index) & _FIRMWARE_CONTEXT_NEIGHBORS)
        or any(_is_version_like_token(neighbor) for neighbor in _neighbor_tokens(spans, index))
        for index in indexes
    )


def _advisory_device_tokens(product: str, exclude: set[str]) -> set[str]:
    paren_spans = _parenthetical_spans(product)
    tokens: set[str] = set()
    spans = _token_spans(product)
    for index, (token, start, end) in enumerate(spans):
        if token in exclude or token in GENERIC_PRODUCT_TOKENS:
            continue
        if not _is_digit_identity_token(token) or len(token) < 3:
            continue
        if _span_in_parentheses(start, end, paren_spans):
            continue
        if _token_only_in_firmware_context(token, product):
            continue
        tokens.add(token)
    return tokens


def _is_firmware_variant_token(token: str) -> bool:
    stripped = token.strip()
    if not FIRMWARE_VARIANT_RE.match(stripped):
        return False
    # Keep short firmware codes like ETA2, but do not suppress product models such as CPCI85.
    return len(stripped) <= 5


def _extract_identity_tokens(*texts: str, exclude: set[str] | None = None) -> set[str]:
    excluded = { _normalize_token(token) for token in (exclude or set()) }
    tokens: set[str] = set()
    for text in texts:
        if not text:
            continue
        for part in re.findall(r"\b[0-9A-Z]{2,}(?:-[0-9A-Z]+)+\b", text.upper()):
            norm = _normalize_token(part)
            if len(norm) >= 6 and norm not in excluded:
                tokens.add(norm)
        for match in re.finditer(r"\b[A-Za-z][A-Za-z0-9_-]{2,}\b", text):
            raw = match.group(0)
            norm = _normalize_token(raw)
            if len(norm) < 3 or norm in GENERIC_PRODUCT_TOKENS or norm in excluded:
                continue
            if _is_firmware_variant_token(raw):
                continue
            if re.search(r"\d", raw) or len(norm) >= 5:
                tokens.add(norm)
    return tokens


def _part_number_tokens_match(observed: str, required: str) -> bool:
    observed_norm = _normalize_token(observed).rstrip("*")
    required_norm = _normalize_token(required).rstrip("*")
    if not observed_norm or not required_norm:
        return False
    if observed_norm == required_norm:
        return True
    if observed.endswith("*") and required_norm.startswith(observed_norm):
        return True
    if required.endswith("*") and observed_norm.startswith(required_norm):
        return True
    return observed_norm in _normalize_blob(required) or required_norm in _normalize_blob(observed)


def _entry_matches_component(
    product: str,
    part_number: str,
    component: ComponentModel,
) -> tuple[bool, str, str]:
    observed_part = (component.part_number or "").strip()
    observed_model = (component.model or "").strip()
    observed_name = (component.name or "").strip()
    vendor_exclude = _alphabetic_family_tokens(component.vendor, component.manufacturer)
    exclude = _alphabetic_family_tokens(
        component.vendor,
        component.manufacturer,
        component.product_family,
    )
    exclude |= _brand_tokens_from_name(observed_name, exclude)
    specific_name_tokens = _name_specific_tokens(observed_name, exclude)
    input_tokens = _extract_identity_tokens(
        observed_part,
        observed_model,
        observed_name,
        exclude=exclude,
    )
    input_tokens |= specific_name_tokens
    entry_tokens = _extract_identity_tokens(product, part_number, exclude=exclude)
    entry_words = _entry_word_set(product, part_number)

    if observed_part and part_number:
        if _part_number_tokens_match(observed_part, part_number):
            return True, "part_number", product

    if observed_model:
        required_model = _structured_model_tokens(observed_model, vendor_exclude)
        if required_model:
            if all(_entry_contains_token(token, entry_words) for token in required_model):
                return True, "model", product
            return False, "conflict", product

    if specific_name_tokens:
        name_tokens_in_entry = all(
            _entry_contains_token(token, entry_words) for token in specific_name_tokens
        )
        if name_tokens_in_entry and _has_canonical_relationship(product):
            return True, "relationship", product
        if name_tokens_in_entry:
            firmware_only = all(
                _token_only_in_firmware_context(token, product) for token in specific_name_tokens
            )
            unmatched_devices = _advisory_device_tokens(product, exclude) - specific_name_tokens
            if firmware_only or unmatched_devices:
                return False, "insufficient", product
            return True, "product_name", product
        return False, "conflict", product

    if observed_name:
        name_norm = _normalize_token(observed_name)
        product_norm = _normalize_token(product)
        if name_norm and name_norm in {product_norm, _product_core_name(product)}:
            return True, "product_name", product

    if input_tokens and entry_tokens and not (input_tokens & entry_tokens):
        return False, "conflict", product

    if input_tokens and not entry_tokens and observed_part and part_number:
        return False, "conflict", product

    return False, "", product


def _resolve_product_identity(
    component: ComponentModel | None,
    record: AdvisoryRecord,
) -> ProductIdentityResolution:
    entries = _source_product_entries(record)
    source_products = [product for product, _, _ in entries if product]
    if record.product and record.product not in source_products:
        source_products.insert(0, record.product)
    input_identity = _input_identity_label(component)

    if component is None:
        return ProductIdentityResolution(
            family_match=TruthValue.UNKNOWN,
            model_match=TruthValue.UNKNOWN,
            part_number_match=TruthValue.UNKNOWN,
            product_name_match=TruthValue.UNKNOWN,
            relationship_match=TruthValue.UNKNOWN,
            product_match=TruthValue.UNKNOWN,
            source_affected_products=source_products,
            input_identity=input_identity,
            rejection_reason="The target component is unavailable.",
        )

    family_tokens = _family_tokens(component.product_family, record.product_family)
    source_family_tokens = _family_tokens(
        record.product_family,
        record.product,
        " ".join(source_products),
    )
    family_overlap = family_tokens & source_family_tokens
    family_match = (
        TruthValue.TRUE
        if family_overlap
        else TruthValue.FALSE
        if family_tokens or source_family_tokens
        else TruthValue.UNKNOWN
    )

    observed_part = (component.part_number or "").strip()
    source_parts = [part for _, _, part in entries if part]
    if not source_parts and record.part_number:
        source_parts = [record.part_number]

    part_number_match = TruthValue.UNKNOWN
    if observed_part and source_parts:
        if any(_part_number_tokens_match(observed_part, part) for part in source_parts):
            part_number_match = TruthValue.TRUE
        else:
            part_number_match = TruthValue.FALSE

    evidence_items = list(record.product_evidence)
    if not evidence_items:
        evidence_items = synthesize_evidence_from_fields(
            cve_id=record.cves[0] if record.cves else "",
            advisory_id=record.advisory_id,
            source_type=record.source_type,
            vendor=record.vendor,
            product=record.product,
            product_family=record.product_family,
            model=record.model,
            part_number=record.part_number,
            affected_products=_split_listish(record.affected_products) or ([record.product] if record.product else []),
            constraints=list(record.affected_product_constraints),
        )

    decision = decide_product_applicability(
        component,
        evidence_items,
        _entry_matches_component,
        input_identity=input_identity,
        family_match=family_match,
    )
    if decision.part_number_match == TruthValue.UNKNOWN and part_number_match != TruthValue.UNKNOWN:
        # Keep explicit part comparison when evidence items omit a part field.
        pass
    if decision.part_number_match == TruthValue.UNKNOWN:
        decision.part_number_match = part_number_match

    return ProductIdentityResolution(
        family_match=decision.family_match,
        model_match=decision.model_match,
        part_number_match=decision.part_number_match,
        product_name_match=decision.product_name_match,
        relationship_match=decision.relationship_match,
        product_match=decision.product_match,
        source_affected_products=decision.source_affected_products or source_products,
        input_identity=input_identity,
        matched_source_product=decision.matched_source_product,
        rejection_reason=decision.rejection_reason,
        has_conflicting_evidence=decision.has_conflicting_evidence,
        traces=list(decision.traces),
        matched_dimension=decision.matched_dimension,
        corroborating=list(decision.corroborating),
        conflicting=list(decision.conflicting),
    )


def parse_primary_advisory_record(text: str) -> AdvisoryRecord | None:
    headline_text = _EVIDENCE_BLOCK_RE.sub("", text or "")
    fields = extract_fields(headline_text)
    ics_advisory = (fields.get("ICS Advisory") or "").strip()
    if ics_advisory and re.fullmatch(
        r"(?:ICSA|ICSMA|ICSALERT)-[\dA-Z-]+",
        ics_advisory,
        flags=re.IGNORECASE,
    ):
        advisory_id = ics_advisory.upper()
    else:
        advisory_id = (fields.get("Identifier") or fields.get("Advisory") or "").strip()
        headline_match = re.search(
            r"\b(ICSA|ICSMA|ICSALERT)-[\dA-Z-]+\b",
            text,
            flags=re.IGNORECASE,
        )
        if headline_match:
            advisory_id = headline_match.group(0).upper()
    vendor = (fields.get("Vendor") or "").strip()
    product = (fields.get("Product") or "").strip()
    affected_products = (fields.get("Affected Products") or "").strip()
    cve_field = fields.get("CVE") or ""
    cwe_field = fields.get("CWE") or ""

    cves = sorted(extract_cves(cve_field))
    if not cves and cve_field:
        cves = sorted(extract_cves(text))

    cwes = frozenset(extract_cwes(cwe_field)) if cwe_field else frozenset(extract_cwes(text))
    if not cves:
        return None

    source_type = "cisa_csaf" if _looks_like_csaf_detail(headline_text, fields) else "cisa_csv"
    model = (fields.get("Model") or "").strip()
    part_number = (fields.get("Part Number") or "").strip()
    product_family = (fields.get("Product Family") or "").strip()
    constraints = _constraints_from_fields(
        fields.get("Affected Product Constraints") or "",
        affected_products,
    )
    cve_id = cves[0] if len(cves) == 1 else ""
    product_evidence = parse_product_evidence_blocks(text, default_cve=cve_id)
    if not product_evidence:
        product_evidence = synthesize_evidence_from_fields(
            cve_id=cve_id,
            advisory_id=advisory_id,
            source_type=source_type,
            vendor=vendor,
            product=product,
            product_family=product_family,
            model=model,
            part_number=part_number,
            affected_products=_split_listish(affected_products) or ([product] if product else []),
            constraints=constraints,
        )
    elif cve_id:
        for item in product_evidence:
            if not item.cve_id:
                item.cve_id = cve_id
    return AdvisoryRecord(
        advisory_id=advisory_id,
        vendor=vendor,
        product=product,
        affected_products=affected_products,
        cves=cves,
        cwes=cwes,
        raw_text=text,
        source_type=source_type,
        part_number=part_number,
        model=model,
        product_family=product_family,
        affected_versions=_split_versions(fields.get("Affected Versions") or ""),
        affected_product_constraints=constraints,
        description=(fields.get("Description") or "").strip(),
        effects=_split_effects(fields.get("Effect") or ""),
        network_access=_parse_prereq_value(fields.get("Prerequisites") or "", "network_access"),
        authentication_required=_parse_bool_prereq(fields.get("Prerequisites") or "", "authentication_required"),
        privileges_required=_parse_prereq_value(fields.get("Prerequisites") or "", "privileges_required"),
        user_interaction=_parse_prereq_value(fields.get("Prerequisites") or "", "user_interaction"),
        physical_access=_parse_bool_prereq(fields.get("Prerequisites") or "", "physical_access"),
        product_evidence=product_evidence,
    )


def classify_step_effect(step: AttackStep) -> str:
    objective = classify_step_objective(step)
    mapping = {
        "network_control_bypass": "network_segmentation_bypass",
        "device_compromise": "component_compromise",
        "session_compromise": "session_compromise",
        "availability_impact": "availability",
        "confidentiality_impact": "information_disclosure",
        "privilege_escalation": "privilege_escalation",
    }
    return mapping.get(objective.value, "other")


def _collect_candidates(text: str) -> list[AdvisoryRecord]:
    blocks = _split_candidate_blocks(text)
    records: list[AdvisoryRecord] = []
    for block in blocks:
        records.extend(_records_from_block(block))
    return records


def _records_from_block(block: str) -> list[AdvisoryRecord]:
    record = parse_primary_advisory_record(block)
    if record is None:
        return []
    if len(record.cves) <= 1:
        return [record]
    expanded: list[AdvisoryRecord] = []
    for cve_id in record.cves:
        isolated_cwes = isolate_cwes_for_cve(
            cve_id=cve_id,
            all_cves=record.cves,
            all_cwes=record.cwes,
        )
        expanded.append(
            AdvisoryRecord(
                advisory_id=record.advisory_id,
                vendor=record.vendor,
                product=record.product,
                affected_products=record.affected_products,
                cves=[cve_id],
                cwes=isolated_cwes,
                raw_text=record.raw_text,
                source_type=record.source_type,
                part_number=record.part_number,
                model=record.model,
                product_family=record.product_family,
                affected_versions=list(record.affected_versions),
                affected_product_constraints=list(record.affected_product_constraints),
                description="" if len(record.cves) > 1 else record.description,
                effects=[] if len(record.cves) > 1 or len(record.cwes) > 1 else list(record.effects),
                network_access=record.network_access,
                authentication_required=record.authentication_required,
                privileges_required=record.privileges_required,
                user_interaction=record.user_interaction,
                physical_access=record.physical_access,
                product_evidence=[
                    ProductEvidence.from_dict({**item.to_dict(), "cve_id": cve_id})
                    for item in record.product_evidence
                ],
            )
        )
    return expanded


def _union_advisory_records(
    current: AdvisoryRecord | None,
    incoming: AdvisoryRecord,
) -> AdvisoryRecord:
    if current is None:
        return incoming
    if current.cves and incoming.cves and current.cves[0] != incoming.cves[0]:
        return current
    primary, secondary = (
        (incoming, current)
        if source_rank(incoming.source_type) < source_rank(current.source_type)
        else (current, incoming)
    )
    canonical_primary = primary.source_type == "cisa_csaf"
    return AdvisoryRecord(
        advisory_id=primary.advisory_id or secondary.advisory_id,
        vendor=primary.vendor or secondary.vendor,
        product=primary.product or secondary.product,
        affected_products=primary.affected_products or secondary.affected_products,
        cves=list(primary.cves),
        cwes=primary.cwes if canonical_primary or primary.cwes else secondary.cwes,
        raw_text=primary.raw_text,
        source_type=primary.source_type,
        part_number=primary.part_number or secondary.part_number,
        model=primary.model or secondary.model,
        product_family=primary.product_family or secondary.product_family,
        affected_versions=list(primary.affected_versions or secondary.affected_versions),
        affected_product_constraints=list(
            primary.affected_product_constraints or secondary.affected_product_constraints
        ),
        description=primary.description if canonical_primary else (primary.description or secondary.description),
        effects=list(primary.effects) if canonical_primary else list(primary.effects or secondary.effects),
        network_access=primary.network_access if primary.network_access is not None else secondary.network_access,
        authentication_required=(
            primary.authentication_required
            if primary.authentication_required is not None
            else secondary.authentication_required
        ),
        privileges_required=primary.privileges_required or secondary.privileges_required,
        user_interaction=primary.user_interaction or secondary.user_interaction,
        physical_access=primary.physical_access if primary.physical_access is not None else secondary.physical_access,
        product_evidence=merge_product_evidence(current.product_evidence, incoming.product_evidence),
    )


def _split_candidate_blocks(text: str) -> list[str]:
    """Split multi-CVE CSAF detail dumps and joined CSV advisory chunks."""
    if not text.strip():
        return []
    blocks: list[str] = []
    seen: set[str] = set()

    def add_block(part: str) -> None:
        cleaned = part.strip()
        attack_prefix = re.search(
            r"(?im)^\s*(?:ATT&CK ID|Technique Name|Tactic)\s*:",
            cleaned,
        )
        advisory_start = re.search(
            r"(?im)^(?:CVE:\s*CVE-\d{4}-\d+|Advisory:).*$",
            cleaned,
        )
        if (
            attack_prefix
            and advisory_start
            and attack_prefix.start() < advisory_start.start()
        ):
            cleaned = cleaned[advisory_start.start():].strip()
        trail = re.search(
            r"(?im)^\s*(?:ATT&CK ID|Technique Name|Tactic)\s*:",
            cleaned,
        )
        if trail and trail.start() > 0:
            cleaned = cleaned[:trail.start()].rstrip()
        if not cleaned or not re.search(r"\bCVE:\s*CVE-\d{4}-\d+\b", cleaned, flags=re.IGNORECASE):
            return
        key = cleaned[:160]
        if key in seen:
            return
        seen.add(key)
        blocks.append(cleaned)

    csaf_parts = re.split(r"(?=\bCVE:\s*CVE-\d{4}-\d+\b)", text, flags=re.IGNORECASE)
    for part in csaf_parts:
        if part.strip() and _looks_like_csaf_detail(part, extract_fields(part)):
            add_block(part)

    for part in re.split(r"(?:\n\n|\n)(?=Advisory:)", text):
        add_block(part)

    for part in re.split(r"\n\n+", text):
        add_block(part)

    if blocks:
        return blocks
    return [text.strip()]


def _looks_like_csaf_detail(text: str, fields: dict[str, str]) -> bool:
    if fields.get("Description") or fields.get("Prerequisites") or fields.get("Effect"):
        return True
    lowered = text.lower()
    return "document_type" in lowered or "cve_detail" in lowered or "affected versions:" in lowered


def _passes_validation_chain(
    component: ComponentModel | None,
    step: AttackStep,
    cve_id: str,
    record: AdvisoryRecord,
) -> bool:
    # 1. Vendor match
    if not _vendor_matches(component, record):
        return False
    # 2. Product / model match
    if not _product_matches(component, record):
        return False
    # 3. Part number match when both sides have one
    if not _part_number_matches(component, record):
        return False
    # 4. Installed version match — skipped when component version is unknown
    # 5-7. Access / auth / privileges / protocol
    if not _access_prerequisites_compatible(step, record):
        return False
    # 8-9. Vulnerability effect vs attack-step objective
    if not _step_effect_matches_cve(step, cve_id, record):
        return False
    # Sparse advisory aggregates can identify candidates, but a CWE or title
    # alone is not sufficient proof that one CVE enables this specific step.
    return _strong_description_overlap(record, required_terms)


def _vendor_matches(component: ComponentModel | None, record: AdvisoryRecord) -> bool:
    if component is None:
        return False
    component_vendor = (component.vendor or component.manufacturer or "").strip()
    record_vendor = (record.vendor or "").strip()
    if not component_vendor or not record_vendor:
        # Fall back to product matching if vendor is absent on either side.
        return True
    return _normalize_token(component_vendor) in _normalize_blob(record_vendor, record.raw_text)


def _product_matches(component: ComponentModel | None, record: AdvisoryRecord) -> bool:
    return _resolve_product_identity(component, record).product_match == TruthValue.TRUE


def _part_number_matches(component: ComponentModel | None, record: AdvisoryRecord) -> bool:
    identity = _resolve_product_identity(component, record)
    if identity.part_number_match == TruthValue.TRUE:
        return True
    if identity.part_number_match == TruthValue.FALSE:
        return False
    return identity.product_match == TruthValue.TRUE


def _access_prerequisites_compatible(step: AttackStep, record: AdvisoryRecord) -> bool:
    step_blob = f"{step.name} {step.description}".lower()
    remote_step = any(
        token in step_blob
        for token in ("network", "remote", "reachable", "lateral", "segmentation", "compromise")
    )

    if record.physical_access is True and remote_step and "physical" not in step_blob:
        return False
    if (record.network_access or "").lower() == "physical" and remote_step and "physical" not in step_blob:
        return False

    description = (record.description or record.raw_text).lower()
    if remote_step and "physical access" in description and "remote" not in description:
        # Physical-only exploitation path is incompatible with network attack steps.
        if not any(token in description for token in ("remote attacker", "network", "adjacent")):
            return False
    return True


def _step_effect_matches_cve(step: AttackStep, cve_id: str, record: AdvisoryRecord) -> bool:
    """True only when CVE-local consequences are compatible with the step objective."""
    del cve_id
    objective = classify_step_objective(step)
    if objective.value == "other":
        return False
    vulnerability_effects = extract_vulnerability_effects(
        cwes=record.cwes,
        description=record.description,
        effects=record.effects,
    )
    if not vulnerability_effects:
        return False
    if effect_blocked_for_objective(record.description, record.effects, objective):
        return False
    return effect_supports_objective(vulnerability_effects, objective)


def _strong_description_overlap(record: AdvisoryRecord, required_terms: frozenset[str]) -> bool:
    blob = _effect_text(record).lower()
    strong_required = required_terms - WEAK_EFFECT_TERMS
    if any(term in blob for term in strong_required):
        return True
    derived: set[str] = set()
    for needle, terms in (
        ("command injection", {"command execution", "code execution", "execute code"}),
        ("execute arbitrary code", {"code execution", "execute code", "remote code"}),
        ("remote code execution", {"code execution", "remote code", "execute code"}),
        ("authentication bypass", {"authentication bypass", "unauthorized access"}),
        ("man-in-the-middle", {"mitm", "message integrity", "session integrity"}),
        ("man in the middle", {"mitm", "message integrity", "session integrity"}),
        ("observe and modify", {"observe traffic", "modify traffic", "session integrity"}),
        ("denial of service", {"denial of service", "availability impact"}),
        ("resource exhaustion", {"resource exhaustion", "denial of service"}),
        ("information disclosure", {"information disclosure", "information exposure"}),
        ("privilege escalation", {"privilege escalation", "elevate privileges"}),
    ):
        if needle in blob:
            derived.update(terms)
    return bool(strong_required & derived)


def _effect_text(record: AdvisoryRecord) -> str:
    """CVE-local effect text only — never advisory-wide raw retrieval blobs."""
    raw = " ".join([record.description, " ".join(record.effects)]).strip()
    if not raw:
        return ""
    lowered = raw.lower()
    cut_markers = (
        "workaround",
        "mitigation",
        "remediation",
        "this issue is patched",
        "a temporary workaround",
        "references:",
    )
    cut_at = len(raw)
    for marker in cut_markers:
        idx = lowered.find(marker)
        if idx != -1:
            cut_at = min(cut_at, idx)
    return raw[:cut_at].strip()


def _cve_behavior_terms(cve_id: str, record: AdvisoryRecord) -> frozenset[str]:
    terms: set[str] = set()

    for cwe in record.cwes:
        terms.update(CWE_EFFECT_TERMS.get(cwe.upper(), frozenset()))

    blob = _effect_text(record).lower()

    phrase_checks = {
        "authentication bypass": "authentication bypass",
        "code execution": "code execution",
        "execute code": "code execution",
        "execute arbitrary code": "code execution",
        "remote code": "remote code",
        "command execution": "command execution",
        "command injection": "command execution",
        "buffer overflow": "buffer overflow",
        "denial of service": "denial of service",
        "resource exhaustion": "resource exhaustion",
        "incorrect authorization": "incorrect authorization",
        "missing authorization": "authorization",
        "privilege escalation": "privilege escalation",
        "network configuration": "network configuration",
        "network access-control": "access-control",
        "access-control settings": "access-control",
        "access control": "access control",
        "network segmentation": "segmentation",
        "segmentation controls": "segmentation",
        "bypass network": "bypass network",
        "modify network": "modify network",
        "modify configuration": "modify configuration",
        "unauthorized modification of network": "unauthorized modification of network",
        "clearing the local system log": "clearing the local system log",
        "physical access": "physical access",
        "spi bus": "spi bus",
        "ssh": "ssh",
        "terrapin": "terrapin",
        "man-in-the-middle": "mitm",
        "man in the middle": "mitm",
        "message integrity": "message integrity",
        "session integrity": "session integrity",
        "session confidentiality": "session confidentiality",
        "observe network traffic": "observe traffic",
        "modify network traffic": "modify traffic",
        "intercept": "intercept",
        "spoof": "spoofing",
        "downgrade": "downgrade",
        "availability impact": "availability impact",
        "information disclosure": "information disclosure",
        "information exposure": "information exposure",
        "credential exposure": "credential exposure",
    }
    for needle, term in phrase_checks.items():
        if needle in blob:
            terms.add(term)

    return frozenset(terms)


def _build_enablement(cve_id: str, record: AdvisoryRecord) -> str:
    phrase = _build_vulnerability_phrase(record)
    if phrase:
        return phrase

    for cwe in sorted(record.cwes):
        label = CWE_VULN_LABELS.get(cwe.upper())
        if label:
            return f"a {label} vulnerability affecting the installed product version"

    return "an applicable vulnerability affecting the installed product version"


CWE_VULN_LABELS: dict[str, str] = {
    "CWE-20": "input-validation",
    "CWE-22": "path-traversal",
    "CWE-77": "command-injection",
    "CWE-78": "command-injection",
    "CWE-79": "cross-site scripting",
    "CWE-89": "sql-injection",
    "CWE-94": "code-injection",
    "CWE-120": "buffer-overflow",
    "CWE-121": "buffer-overflow",
    "CWE-122": "buffer-overflow",
    "CWE-200": "information-disclosure",
    "CWE-269": "incorrect-authorization",
    "CWE-287": "authentication-bypass",
    "CWE-290": "authentication-bypass",
    "CWE-294": "authentication-replay",
    "CWE-306": "missing-authentication",
    "CWE-319": "cleartext-transmission",
    "CWE-352": "cross-site request-forgery",
    "CWE-400": "resource-exhaustion",
    "CWE-522": "credential-exposure",
    "CWE-732": "incorrect-permission-assignment",
    "CWE-770": "resource-exhaustion",
    "CWE-862": "missing-authorization",
    "CWE-863": "incorrect-authorization",
    "CWE-924": "message-integrity",
}


def _build_vulnerability_phrase(record: AdvisoryRecord) -> str:
    label = _vulnerability_label(record)
    if label == "applicable":
        return "an applicable vulnerability"
    description = re.sub(r"\s+", " ", (record.description or "").strip())
    location = _location_clause(description)
    impact = _impact_clause(description)

    parts = [f"{'an' if label[:1] in {'a', 'e', 'i', 'o', 'u'} else 'a'} {label} vulnerability"]
    if location:
        parts.append(location)
    if impact:
        parts.append(impact)
    elif description and not location:
        # Keep a short cleaned first sentence only when structured clauses are unavailable.
        first = re.split(r"(?<=[.!?])\s+", description)[0].rstrip(".")
        if 20 <= len(first) <= 160 and "vulnerability" in first.lower():
            return first[0].lower() + first[1:] if first else parts[0]
    return " ".join(parts)


def _vulnerability_label(record: AdvisoryRecord) -> str:
    for cwe in sorted(record.cwes):
        label = CWE_VULN_LABELS.get(cwe.upper())
        if label:
            return label

    description = (record.description or "").lower()
    for needle, label in (
        ("command injection", "command-injection"),
        ("code injection", "code-injection"),
        ("sql injection", "sql-injection"),
        ("authentication bypass", "authentication-bypass"),
        ("buffer overflow", "buffer-overflow"),
        ("path traversal", "path-traversal"),
        ("incorrect authorization", "incorrect-authorization"),
        ("missing authentication", "missing-authentication"),
        ("replay attack", "authentication-replay"),
        ("capture replay", "authentication-replay"),
    ):
        if needle in description:
            return label
    return "applicable"


def _location_clause(description: str) -> str:
    lowered = description.lower()
    if "web interface" in lowered:
        return "in the device's web interface"
    if "ssh" in lowered:
        return "in the SSH service"
    if "management interface" in lowered:
        return "in the management interface"
    if "network configuration" in lowered:
        return "in network configuration management"
    return ""


def _impact_clause(description: str) -> str:
    if not description:
        return ""
    match = re.search(
        r"(?:this could allow|this allows|allowing)\s+(.+?)(?:\.|$)",
        description,
        flags=re.IGNORECASE,
    )
    if not match:
        return ""
    rest = re.sub(r"\s+", " ", match.group(1)).strip().rstrip(".")
    if not rest:
        return ""
    if match.group(0).lower().startswith("this could allow"):
        return f"that can allow {rest}"
    return f"that allows {rest}"


def _extract_version_bound(record: AdvisoryRecord) -> str | None:
    """Return a concise upper-bound version such as 'V5.30' when recoverable."""
    blobs = [
        " ".join(record.affected_versions),
        record.affected_products,
        record.description,
        record.raw_text,
    ]
    product_hints = [record.product, record.model, record.product_family]
    product_hints = [hint for hint in product_hints if hint]

    # Prefer a product-local constraint when the advisory covers multiple products.
    for blob in blobs:
        if not blob:
            continue
        for hint in product_hints:
            pattern = re.compile(
                rf"{re.escape(hint)}[^.]{{0,80}}?(?:all versions\s+)?(?:prior to|before|earlier than|<)\s*(V?\d+(?:\.\d+)*)",
                flags=re.IGNORECASE,
            )
            match = pattern.search(blob)
            if match:
                return _normalize_version_token(match.group(1))

    for blob in blobs:
        if not blob:
            continue
        match = re.search(
            r"(?:all versions\s+)?(?:prior to|before|earlier than|<)\s*(V?\d+(?:\.\d+)*)",
            blob,
            flags=re.IGNORECASE,
        )
        if match:
            return _normalize_version_token(match.group(1))
        match = re.search(r"\bprior to\s+(V?\d+(?:\.\d+)*)", blob, flags=re.IGNORECASE)
        if match:
            return _normalize_version_token(match.group(1))
        match = re.search(
            r'Versions?\s*"?\s*(\d+(?:\.\d+)*)\s*"?\s+and prior',
            blob,
            flags=re.IGNORECASE,
        )
        if match:
            return _normalize_version_token(match.group(1))
    return None


def _firmware_status(component: ComponentModel | None, record: AdvisoryRecord) -> str:
    observed = _component_deployed_version(component)
    if component is None or not observed:
        return "unknown"
    installed = _parse_version_tuple(observed)
    if installed is None:
        return "unknown"
    constraints = _matching_version_constraints(component, record)
    if any(value.strip().lower() in {"all versions", "all", "*"} for value in constraints):
        return "affected"
    if not constraints:
        bound = _extract_version_bound(record)
        constraints = [f"prior to {bound}"] if bound else []
    results = [
        result
        for constraint in constraints
        if (result := _evaluate_version_constraint(installed, constraint)) is not None
    ]
    if not results:
        return "unknown"
    return "affected" if any(results) else "not_affected"


def _matching_version_constraints(
    component: ComponentModel | None,
    record: AdvisoryRecord,
) -> list[str]:
    if component and record.affected_product_constraints:
        matches: list[str] = []
        for product, version, part_number in record.affected_product_constraints:
            matched, _, _ = _entry_matches_component(product, part_number, component)
            if matched and version:
                matches.append(version)
        if matches:
            return list(dict.fromkeys(matches))
    return list(record.affected_versions)


def _extract_bound_from_values(values: list[str]) -> str | None:
    for value in values:
        match = re.search(
            r"(?:prior to|before|earlier than|<)\s*(V?\d+(?:\.\d+)*)",
            value,
            flags=re.IGNORECASE,
        )
        if match:
            return _normalize_version_token(match.group(1))
    return None


def _evaluate_version_constraint(
    installed: tuple[int, ...],
    constraint: str,
) -> bool | None:
    text = constraint.strip()
    lowered = text.lower()
    if "all serial" in lowered or lowered in {"all versions", "all", "*"}:
        return True
    versions = [
        _parse_version_tuple(match)
        for match in re.findall(r"V?\d+(?:\.\d+)*", text, flags=re.IGNORECASE)
    ]
    versions = [version for version in versions if version is not None]
    if not versions:
        return None

    if len(versions) >= 2 and any(token in lowered for token in ("since", "from", ">=")) and any(
        token in lowered for token in ("prior to", "before", "<")
    ):
        return versions[0] <= installed < versions[1]
    if len(versions) >= 2 and any(token in lowered for token in ("between", "through", "up to")):
        return versions[0] <= installed <= versions[1]

    version = versions[-1]
    if any(token in lowered for token in ("prior to", "before", "earlier than")) or re.search(
        r"(^|\s)<(?![=])", text
    ):
        return installed < version
    if any(token in lowered for token in ("through", "up to", "or earlier", "and earlier", "and prior")) or "<=" in text:
        return installed <= version
    if any(token in lowered for token in ("since", "or later", "and later")) or ">=" in text:
        return installed >= version
    if re.search(r"(^|\s)>(?![=])", text):
        return installed > version
    # Bare comparable version tokens are treated as exact affected versions.
    if any(token in lowered for token in ("version", "versions", "=", "affected")) or re.fullmatch(
        r"V?\d+(?:\.\d+)*",
        text.strip(),
        flags=re.IGNORECASE,
    ):
        return installed == version
    return installed == version


def _enrich_record_requirements_from_description(record: AdvisoryRecord) -> None:
    """Fill missing auth/privilege requirements only from explicit exploitation phrases."""
    if record.authentication_required is not None and record.privileges_required:
        return
    auth, privilege, provenance = enrich_auth_from_description(record.description or "")
    if record.authentication_required is None and auth is not None:
        record.authentication_required = auth
    if not record.privileges_required and privilege:
        record.privileges_required = privilege


def _required_service(record: AdvisoryRecord) -> tuple[str | None, str]:
    prereq_text = ""
    if record.raw_text:
        fields = extract_fields(record.raw_text)
        prereq_text = fields.get("Prerequisites") or ""
    return extract_required_service(
        description=record.description or "",
        effects=record.effects,
        prerequisites_text=prereq_text,
    )


def _prerequisite_checks(
    component: ComponentModel | None,
    step: AttackStep,
    record: AdvisoryRecord,
    bundle: ScenarioBundle | None,
) -> list[ApplicabilityCheck]:
    checks: list[ApplicabilityCheck] = []
    required_service, service_provenance = _required_service(record)
    if required_service:
        status = _service_status(component, step, required_service)
        checks.append(
            ApplicabilityCheck(
                "service",
                status,
                _service_condition(required_service),
                ", ".join((component.services + component.protocols) if component else []),
                "" if status == TruthValue.TRUE else "Required service reachability is not established.",
                provenance=service_provenance,
            )
        )

    privilege = (record.privileges_required or "").lower()
    if record.authentication_required is True or privilege not in {"", "none"}:
        privilege_status = _privilege_status(component, bundle, privilege or "low")
        if privilege in {"high", "admin", "administrator", "privileged"}:
            condition = (
                f"the attacker has authenticated privileged access to the device's "
                f"{'web interface' if required_service == 'web_interface' else 'affected service'}"
            )
        elif required_service == "web_interface":
            condition = "the attacker has authenticated access to the device's web interface"
        else:
            condition = "the attacker has authenticated access to the affected service"
        checks.append(
            ApplicabilityCheck(
                "privileges",
                privilege_status,
                condition,
                _observed_privileges(component, bundle),
                "" if privilege_status == TruthValue.TRUE else "Required attacker privileges are not established.",
                provenance="prerequisites:privileges_required" if record.privileges_required else "description:authenticated remote attacker",
            )
        )
    elif record.authentication_required is False:
        checks.append(
            ApplicabilityCheck(
                "authentication",
                TruthValue.TRUE,
                "no authentication is required",
                "advisory states unauthenticated exploitation",
                provenance="prerequisites:authentication_required=false",
            )
        )

    network_access = (record.network_access or "").lower()
    if record.physical_access is True or network_access == "physical":
        context = _scenario_context_blob(step, bundle)
        if "physical" in context:
            status = TruthValue.TRUE
        elif any(token in context for token in ("remote", "network path", "network access")):
            status = TruthValue.FALSE
        else:
            status = TruthValue.UNKNOWN
        checks.append(
            ApplicabilityCheck(
                "network_position",
                status,
                "the attacker has physical access to the target",
                context,
                "" if status == TruthValue.TRUE else "Physical access required by the advisory is not established.",
                provenance=f"prerequisites:network_access={record.network_access or 'physical'}",
            )
        )
    elif _requires_mitm(record):
        context = _scenario_context_blob(step, bundle)
        status = TruthValue.TRUE if _context_establishes_mitm(context) else TruthValue.UNKNOWN
        checks.append(
            ApplicabilityCheck(
                "network_position",
                status,
                "the attacker is positioned on the communication path",
                context,
                "" if status == TruthValue.TRUE else "A man-in-the-middle position is not established.",
                provenance="effect_taxonomy:mitm_position",
            )
        )

    interaction = (record.user_interaction or "").lower()
    if interaction and interaction not in {"none", "n"}:
        context = _scenario_context_blob(step, bundle)
        status = (
            TruthValue.TRUE
            if any(token in context for token in ("valid user", "user initiates", "user opens", "user interaction"))
            else TruthValue.UNKNOWN
        )
        checks.append(
            ApplicabilityCheck(
                "user_interaction",
                status,
                "the required user interaction occurs",
                context,
                "" if status == TruthValue.TRUE else "Required user interaction is not established.",
                provenance=f"prerequisites:user_interaction={interaction}",
            )
        )
    return checks


def _service_status(
    component: ComponentModel | None,
    step: AttackStep,
    required_service: str,
) -> TruthValue:
    if _service_reachability_confirmed(component, step, required_service):
        return TruthValue.TRUE
    if component is None:
        return TruthValue.UNKNOWN
    known = component.services + component.protocols
    if known:
        return TruthValue.FALSE
    return TruthValue.UNKNOWN


def _service_condition(required_service: str) -> str:
    if required_service == "web_interface":
        return "the device's web interface is reachable"
    return f"the required {required_service.replace('_', ' ')} service is available and reachable"


def _privilege_status(
    component: ComponentModel | None,
    bundle: ScenarioBundle | None,
    required_privilege: str,
) -> TruthValue:
    if _attacker_privilege_confirmed(component, bundle, required_privilege):
        return TruthValue.TRUE
    auth = component.authentication if component else {}
    if auth.get("attacker_has_privileged_credentials") is False and required_privilege == "high":
        return TruthValue.FALSE
    if auth.get("attacker_has_credentials") is False and required_privilege != "none":
        return TruthValue.FALSE
    return TruthValue.UNKNOWN


def _observed_privileges(
    component: ComponentModel | None,
    bundle: ScenarioBundle | None,
) -> str:
    values: list[str] = []
    if component:
        values.extend(str(item) for item in component.authorization.get("privileges") or [])
        values.extend(str(item) for item in component.authorization.get("roles") or [])
    if bundle and bundle.scenario.attacker_profile:
        values.extend(bundle.scenario.attacker_profile.capabilities)
    return ", ".join(values)


def _requires_mitm(record: AdvisoryRecord) -> bool:
    blob = _effect_text(record).lower()
    return any(
        token in blob
        for token in (
            "man-in-the-middle",
            "man in the middle",
            "mitm",
            "positioned between",
            "intercept",
            "on-path attacker",
        )
    )


def _scenario_context_blob(step: AttackStep, bundle: ScenarioBundle | None) -> str:
    parts = [step.name, step.description, " ".join(step.required_conditions)]
    if bundle:
        parts.extend(bundle.scenario.global_preconditions)
        if bundle.scenario.attacker_profile:
            parts.extend(bundle.scenario.attacker_profile.capabilities)
            parts.append(bundle.scenario.attacker_profile.description)
        for prior in bundle.scenario.attack_path:
            if prior.sequence < step.sequence:
                parts.extend([prior.name, prior.description, " ".join(prior.required_conditions)])
    return " ".join(parts).lower().replace("_", " ")


def _context_establishes_mitm(context: str) -> bool:
    return any(
        token in context
        for token in (
            "man-in-the-middle",
            "man in the middle",
            "positioned between",
            "position themselves on the communication path",
            "observe and modify traffic",
            "on-path",
        )
    )


def _unresolved_prerequisites(
    component: ComponentModel | None,
    step: AttackStep,
    record: AdvisoryRecord,
    firmware_status: str,
    bundle: ScenarioBundle | None,
) -> list[str]:
    unresolved: list[str] = []
    version_bound = _extract_version_bound(record)
    required_service = _required_service(record)

    if firmware_status == "unknown" and version_bound:
        unresolved.append(f"the deployed firmware version is earlier than {version_bound}")

    auth_required = record.authentication_required
    privilege = (record.privileges_required or "").lower() or None
    if auth_required or privilege in {"low", "high"}:
        if not _attacker_privilege_confirmed(component, bundle, privilege or "low"):
            if privilege == "high" and required_service == "web_interface":
                unresolved.append(
                    "the attacker has authenticated privileged access to the device's web interface"
                )
            elif privilege == "high":
                unresolved.append("the attacker has authenticated privileged access to the affected service")
            elif required_service == "web_interface":
                unresolved.append("the attacker has authenticated access to the device's web interface")
            else:
                unresolved.append("the attacker has authenticated access to the affected service")

    if required_service and not _service_reachability_confirmed(component, step, required_service):
        # Avoid duplicating web-interface wording already covered by privilege condition.
        if not any("web interface" in item for item in unresolved):
            if required_service == "web_interface":
                unresolved.append("the device's web interface is reachable")
            else:
                unresolved.append(f"the required {required_service.replace('_', ' ')} is reachable")

    return unresolved


def _attacker_privilege_confirmed(
    component: ComponentModel | None,
    bundle: ScenarioBundle | None,
    required_privilege: str,
) -> bool:
    auth = dict(component.authentication) if component and component.authentication else {}
    if auth.get("attacker_has_privileged_credentials") is True:
        return True
    if required_privilege == "low" and auth.get("attacker_has_credentials") is True:
        return True

    # Explicit scenario-level flags only; generic capability tags are not enough.
    if bundle and bundle.scenario.attacker_profile:
        capabilities = {item.lower() for item in bundle.scenario.attacker_profile.capabilities}
        if required_privilege == "high" and "privileged_target_credentials" in capabilities:
            return True
        if required_privilege == "low" and (
            "target_credentials" in capabilities or "privileged_target_credentials" in capabilities
        ):
            return True
    return False


def _service_reachability_confirmed(
    component: ComponentModel | None,
    step: AttackStep,
    required_service: str,
) -> bool:
    if component is None:
        return False

    service_aliases = {
        "web_interface": {"web_interface", "web", "http", "https", "webui", "web_ui"},
        "ssh": {"ssh"},
        "management_interface": {"management_interface", "management", "mgmt"},
        "opc ua": {"opc ua", "opcua"},
        "iec 61850": {"iec 61850", "iec61850"},
        "ethernet/ip": {"ethernet/ip", "ethernetip", "cip"},
    }
    aliases = service_aliases.get(required_service, {required_service})
    normalized_services = {_normalize_service_token(item) for item in component.services}
    if normalized_services & {_normalize_service_token(item) for item in aliases}:
        return True

    # Step conditions may explicitly assert the needed service/protocol is reachable.
    conditions = " ".join(step.required_conditions).lower()
    description = step.description.lower()
    blob = f"{conditions} {description}"
    if required_service == "web_interface" and any(
        token in blob for token in ("web interface", "webui", "http service", "https service")
    ):
        return True
    if required_service == "ssh" and "ssh" in blob:
        return True
    if _normalize_service_token(required_service) in _normalize_service_token(blob):
        return True
    return False


def _normalize_service_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _normalize_version_token(value: str) -> str:
    cleaned = value.strip()
    if cleaned.upper().startswith("V"):
        return "V" + cleaned[1:]
    return f"V{cleaned}"


def _parse_version_tuple(value: str) -> tuple[int, ...] | None:
    match = re.search(r"V?(\d+(?:\.\d+)*)", value.strip(), flags=re.IGNORECASE)
    if not match:
        return None
    try:
        return tuple(int(part) for part in match.group(1).split("."))
    except ValueError:
        return None


def _combined_advisory_text(enrichment: StepEnrichment) -> str:
    parts = [enrichment.advisory_context or "", enrichment.advisory_answer or "", enrichment.retrieved_text or ""]
    return "\n".join(part.strip() for part in parts if part and part.strip())


def _answer_is_insufficient(answer: str) -> bool:
    lowered = answer.lower()
    return any(marker in lowered for marker in INSUFFICIENT_ANSWER_MARKERS)


def _advisory_id_from_sources(sources: list[SourceReference]) -> str | None:
    for source in sources:
        if source.document_source in {"CISA ICS Advisory", "cisa_csaf"} and source.attack_id:
            return source.attack_id
    return None


def _split_versions(value: str) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in re.split(r"[;|]", value) if part.strip()]


def _constraints_from_fields(
    constraints_field: str,
    affected_products: str,
) -> list[tuple[str, str, str]]:
    constraints = _split_product_constraints(constraints_field)
    if constraints:
        return constraints
    return _parse_csv_affected_product_constraints(affected_products)


def _parse_csv_affected_product_constraints(text: str) -> list[tuple[str, str, str]]:
    if not text:
        return []
    constraints: list[tuple[str, str, str]] = []
    pattern = re.compile(
        r"([^:;|]+?)(?::|;)\s*Versions?\s*\"?(\d+(?:\.\d+)*)\"?\s+and prior",
        flags=re.IGNORECASE,
    )
    for match in pattern.finditer(text):
        product = match.group(1).strip()
        version = match.group(2).strip().strip('"')
        if product and version:
            constraints.append((product, f"{version} and prior", ""))
    return constraints


def _split_product_constraints(value: str) -> list[tuple[str, str, str]]:
    constraints: list[tuple[str, str, str]] = []
    for item in value.split("||"):
        parts = [part.strip() for part in item.split("@@")]
        if not parts or not parts[0]:
            continue
        constraints.append(
            (
                parts[0],
                parts[1] if len(parts) > 1 else "",
                parts[2] if len(parts) > 2 else "",
            )
        )
    return constraints


def _split_effects(value: str) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in re.split(r"[;|]", value) if part.strip()]


def _parse_prereq_value(prereq_text: str, key: str) -> str | None:
    match = re.search(rf"\b{re.escape(key)}=([^\s,;]+)", prereq_text, flags=re.IGNORECASE)
    if not match:
        return None
    return match.group(1).strip().lower()


def _parse_bool_prereq(prereq_text: str, key: str) -> bool | None:
    value = _parse_prereq_value(prereq_text, key)
    if value is None:
        return None
    if value in {"true", "yes", "1"}:
        return True
    if value in {"false", "no", "0"}:
        return False
    return None


def _normalize_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _normalize_blob(*parts: str) -> str:
    tokens: list[str] = []
    for part in parts:
        if not part:
            continue
        tokens.append(_normalize_token(part))
        tokens.extend(_normalize_token(token) for token in re.findall(r"[A-Za-z0-9]+", part))
    return " ".join(token for token in tokens if token)


# Backward-compatible alias used by older tests/helpers.
_component_matches_advisory = _product_matches
