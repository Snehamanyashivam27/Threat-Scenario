from __future__ import annotations

# Narrator-only projection of validated, CVE-independent technical facts.
# Not a fallback CVE-selection path. Composer must consume this DTO only.

from rag.scenario.canonical_cve import TechnicalContextFact
from rag.scenario.evidence import ApplicabilityCheck, CandidateEvidence, TruthValue
from rag.scenario.models import AttackStep, ComponentModel

MAX_TECHNICAL_CONTEXT_FACTS = 2

CATEGORY_PRIORITY = (
    "affected_functionality",
    "access_category",
    "technical_consequence",
    "vulnerability_class",
    "asset_role",
)

_PREREQ_GATES = ("service", "authentication", "privileges", "network_position", "user_interaction")

_SERVICE_TEMPLATES = {
    "web_interface": {
        TruthValue.TRUE: "through a reachable web management function",
        TruthValue.UNKNOWN: "This would require that a web management function is reachable.",
    },
    "ssh": {
        TruthValue.TRUE: "through a reachable SSH service",
        TruthValue.UNKNOWN: "This would require that an SSH service is reachable.",
    },
}

_ACCESS_TEMPLATES = {
    "unauthenticated": {
        TruthValue.TRUE: "using unauthenticated access",
        TruthValue.UNKNOWN: "This would require that unauthenticated access is possible.",
    },
    "authenticated": {
        TruthValue.TRUE: "using authenticated access",
        TruthValue.UNKNOWN: "This would require that authenticated access is present.",
    },
    "privileged": {
        TruthValue.TRUE: "using privileged access",
        TruthValue.UNKNOWN: "This would require that privileged access is present.",
    },
}

_EFFECT_LABELS = {
    "authentication_bypass": "authentication bypass",
    "authorization_bypass": "authorization bypass",
    "command_injection": "command injection",
    "code_execution": "code execution",
    "remote_code_execution": "remote code execution",
    "privilege_escalation": "privilege escalation",
    "configuration_modification": "configuration modification",
    "session_hijack": "session hijack",
    "information_disclosure": "information disclosure",
    "denial_of_service": "denial of service",
    "device_reboot": "device reboot",
    "firmware_modification": "firmware modification",
    "credential_disclosure": "credential disclosure",
    "network_control_modification": "network-control modification",
}

_CWE_CLASS_LABELS = {
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


def project_technical_context(
    step: AttackStep,
    component: ComponentModel | None,
    candidates: list[CandidateEvidence],
) -> list[TechnicalContextFact]:
    """Project at most two narrator-safe facts from validated candidate checks."""
    del step, component
    by_category: dict[str, list[TechnicalContextFact]] = {}
    for candidate in candidates:
        if not _is_contributor(candidate):
            continue
        for fact in _facts_from_candidate(candidate):
            by_category.setdefault(fact.category, []).append(fact)
    merged = _merge_facts(by_category)
    return merged[:MAX_TECHNICAL_CONTEXT_FACTS]


def facts_as_payload(facts: list[TechnicalContextFact]) -> list[dict[str, str]]:
    return [
        {
            "category": fact.category,
            "polarity": fact.polarity,
            "statement": fact.statement,
            "evidence_state": fact.evidence_state,
        }
        for fact in facts
    ]


def _is_contributor(candidate: CandidateEvidence) -> bool:
    checks = _check_map(candidate)
    product = checks.get("product")
    if product is None or product.status != TruthValue.TRUE:
        return False
    effect = checks.get("technical_effect")
    if effect is not None and effect.status == TruthValue.FALSE:
        return False
    version = checks.get("version")
    if version is not None and version.status == TruthValue.FALSE:
        return False
    for name in _PREREQ_GATES:
        check = checks.get(name)
        if check is not None and check.status == TruthValue.FALSE:
            return False
    return True


def _facts_from_candidate(candidate: CandidateEvidence) -> list[TechnicalContextFact]:
    checks = _check_map(candidate)
    facts: list[TechnicalContextFact] = []
    service_fact = _service_fact(checks.get("service"))
    if service_fact:
        facts.append(service_fact)
    access_fact = _access_fact(checks)
    if access_fact:
        facts.append(access_fact)

    effect = checks.get("technical_effect")
    if effect is not None and effect.status == TruthValue.TRUE:
        consequence = _consequence_fact(effect)
        if consequence:
            facts.append(consequence)
        class_fact = _class_fact(candidate)
        if class_fact:
            facts.append(class_fact)
    return facts


def _service_fact(check: ApplicabilityCheck | None) -> TechnicalContextFact | None:
    if check is None or check.status in {TruthValue.FALSE, TruthValue.CONFLICT}:
        return None
    token = _service_token(check)
    templates = _SERVICE_TEMPLATES.get(token or "")
    if not templates or check.status not in templates:
        return None
    return _fact(
        "affected_functionality",
        check.status,
        templates[check.status],
        token=token or "",
    )


def _access_fact(checks: dict[str, ApplicabilityCheck]) -> TechnicalContextFact | None:
    auth = checks.get("authentication")
    privileges = checks.get("privileges")
    token: str | None = None
    status: TruthValue | None = None
    if auth is not None and "no authentication" in (auth.required or "").lower():
        token = "unauthenticated"
        status = auth.status
    elif privileges is not None:
        required = (privileges.required or "").lower()
        status = privileges.status
        if "privileged" in required:
            token = "privileged"
        elif "authenticated" in required:
            token = "authenticated"
    if token is None or status is None or status in {TruthValue.FALSE, TruthValue.CONFLICT}:
        return None
    templates = _ACCESS_TEMPLATES.get(token)
    if not templates or status not in templates:
        return None
    return _fact("access_category", status, templates[status], token=token)


def _consequence_fact(check: ApplicabilityCheck) -> TechnicalContextFact | None:
    labels = [
        _EFFECT_LABELS[token]
        for token in _effect_tokens(check.observed)
        if token in _EFFECT_LABELS
    ]
    if len(labels) != 1:
        return None
    return _fact(
        "technical_consequence",
        TruthValue.TRUE,
        f"A possible technical consequence is {labels[0]}.",
        token=labels[0],
    )


def _class_fact(candidate: CandidateEvidence) -> TechnicalContextFact | None:
    labels = []
    for cwe in candidate.cwes:
        label = _CWE_CLASS_LABELS.get(str(cwe).upper())
        if label and label not in labels:
            labels.append(label)
    if len(labels) != 1:
        return None
    return _fact(
        "vulnerability_class",
        TruthValue.TRUE,
        f"The associated vulnerability class is {labels[0]}.",
        token=labels[0],
    )


def _merge_facts(by_category: dict[str, list[TechnicalContextFact]]) -> list[TechnicalContextFact]:
    merged: list[TechnicalContextFact] = []
    for category in CATEGORY_PRIORITY:
        facts = by_category.get(category) or []
        if not facts:
            continue
        tokens = {fact.token or fact.statement for fact in facts}
        if len(tokens) != 1:
            continue
        confirmed = [fact for fact in facts if fact.polarity == "confirmed"]
        chosen = confirmed[0] if confirmed else facts[0]
        merged.append(chosen)
    return merged


def _fact(category: str, status: TruthValue, statement: str, *, token: str) -> TechnicalContextFact:
    polarity = "confirmed" if status == TruthValue.TRUE else "conditional"
    return TechnicalContextFact(
        category=category,
        polarity=polarity,
        statement=statement,
        evidence_state=status.value,
        token=token,
    )


def _check_map(candidate: CandidateEvidence) -> dict[str, ApplicabilityCheck]:
    return {check.name: check for check in candidate.checks}


def _service_token(check: ApplicabilityCheck) -> str | None:
    blob = " ".join(
        part for part in (check.required, check.provenance, check.observed) if part
    ).lower()
    if "web interface" in blob or "web_interface" in blob or "web management" in blob:
        return "web_interface"
    if "ssh" in blob:
        return "ssh"
    return None


def _effect_tokens(observed: str) -> list[str]:
    return [token.strip() for token in (observed or "").lower().replace(" ", "_").split(",") if token.strip()]
