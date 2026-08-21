from __future__ import annotations

import re
from enum import Enum

from rag.scenario.evidence import ApplicabilityCheck, TruthValue
from rag.scenario.models import AttackStep


class FinalStatus(str, Enum):
    VERIFIED_APPLICABLE = "verified_applicable"
    CONDITIONAL_VERSION_UNKNOWN = "conditional_version_unknown"
    CONDITIONAL_PREREQUISITE_UNKNOWN = "conditional_prerequisite_unknown"
    REJECTED_PRODUCT_MISMATCH = "rejected_product_mismatch"
    REJECTED_VERSION_MISMATCH = "rejected_version_mismatch"
    REJECTED_PREREQUISITE_MISMATCH = "rejected_prerequisite_mismatch"
    REJECTED_EFFECT_MISMATCH = "rejected_effect_mismatch"
    REJECTED_DIMENSION_MISMATCH = "rejected_dimension_mismatch"
    CONDITIONAL_DIMENSION_UNKNOWN = "conditional_dimension_unknown"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    INSUFFICIENT_CONTEXT = "insufficient_context"


APPLICABILITY_DIMENSIONS = (
    "serial_number",
    "firmware_version",
    "software_version",
    "hardware_version",
    "product_revision",
    "configuration",
)
FIRMWARE_GATE_NAMES = frozenset({"version", "firmware_version"})


class StepObjective(str, Enum):
    INITIAL_ACCESS = "initial_access"
    CREDENTIAL_ACCESS = "credential_access"
    LATERAL_MOVEMENT = "lateral_movement"
    SESSION_COMPROMISE = "session_compromise"
    NETWORK_CONTROL_BYPASS = "network_control_bypass"
    DEVICE_COMPROMISE = "device_compromise"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CONTROL_MODIFICATION = "control_modification"
    PROCESS_MANIPULATION = "process_manipulation"
    CONFIDENTIALITY_IMPACT = "confidentiality_impact"
    INTEGRITY_IMPACT = "integrity_impact"
    AVAILABILITY_IMPACT = "availability_impact"
    OTHER = "other"


class VulnerabilityEffect(str, Enum):
    AUTHENTICATION_BYPASS = "authentication_bypass"
    AUTHORIZATION_BYPASS = "authorization_bypass"
    COMMAND_INJECTION = "command_injection"
    CODE_EXECUTION = "code_execution"
    REMOTE_CODE_EXECUTION = "remote_code_execution"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CONFIGURATION_MODIFICATION = "configuration_modification"
    SESSION_HIJACK = "session_hijack"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    DEVICE_REBOOT = "device_reboot"
    FIRMWARE_MODIFICATION = "firmware_modification"
    CREDENTIAL_DISCLOSURE = "credential_disclosure"
    NETWORK_CONTROL_MODIFICATION = "network_control_modification"


EFFECT_OBJECTIVE_MATRIX: dict[VulnerabilityEffect, frozenset[StepObjective]] = {
    VulnerabilityEffect.AUTHENTICATION_BYPASS: frozenset(
        {
            StepObjective.INITIAL_ACCESS,
            StepObjective.DEVICE_COMPROMISE,
            StepObjective.LATERAL_MOVEMENT,
            StepObjective.CREDENTIAL_ACCESS,
            StepObjective.SESSION_COMPROMISE,
        }
    ),
    VulnerabilityEffect.AUTHORIZATION_BYPASS: frozenset(
        {
            StepObjective.PRIVILEGE_ESCALATION,
            StepObjective.DEVICE_COMPROMISE,
            StepObjective.CONTROL_MODIFICATION,
        }
    ),
    VulnerabilityEffect.COMMAND_INJECTION: frozenset(
        {StepObjective.DEVICE_COMPROMISE, StepObjective.INITIAL_ACCESS, StepObjective.CONTROL_MODIFICATION}
    ),
    VulnerabilityEffect.CODE_EXECUTION: frozenset(
        {StepObjective.DEVICE_COMPROMISE, StepObjective.INITIAL_ACCESS, StepObjective.CONTROL_MODIFICATION}
    ),
    VulnerabilityEffect.REMOTE_CODE_EXECUTION: frozenset(
        {StepObjective.DEVICE_COMPROMISE, StepObjective.INITIAL_ACCESS, StepObjective.CONTROL_MODIFICATION}
    ),
    VulnerabilityEffect.PRIVILEGE_ESCALATION: frozenset(
        {
            StepObjective.PRIVILEGE_ESCALATION,
            StepObjective.DEVICE_COMPROMISE,
            StepObjective.CONTROL_MODIFICATION,
        }
    ),
    VulnerabilityEffect.CONFIGURATION_MODIFICATION: frozenset(
        {StepObjective.CONTROL_MODIFICATION, StepObjective.PROCESS_MANIPULATION}
    ),
    VulnerabilityEffect.SESSION_HIJACK: frozenset(
        {
            StepObjective.SESSION_COMPROMISE,
            StepObjective.INTEGRITY_IMPACT,
            StepObjective.CONFIDENTIALITY_IMPACT,
            StepObjective.CONTROL_MODIFICATION,
        }
    ),
    VulnerabilityEffect.INFORMATION_DISCLOSURE: frozenset(
        {StepObjective.CONFIDENTIALITY_IMPACT, StepObjective.CREDENTIAL_ACCESS}
    ),
    VulnerabilityEffect.DENIAL_OF_SERVICE: frozenset({StepObjective.AVAILABILITY_IMPACT}),
    VulnerabilityEffect.DEVICE_REBOOT: frozenset({StepObjective.AVAILABILITY_IMPACT}),
    VulnerabilityEffect.FIRMWARE_MODIFICATION: frozenset(
        {StepObjective.DEVICE_COMPROMISE, StepObjective.CONTROL_MODIFICATION, StepObjective.INTEGRITY_IMPACT}
    ),
    VulnerabilityEffect.CREDENTIAL_DISCLOSURE: frozenset(
        {StepObjective.CREDENTIAL_ACCESS, StepObjective.CONFIDENTIALITY_IMPACT}
    ),
    VulnerabilityEffect.NETWORK_CONTROL_MODIFICATION: frozenset(
        {StepObjective.NETWORK_CONTROL_BYPASS, StepObjective.CONTROL_MODIFICATION}
    ),
}

CWE_TO_EFFECT: dict[str, VulnerabilityEffect] = {
    # Class identification only. Do not treat these mappings as proven consequences.
    "CWE-20": VulnerabilityEffect.CONFIGURATION_MODIFICATION,
    "CWE-77": VulnerabilityEffect.COMMAND_INJECTION,
    "CWE-78": VulnerabilityEffect.COMMAND_INJECTION,
    "CWE-94": VulnerabilityEffect.CODE_EXECUTION,
    "CWE-120": VulnerabilityEffect.REMOTE_CODE_EXECUTION,
    "CWE-121": VulnerabilityEffect.REMOTE_CODE_EXECUTION,
    "CWE-122": VulnerabilityEffect.REMOTE_CODE_EXECUTION,
    "CWE-200": VulnerabilityEffect.INFORMATION_DISCLOSURE,
    "CWE-269": VulnerabilityEffect.PRIVILEGE_ESCALATION,
    "CWE-287": VulnerabilityEffect.AUTHENTICATION_BYPASS,
    "CWE-290": VulnerabilityEffect.SESSION_HIJACK,
    "CWE-294": VulnerabilityEffect.SESSION_HIJACK,
    "CWE-306": VulnerabilityEffect.AUTHENTICATION_BYPASS,
    "CWE-319": VulnerabilityEffect.INFORMATION_DISCLOSURE,
    "CWE-354": VulnerabilityEffect.SESSION_HIJACK,
    "CWE-400": VulnerabilityEffect.DENIAL_OF_SERVICE,
    "CWE-522": VulnerabilityEffect.CREDENTIAL_DISCLOSURE,
    "CWE-732": VulnerabilityEffect.PRIVILEGE_ESCALATION,
    "CWE-770": VulnerabilityEffect.DENIAL_OF_SERVICE,
    "CWE-862": VulnerabilityEffect.AUTHORIZATION_BYPASS,
    "CWE-863": VulnerabilityEffect.AUTHORIZATION_BYPASS,
    "CWE-924": VulnerabilityEffect.SESSION_HIJACK,
}

DESCRIPTION_EFFECT_PATTERNS: tuple[tuple[str, VulnerabilityEffect], ...] = (
    (r"command injection", VulnerabilityEffect.COMMAND_INJECTION),
    (r"code injection", VulnerabilityEffect.CODE_EXECUTION),
    (r"execute arbitrary code", VulnerabilityEffect.REMOTE_CODE_EXECUTION),
    (r"arbitrary code execution", VulnerabilityEffect.REMOTE_CODE_EXECUTION),
    (r"remote code execution", VulnerabilityEffect.REMOTE_CODE_EXECUTION),
    (r"authentication bypass", VulnerabilityEffect.AUTHENTICATION_BYPASS),
    (r"unauthenticated remote attackers", VulnerabilityEffect.AUTHENTICATION_BYPASS),
    (r"incorrect authorization", VulnerabilityEffect.AUTHORIZATION_BYPASS),
    (r"privilege escalation", VulnerabilityEffect.PRIVILEGE_ESCALATION),
    (r"man[- ]in[- ]the[- ]middle", VulnerabilityEffect.SESSION_HIJACK),
    (r"\breplay\b", VulnerabilityEffect.SESSION_HIJACK),
    (r"denial of service", VulnerabilityEffect.DENIAL_OF_SERVICE),
    (r"resource exhaustion", VulnerabilityEffect.DENIAL_OF_SERVICE),
    (r"information disclosure", VulnerabilityEffect.INFORMATION_DISCLOSURE),
    (r"credential (?:disclosure|exposure|theft)", VulnerabilityEffect.CREDENTIAL_DISCLOSURE),
    (r"modify network", VulnerabilityEffect.NETWORK_CONTROL_MODIFICATION),
    (r"(?:modif(?:y|ying|ication of)|bypass(?:es|ing)?)\s+network\s+configuration", VulnerabilityEffect.NETWORK_CONTROL_MODIFICATION),
    (r"unauthorized modification of network", VulnerabilityEffect.NETWORK_CONTROL_MODIFICATION),
    (r"network configuration management", VulnerabilityEffect.NETWORK_CONTROL_MODIFICATION),
    (r"access[- ]control settings", VulnerabilityEffect.NETWORK_CONTROL_MODIFICATION),
    (r"network access[- ]control", VulnerabilityEffect.NETWORK_CONTROL_MODIFICATION),
    (r"segmentation controls", VulnerabilityEffect.NETWORK_CONTROL_MODIFICATION),
    (r"configuration modification", VulnerabilityEffect.CONFIGURATION_MODIFICATION),
)

EXPLICIT_SERVICE_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (r"\bweb interface\b", "web_interface", "description:web interface"),
    (r"\bweb server\b", "web_interface", "description:web server"),
    (r"\bweb-based management\b", "web_interface", "description:web-based management"),
    (r"\bssh service\b|\bssh server\b|\bssh daemon\b", "ssh", "description:ssh service"),
    (r"\bftp service\b|\bftp server\b", "ftp", "description:ftp service"),
    (r"\btelnet service\b|\btelnet server\b", "telnet", "description:telnet service"),
    (r"\bsnmp service\b|\bsnmp agent\b", "snmp", "description:snmp service"),
    (r"\bmodbus\b", "modbus", "effects:modbus"),
    (r"\bopc ua\b", "opc_ua", "effects:opc ua"),
    (r"\bdnp3\b", "dnp3", "effects:dnp3"),
    (r"\biec 61850\b", "iec_61850", "effects:iec 61850"),
    (r"\bethernet/ip\b", "ethernet_ip", "effects:ethernet/ip"),
    (r"\bprofinet\b", "profinet", "effects:profinet"),
    (r"\bmanagement interface\b", "management_interface", "description:management interface"),
)

PREREQUISITE_GATE_NAMES = frozenset(
    {
        "service",
        "authentication",
        "privileges",
        "network_position",
        "user_interaction",
    }
)


def classify_step_objective(step: AttackStep) -> StepObjective:
    blob = f"{step.name} {step.description}".lower()
    if "segmentation" in blob or ("bypass" in blob and "network" in blob):
        return StepObjective.NETWORK_CONTROL_BYPASS
    if "replay" in blob:
        return StepObjective.SESSION_COMPROMISE
    if "capture" in blob and "authentication" in blob:
        return StepObjective.SESSION_COMPROMISE
    if any(token in blob for token in ("disclose", "modify", "change")) and any(
        token in blob for token in ("program", "parameter", "settings")
    ):
        return StepObjective.CONTROL_MODIFICATION
    if "elevated permission" in blob or "elevated privileges" in blob:
        return StepObjective.PRIVILEGE_ESCALATION
    if any(token in blob for token in ("man-in-the-middle", "mitm", "session integrity", "session confidentiality")):
        return StepObjective.SESSION_COMPROMISE
    if "session" in blob and any(token in blob for token in ("intercept", "observe", "modify", "compromise")):
        return StepObjective.SESSION_COMPROMISE
    if any(token in blob for token in ("denial of service", "availability", "resource exhaustion")):
        return StepObjective.AVAILABILITY_IMPACT
    if any(token in blob for token in ("information disclosure", "exfiltrat", "credential theft", "confidentiality")):
        return StepObjective.CONFIDENTIALITY_IMPACT
    if any(token in blob for token in ("privilege escalation", "elevate privilege")):
        return StepObjective.PRIVILEGE_ESCALATION
    if any(token in blob for token in ("lateral movement", "lateral path", "pivot")):
        return StepObjective.LATERAL_MOVEMENT
    if any(token in blob for token in ("initial access", "entry point", "foothold")):
        return StepObjective.INITIAL_ACCESS
    if any(token in blob for token in ("credential", "password", "login", "authenticate")):
        return StepObjective.CREDENTIAL_ACCESS
    if "compromise" in blob and "compromised" not in blob:
        return StepObjective.DEVICE_COMPROMISE
    return StepObjective.OTHER


def extract_vulnerability_effects(
    *,
    cwes: frozenset[str] | set[str],
    description: str,
    effects: list[str],
) -> set[VulnerabilityEffect]:
    """Derive technical consequences from CVE-local description/effects only.

    CWE identifies weakness class; it is not a proven consequence. del cwes
    keeps the call signature stable for existing callers.
    """
    del cwes
    found: set[VulnerabilityEffect] = set()
    blob = " ".join([description, " ".join(effects)]).lower()
    if not blob.strip():
        return found
    for pattern, effect in DESCRIPTION_EFFECT_PATTERNS:
        if re.search(pattern, blob, flags=re.IGNORECASE):
            found.add(effect)
    return found


def effect_supports_objective(
    vulnerability_effects: set[VulnerabilityEffect],
    objective: StepObjective,
) -> bool:
    if objective == StepObjective.OTHER or not vulnerability_effects:
        return False
    return any(objective in EFFECT_OBJECTIVE_MATRIX.get(effect, frozenset()) for effect in vulnerability_effects)


def extract_required_service(
    *,
    description: str,
    effects: list[str],
    prerequisites_text: str = "",
) -> tuple[str | None, str]:
    """Return (service_id, provenance) only for explicit evidence."""
    for source_label, blob in (
        ("effects", " ".join(effects).lower()),
        ("description", description.lower()),
        ("prerequisites", prerequisites_text.lower()),
    ):
        if not blob.strip():
            continue
        for pattern, service_id, provenance_suffix in EXPLICIT_SERVICE_PATTERNS:
            if re.search(pattern, blob, flags=re.IGNORECASE):
                return service_id, f"{source_label}:{provenance_suffix.split(':', 1)[-1]}"
    return None, ""


def description_confirms_effects(
    description: str,
    effects: list[str],
    vulnerability_effects: set[VulnerabilityEffect],
) -> bool:
    if not vulnerability_effects:
        return False
    blob = " ".join([description, " ".join(effects)]).lower()
    for pattern, effect in DESCRIPTION_EFFECT_PATTERNS:
        if effect in vulnerability_effects and re.search(pattern, blob, flags=re.IGNORECASE):
            return True
    return False


OBJECTIVE_NEGATIVE_PATTERNS: dict[StepObjective, frozenset[str]] = {
    StepObjective.NETWORK_CONTROL_BYPASS: frozenset(
        {
            "clearing the local system log",
            "clear system log",
            "denial of service",
            "resource exhaustion",
            "information disclosure only",
            "physical access",
            "spi bus",
        }
    ),
    StepObjective.DEVICE_COMPROMISE: frozenset(
        {
            "clearing the local system log",
            "clear system log",
            "denial of service only",
            "physical access",
            "spi bus",
        }
    ),
    StepObjective.SESSION_COMPROMISE: frozenset(
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


def effect_blocked_for_objective(
    description: str,
    effects: list[str],
    objective: StepObjective,
) -> bool:
    blob = " ".join([description, " ".join(effects)]).lower()
    return any(pattern in blob for pattern in OBJECTIVE_NEGATIVE_PATTERNS.get(objective, frozenset()))


def enrich_auth_from_description(description: str) -> tuple[bool | None, str | None, str]:
    """Fill missing auth/privilege only from explicit exploitation phrases."""
    lowered = description.lower()
    if not lowered:
        return None, None, ""

    if re.search(r"\bunauthenticated remote attackers?\b", lowered):
        return False, None, "description:unauthenticated remote attackers"
    if re.search(r"\bwithout authentication\b", lowered):
        return False, None, "description:without authentication"
    if re.search(r"\bauthenticated privileged remote attackers?\b", lowered):
        return True, "high", "description:authenticated privileged remote attacker"
    if re.search(r"\bauthenticated remote attackers?\b", lowered):
        privilege = "low"
        if re.search(r"\b(guest|low[- ]privilege)\b", lowered):
            privilege = "low"
        elif re.search(r"\b(administrator|administrative|privileged|high[- ]privilege)\b", lowered):
            privilege = "high"
        return True, privilege, "description:authenticated remote attacker"
    return None, None, ""


def _check_status(checks: list[ApplicabilityCheck], name: str) -> TruthValue | None:
    match = next((check for check in checks if check.name == name), None)
    return match.status if match else None


def compute_final_status(
    checks: list[ApplicabilityCheck],
    *,
    has_conflicting_evidence: bool = False,
) -> FinalStatus:
    if has_conflicting_evidence:
        return FinalStatus.CONFLICTING_EVIDENCE

    product = _check_status(checks, "product")
    if product == TruthValue.FALSE:
        return FinalStatus.REJECTED_PRODUCT_MISMATCH

    dimension_names = (
        "serial_number",
        "firmware_version",
        "software_version",
        "hardware_version",
        "product_revision",
        "configuration",
        "version",
    )
    unknown_dimensions: list[str] = []
    for name in dimension_names:
        status = _check_status(checks, name)
        if status is None or status == TruthValue.NOT_APPLICABLE:
            continue
        if status == TruthValue.FALSE:
            if name in FIRMWARE_GATE_NAMES or name == "software_version":
                return FinalStatus.REJECTED_VERSION_MISMATCH
            return FinalStatus.REJECTED_DIMENSION_MISMATCH
        if status == TruthValue.UNKNOWN:
            unknown_dimensions.append(name)

    effect = _check_status(checks, "technical_effect")
    if effect == TruthValue.FALSE:
        return FinalStatus.REJECTED_EFFECT_MISMATCH

    for name in PREREQUISITE_GATE_NAMES:
        status = _check_status(checks, name)
        if status == TruthValue.FALSE:
            return FinalStatus.REJECTED_PREREQUISITE_MISMATCH

    # UNKNOWN product/effect stay visible as insufficient. They must not hide a
    # prior FALSE, and they must not be rewritten as rejected.
    if product == TruthValue.UNKNOWN:
        return FinalStatus.INSUFFICIENT_CONTEXT
    if effect == TruthValue.UNKNOWN:
        return FinalStatus.INSUFFICIENT_CONTEXT

    if any(name in FIRMWARE_GATE_NAMES for name in unknown_dimensions):
        return FinalStatus.CONDITIONAL_VERSION_UNKNOWN
    if unknown_dimensions:
        return FinalStatus.CONDITIONAL_DIMENSION_UNKNOWN

    for name in PREREQUISITE_GATE_NAMES:
        status = _check_status(checks, name)
        if status == TruthValue.UNKNOWN:
            return FinalStatus.CONDITIONAL_PREREQUISITE_UNKNOWN

    return FinalStatus.VERIFIED_APPLICABLE


def disposition_from_final_status(final_status: FinalStatus) -> str:
    if final_status == FinalStatus.VERIFIED_APPLICABLE:
        return "applicable"
    if final_status.value.startswith("conditional_"):
        return "conditional"
    if final_status == FinalStatus.INSUFFICIENT_CONTEXT:
        return "insufficient"
    return "rejected"


def compute_rank_score(checks: list[ApplicabilityCheck], unresolved_count: int) -> int:
    score = 0
    weights = {
        "product": 1000,
        "part_number": 120,
        "model": 80,
        "version": 250,
        "serial_number": 250,
        "firmware_version": 250,
        "software_version": 250,
        "hardware_version": 80,
        "technical_effect": 300,
        "service": 40,
        "authentication": 40,
        "privileges": 40,
        "network_position": 40,
        "user_interaction": 20,
    }
    for check in checks:
        weight = weights.get(check.name, 0)
        if check.status == TruthValue.TRUE:
            score += weight
        elif check.status == TruthValue.UNKNOWN and weight:
            score += max(weight // 4, 5)
    score -= unresolved_count * 10
    return score


GATE_LABELS = {
    "product": "Product",
    "version": "Version",
    "serial_number": "Serial",
    "firmware_version": "Firmware",
    "software_version": "Software",
    "hardware_version": "Hardware",
    "network_position": "Network pos.",
    "authentication": "Authentication",
    "privileges": "Privileges",
    "service": "Service",
    "user_interaction": "User action",
    "technical_effect": "Effect match",
}


def format_gate_summary(cve_id: str, final_status: FinalStatus, checks: list[ApplicabilityCheck]) -> str:
    lines = [cve_id]
    for gate_name, label in GATE_LABELS.items():
        status = _check_status(checks, gate_name)
        if status is None:
            continue
        lines.append(f"{label + ':':16} {status.value.replace('known_', '').upper()}")
    lines.append(f"Final:            {final_status.value.upper()}")
    return "\n".join(lines)


def gate_table(checks: list[ApplicabilityCheck]) -> dict[str, str]:
    table: dict[str, str] = {}
    for gate_name, label in GATE_LABELS.items():
        status = _check_status(checks, gate_name)
        if status is not None:
            table[label] = status.value.replace("known_", "").upper()
    return table
