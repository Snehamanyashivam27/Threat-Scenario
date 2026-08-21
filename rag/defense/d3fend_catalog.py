from __future__ import annotations

"""Frozen D3FEND-style control catalog.

Lookup only. Does not infer ATT&CK technique IDs, generate prose, or call an LLM.
"""

from rag.defense.models import D3FendControlSpec
from rag.scenario.applicability import StepObjective, VulnerabilityEffect

D3_SU = D3FendControlSpec(
    "Harden",
    "D3-SU",
    "Software Update",
    "Apply the vendor software or firmware update for the affected component.",
)
D3_AH = D3FendControlSpec(
    "Harden",
    "D3-AH",
    "Application Hardening",
    "Harden exposed services and disable unused application functions on the target component.",
)
D3_PH = D3FendControlSpec(
    "Harden",
    "D3-PH",
    "Platform Hardening",
    "Harden operating-system and platform configuration against unauthorized change.",
)
D3_CH = D3FendControlSpec(
    "Harden",
    "D3-CH",
    "Credential Hardening",
    "Replace default or shared credentials and enforce unique, managed secrets.",
)
D3_MFA = D3FendControlSpec(
    "Harden",
    "D3-MFA",
    "Multi-factor Authentication",
    "Require multi-factor authentication for privileged and remote maintenance access.",
)
D3_UAP = D3FendControlSpec(
    "Harden",
    "D3-UAP",
    "User Account Permissions",
    "Restrict privileged and management accounts to the minimum required roles.",
)
D3_EAL = D3FendControlSpec(
    "Harden",
    "D3-EAL",
    "Executable Allowlisting",
    "Allow only authorized executables and engineering tools on the component.",
)
D3_NI = D3FendControlSpec(
    "Isolate",
    "D3-NI",
    "Network Isolation",
    "Enforce network segmentation so unauthorized paths cannot reach the protected zone.",
)
D3_NTF = D3FendControlSpec(
    "Isolate",
    "D3-NTF",
    "Network Traffic Filtering",
    "Filter management and east-west traffic to authorized sources, destinations, and protocols.",
)
D3_ITF = D3FendControlSpec(
    "Isolate",
    "D3-ITF",
    "Inbound Traffic Filtering",
    "Restrict inbound access to management and process interfaces.",
)
D3_EI = D3FendControlSpec(
    "Isolate",
    "D3-EI",
    "Execution Isolation",
    "Constrain untrusted execution so injected commands cannot run with elevated privileges.",
)
D3_NTA = D3FendControlSpec(
    "Detect",
    "D3-NTA",
    "Network Traffic Analysis",
    "Monitor OT and management traffic with IDS or network traffic analysis for unauthorized flows.",
)
D3_ANAA = D3FendControlSpec(
    "Detect",
    "D3-ANAA",
    "Administrative Network Activity Analysis",
    "Detect anomalous administrative or maintenance-session activity on the management plane.",
)
D3_PM = D3FendControlSpec(
    "Detect",
    "D3-PM",
    "Platform Monitoring",
    "Monitor the platform for unauthorized configuration, privilege, or integrity changes.",
)
D3_PA = D3FendControlSpec(
    "Detect",
    "D3-PA",
    "Process Analysis",
    "Detect unauthorized process or command execution on the control component.",
)
D3_BA = D3FendControlSpec(
    "Restore",
    "D3-BA",
    "Backup",
    "Maintain recoverable configuration and operational backups for the affected function.",
)

TACTIC_RANK = {
    "Harden": 0,
    "Detect": 1,
    "Isolate": 2,
    "Deceive": 3,
    "Evict": 4,
    "Restore": 5,
}

SOURCE_ATTACK_MITIGATION = "attack_mitigation"
SOURCE_CSAF = "csaf_remediation"
SOURCE_TECHNIQUE = "attack_technique"
SOURCE_EFFECT = "vulnerability_effect"
SOURCE_CWE = "cwe"
SOURCE_OBJECTIVE = "step_objective"
SOURCE_STEP_ID = "step_id"

SOURCE_RANK = {
    SOURCE_ATTACK_MITIGATION: 0,
    SOURCE_CSAF: 1,
    SOURCE_TECHNIQUE: 2,
    SOURCE_EFFECT: 3,
    SOURCE_CWE: 4,
    SOURCE_OBJECTIVE: 5,
    SOURCE_STEP_ID: 6,
}

_MITIGATION_ID_MAP: dict[str, tuple[D3FendControlSpec, ...]] = {
    "M1030": (D3_NI, D3_NTF),
    "M1031": (D3_NTA,),
    "M1032": (D3_MFA,),
    "M1033": (D3_EAL,),
    "M1035": (D3_NI, D3_NTF),
    "M1037": (D3_NTF, D3_ITF),
    "M1038": (D3_EI, D3_EAL),
    "M1040": (D3_PA, D3_EI),
    "M1042": (D3_AH,),
    "M1047": (D3_PM,),
    "M1048": (D3_EI,),
    "M1049": (D3_PA,),
    "M1050": (D3_AH,),
    "M1051": (D3_SU,),
    "M1018": (D3_UAP,),
    "M1026": (D3_UAP,),
    "M1028": (D3_PH,),
    "M1053": (D3_BA,),
    "M1054": (D3_AH, D3_PH),
    "M0800": (D3_UAP,),
    "M0801": (D3_UAP,),
    "M0804": (D3_MFA, D3_CH),
    "M0807": (D3_NTF, D3_ITF),
    "M0813": (D3_BA,),
    "M0814": (D3_PH, D3_NTF),
    "M0930": (D3_NI, D3_NTF),
    "M0931": (D3_NTA,),
    "M0936": (D3_NTF, D3_ITF),
    "M0942": (D3_AH,),
    "M0947": (D3_PM,),
    "M0948": (D3_EI,),
    "M0949": (D3_PA,),
    "M0950": (D3_AH,),
    "M0951": (D3_SU,),
}

_MITIGATION_NAME_MAP: dict[str, tuple[D3FendControlSpec, ...]] = {
    "network isolation": (D3_NI,),
    "network segmentation": (D3_NI, D3_NTF),
    "filter network traffic": (D3_NTF, D3_ITF),
    "network intrusion prevention": (D3_NTA,),
    "update software": (D3_SU,),
    "access restriction": (D3_NTF, D3_UAP),
    "multi-factor authentication": (D3_MFA,),
    "privileged account management": (D3_UAP,),
    "user account management": (D3_UAP,),
    "execution prevention": (D3_EI, D3_EAL),
    "application isolation and sandboxing": (D3_EI,),
    "audit": (D3_PM,),
    "antivirus/antimalware": (D3_PA,),
    "exploit protection": (D3_AH,),
    "operating system configuration": (D3_PH,),
    "software configuration": (D3_AH,),
    "data backup": (D3_BA,),
    "network allowlists": (D3_NTF, D3_ITF),
    "authorization enforcement": (D3_UAP,),
    "access management": (D3_UAP,),
    "human user authentication": (D3_MFA, D3_CH),
}

_TECHNIQUE_ID_MAP: dict[str, tuple[D3FendControlSpec, ...]] = {
    "T0812": (D3_CH, D3_MFA, D3_ANAA),
    "T0819": (D3_ITF, D3_AH, D3_NTA),
    "T0831": (D3_PM, D3_AH, D3_UAP),
    "T0855": (D3_NTA, D3_AH, D3_UAP),
    "T0866": (D3_NI, D3_NTF, D3_NTA),
    "T0883": (D3_ITF, D3_NI, D3_NTA),
    "T0886": (D3_NTF, D3_MFA, D3_ANAA),
    "T1021": (D3_NTF, D3_MFA, D3_NTA),
    "T1059": (D3_EI, D3_PA, D3_EAL),
    "T1078": (D3_MFA, D3_UAP, D3_ANAA),
    "T1190": (D3_ITF, D3_AH, D3_NTA),
    "T1210": (D3_NI, D3_NTF, D3_NTA),
    "T1570": (D3_NI, D3_NTF, D3_NTA),
}

_OBJECTIVE_MAP: dict[StepObjective, tuple[D3FendControlSpec, ...]] = {
    StepObjective.INITIAL_ACCESS: (D3_NI, D3_ITF, D3_MFA, D3_ANAA),
    StepObjective.CREDENTIAL_ACCESS: (D3_CH, D3_MFA, D3_UAP, D3_ANAA),
    StepObjective.LATERAL_MOVEMENT: (D3_NI, D3_NTF, D3_NTA),
    StepObjective.NETWORK_CONTROL_BYPASS: (D3_NI, D3_NTF, D3_NTA),
    StepObjective.DEVICE_COMPROMISE: (D3_SU, D3_AH, D3_EI, D3_PA),
    StepObjective.CONTROL_MODIFICATION: (D3_AH, D3_UAP, D3_PM),
    StepObjective.PRIVILEGE_ESCALATION: (D3_UAP, D3_EI, D3_PM),
    StepObjective.SESSION_COMPROMISE: (D3_MFA, D3_NTF, D3_ANAA),
    StepObjective.PROCESS_MANIPULATION: (D3_AH, D3_PA, D3_PM),
    StepObjective.CONFIDENTIALITY_IMPACT: (D3_NTF, D3_NTA, D3_CH),
    StepObjective.INTEGRITY_IMPACT: (D3_AH, D3_PM, D3_UAP),
    StepObjective.AVAILABILITY_IMPACT: (D3_PM, D3_BA, D3_NTA),
}

_EFFECT_MAP: dict[VulnerabilityEffect, tuple[D3FendControlSpec, ...]] = {
    VulnerabilityEffect.COMMAND_INJECTION: (D3_EI, D3_PA, D3_AH),
    VulnerabilityEffect.CODE_EXECUTION: (D3_EI, D3_PA, D3_AH),
    VulnerabilityEffect.REMOTE_CODE_EXECUTION: (D3_EI, D3_PA, D3_ITF),
    VulnerabilityEffect.AUTHENTICATION_BYPASS: (D3_MFA, D3_CH, D3_ANAA),
    VulnerabilityEffect.AUTHORIZATION_BYPASS: (D3_UAP, D3_PM),
    VulnerabilityEffect.PRIVILEGE_ESCALATION: (D3_UAP, D3_EI, D3_PM),
    VulnerabilityEffect.NETWORK_CONTROL_MODIFICATION: (D3_NI, D3_NTF, D3_NTA),
    VulnerabilityEffect.CONFIGURATION_MODIFICATION: (D3_AH, D3_PM, D3_UAP),
    VulnerabilityEffect.SESSION_HIJACK: (D3_MFA, D3_NTF, D3_ANAA),
    VulnerabilityEffect.CREDENTIAL_DISCLOSURE: (D3_CH, D3_MFA, D3_ANAA),
    VulnerabilityEffect.INFORMATION_DISCLOSURE: (D3_NTF, D3_NTA),
    VulnerabilityEffect.DENIAL_OF_SERVICE: (D3_NTF, D3_PM, D3_BA),
    VulnerabilityEffect.DEVICE_REBOOT: (D3_PM, D3_BA),
    VulnerabilityEffect.FIRMWARE_MODIFICATION: (D3_SU, D3_PM, D3_AH),
}

_CWE_MAP: dict[str, tuple[D3FendControlSpec, ...]] = {
    "CWE-77": (D3_EI, D3_PA, D3_AH),
    "CWE-78": (D3_EI, D3_PA, D3_AH),
    "CWE-94": (D3_EI, D3_PA, D3_AH),
    "CWE-287": (D3_MFA, D3_CH, D3_ANAA),
    "CWE-306": (D3_MFA, D3_ITF, D3_ANAA),
    "CWE-798": (D3_CH, D3_MFA),
    "CWE-863": (D3_UAP, D3_PM),
    "CWE-22": (D3_AH, D3_PA),
    "CWE-400": (D3_NTF, D3_PM, D3_BA),
}

_STEP_ID_TOKEN_MAP: tuple[tuple[frozenset[str], tuple[D3FendControlSpec, ...]], ...] = (
    (frozenset({"bypass", "segmentation"}), (D3_NI, D3_NTF, D3_NTA)),
    (frozenset({"lateral", "movement"}), (D3_NI, D3_NTF, D3_NTA)),
    (frozenset({"initial", "access"}), (D3_NI, D3_ITF, D3_MFA, D3_ANAA)),
    (frozenset({"access", "network"}), (D3_NTF, D3_ITF, D3_ANAA)),
    (frozenset({"compromise", "control"}), (D3_SU, D3_AH, D3_EI, D3_PA)),
    (frozenset({"impact"}), (D3_PM, D3_BA, D3_NTA)),
)

_CSAF_CATEGORY_MAP: dict[str, tuple[D3FendControlSpec, ...]] = {
    "vendor_fix": (D3_SU,),
    "mitigation": (D3_AH,),
    "workaround": (D3_NTF, D3_AH),
}


def controls_for_mitigation(*, mitigation_id: str, mitigation_name: str) -> tuple[D3FendControlSpec, ...]:
    found = _MITIGATION_ID_MAP.get(_normalize_id(mitigation_id))
    if found:
        return found
    return _MITIGATION_NAME_MAP.get(_normalize_name(mitigation_name), ())


def controls_for_technique(technique_id: str) -> tuple[D3FendControlSpec, ...]:
    return _TECHNIQUE_ID_MAP.get(_normalize_id(technique_id), ())


def controls_for_objective(objective: StepObjective) -> tuple[D3FendControlSpec, ...]:
    if objective is StepObjective.OTHER:
        return ()
    return _OBJECTIVE_MAP.get(objective, ())


def controls_for_effect(effect: VulnerabilityEffect) -> tuple[D3FendControlSpec, ...]:
    return _EFFECT_MAP.get(effect, ())


def controls_for_cwe(cwe_id: str) -> tuple[D3FendControlSpec, ...]:
    return _CWE_MAP.get(_normalize_id(cwe_id), ())


def controls_for_csaf_category(category: str, details: str = "") -> tuple[D3FendControlSpec, ...]:
    category_key = str(category or "").strip().casefold()
    if category_key == "vendor_fix":
        return _CSAF_CATEGORY_MAP["vendor_fix"]
    blob = str(details or "").casefold()
    if any(token in blob for token in ("segment", "isolat", "firewall", "vlan", "acl")):
        return (D3_NI, D3_NTF)
    if any(token in blob for token in ("intrusion", "ids", "monitor", "detect", "log")):
        return (D3_NTA, D3_PM)
    return _CSAF_CATEGORY_MAP.get(category_key, ())


def controls_for_step_id(step_id: str) -> tuple[D3FendControlSpec, ...]:
    tokens = _step_id_tokens(step_id)
    if not tokens:
        return ()
    matched: list[D3FendControlSpec] = []
    seen: set[str] = set()
    for required, specs in _STEP_ID_TOKEN_MAP:
        if required <= tokens:
            for spec in specs:
                if spec.technique_id in seen:
                    continue
                seen.add(spec.technique_id)
                matched.append(spec)
    return tuple(matched)


def _normalize_id(value: str) -> str:
    return str(value or "").strip().upper()


def _normalize_name(value: str) -> str:
    return " ".join(str(value or "").casefold().split())


def _step_id_tokens(step_id: str) -> frozenset[str]:
    parts = str(step_id or "").casefold().replace("_", "-").split("-")
    return frozenset(part for part in parts if part and part != "step")
