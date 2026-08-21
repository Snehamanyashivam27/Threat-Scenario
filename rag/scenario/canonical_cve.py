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

from dataclasses import dataclass, field
from typing import Any
import re


@dataclass(frozen=True, slots=True)
class EvidenceValue:
    value: str
    source: str = ""
    advisory_id: str = ""
    cve_id: str = ""


@dataclass(frozen=True, slots=True)
class ApplicabilityConstraint:
    dimension: str
    operator: str
    value: str = ""
    source: str = ""
    advisory_id: str = ""
    cve_id: str = ""

    def describe(self) -> str:
        if self.dimension == "serial_number" and self.operator in {"all", "*"}:
            return "all serial numbers are affected"
        if self.operator in {"all", "*"}:
            return f"all {self.dimension.replace('_', ' ')} values are affected"
        if self.operator in {"<", "prior_to", "before"}:
            return f"{self.dimension.replace('_', ' ')} earlier than {self.value}"
        if self.operator in {"<=", "and_prior", "through"}:
            return f"{self.dimension.replace('_', ' ')} {self.value} and prior"
        if self.operator in {">", "after"}:
            return f"{self.dimension.replace('_', ' ')} later than {self.value}"
        if self.operator in {">=", "and_later"}:
            return f"{self.dimension.replace('_', ' ')} {self.value} and later"
        if self.operator in {"=", "eq", "exact"}:
            return f"{self.dimension.replace('_', ' ')} {self.value}"
        return f"{self.dimension.replace('_', ' ')} {self.operator} {self.value}".strip()


@dataclass(slots=True)
class CanonicalCveEvidence:
    """One CVE's facts only — never merge fields from sibling CVEs."""

    cve_id: str
    advisory_id: str = ""
    vendor: str = ""
    products: list[str] = field(default_factory=list)
    models: list[str] = field(default_factory=list)
    part_numbers: list[str] = field(default_factory=list)
    version_constraints: list[ApplicabilityConstraint] = field(default_factory=list)
    serial_constraints: list[ApplicabilityConstraint] = field(default_factory=list)
    vulnerability_type: str = ""
    cwes: frozenset[str] = field(default_factory=frozenset)
    prerequisites: list[dict[str, Any]] = field(default_factory=list)
    technical_effects: list[str] = field(default_factory=list)
    description: str = ""
    provenance: dict[str, str] = field(default_factory=dict)
    source_type: str = "cisa_csv"
    raw_text: str = ""


@dataclass(slots=True)
class TechnicalContextFact:
    """Narrator-safe, CVE-independent fact. Never carries retrieval text or CVE IDs."""

    category: str
    polarity: str
    statement: str
    evidence_state: str
    token: str = ""


@dataclass(slots=True)
class NarratorStepEvidence:
    step_id: str
    scenario_description: str
    selected_cve: str | None
    target_product: str
    applicability_status: str
    confirmed_conditions: list[str] = field(default_factory=list)
    unresolved_conditions: list[str] = field(default_factory=list)
    vulnerability_type: str = ""
    prerequisites: list[str] = field(default_factory=list)
    technical_effect: str = ""
    vulnerable_component_id: str | None = None
    action_target_id: str | None = None
    downstream_affected_id: str | None = None
    technical_context: list[TechnicalContextFact] = field(default_factory=list)


def isolate_cwes_for_cve(
    *,
    cve_id: str,
    all_cves: list[str],
    all_cwes: frozenset[str] | set[str],
) -> frozenset[str]:
    """Prevent CWE leakage across CVEs in a multi-CVE advisory aggregate.

    If one CVE and one-or-more CWEs: attribute CWEs to that CVE.
    If multiple CVEs and exactly one CWE: share that single CWE.
    If multiple CVEs and multiple CWEs: attribute none (unknown) rather than leak.
    """
    cwes = frozenset(cwe.upper() for cwe in all_cwes)
    if not cwes:
        return frozenset()
    if len(all_cves) <= 1:
        return cwes
    if len(cwes) == 1:
        return cwes
    return frozenset()


def parse_constraint_text(
    text: str,
    *,
    cve_id: str = "",
    advisory_id: str = "",
    source: str = "",
) -> list[ApplicabilityConstraint]:
    """Parse advisory applicability text into typed constraints."""
    if not text or not text.strip():
        return []
    lowered = text.lower()
    constraints: list[ApplicabilityConstraint] = []

    def _add(dimension: str, operator: str, value: str = "") -> None:
        constraints.append(
            ApplicabilityConstraint(
                dimension=dimension,
                operator=operator,
                value=value,
                source=source,
                advisory_id=advisory_id,
                cve_id=cve_id,
            )
        )

    if "all serial" in lowered:
        _add("serial_number", "all")

    serial_prior = re.search(
        r"serial\s+numbers?\s+(\S+)\s+and prior",
        text,
        flags=re.IGNORECASE,
    )
    if serial_prior:
        _add("serial_number", "<=", serial_prior.group(1).rstrip(".,;"))
    serial_later = re.search(
        r"serial\s+numbers?\s+(\S+)\s+and later",
        text,
        flags=re.IGNORECASE,
    )
    if serial_later:
        _add("serial_number", ">=", serial_later.group(1).rstrip(".,;"))
    serial_exact = re.search(
        r"serial\s+numbers?\s+(\S+)\s*$",
        text,
        flags=re.IGNORECASE,
    )
    if serial_exact and "and prior" not in lowered and "and later" not in lowered and "all serial" not in lowered:
        _add("serial_number", "=", serial_exact.group(1).rstrip(".,;"))

    bounded = any(token in lowered for token in ("prior", "before", "earlier", "later", "<", ">"))
    if re_all_versions(lowered) and "serial" not in lowered and not bounded:
        _add(_infer_dimension(text), "all")

    if "serial" not in lowered:
        for match in re.finditer(
            r"(?:prior to|before|earlier than|<)\s*(V?\d+(?:\.\d+)*)",
            text,
            flags=re.IGNORECASE,
        ):
            _add(_infer_dimension(text), "<", match.group(1))
        for match in re.finditer(
            r'(?:versions?\s*)?"?(\d+(?:\.\d+)*)"?\s+and prior',
            text,
            flags=re.IGNORECASE,
        ):
            _add(_infer_dimension(text), "<=", match.group(1))
        for match in re.finditer(
            r"\bversion\s+(\d+(?:\.\d+)*)\b",
            text,
            flags=re.IGNORECASE,
        ):
            if "prior" in lowered or "before" in lowered or "<" in text:
                continue
            _add(_infer_dimension(text), "=", match.group(1))
    return constraints


def re_all_versions(lowered: str) -> bool:
    return "all versions" in lowered or lowered.strip() in {"all", "*"}


def _infer_dimension(text: str) -> str:
    lowered = text.lower()
    if "serial" in lowered:
        return "serial_number"
    if "hardware" in lowered:
        return "hardware_version"
    if "software" in lowered or "application" in lowered:
        return "software_version"
    if "revision" in lowered:
        return "product_revision"
    if "configuration" in lowered:
        return "configuration"
    return "firmware_version"


def condition_text_for_constraint(constraint: ApplicabilityConstraint) -> str:
    if constraint.dimension == "serial_number":
        if constraint.operator == "all":
            return ""
        return "the device serial number is within the affected range"
    if constraint.operator == "all":
        return ""
    label = constraint.dimension.replace("_", " ")
    if constraint.operator in {"<", "prior_to", "before"}:
        return f"the deployed {label} is earlier than {constraint.value}"
    if constraint.operator in {"<=", "and_prior"}:
        return f"the deployed {label} is {constraint.value} or prior"
    if constraint.operator in {"=", "eq", "exact"}:
        return f"the deployed {label} is {constraint.value}"
    return f"the deployed {label} is within the affected range"
