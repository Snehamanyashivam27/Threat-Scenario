from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from rag.models.answer import SourceReference
from rag.scenario.evidence import StepEvidence


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


@dataclass(slots=True)
class ComponentSource:
    origin: str = ""
    evidence: str = ""
    reference: str | None = None


@dataclass(slots=True)
class ComponentModel:
    id: str
    name: str
    type: str = ""
    subtype: str = ""
    vendor: str | None = None
    manufacturer: str | None = None
    product_family: str | None = None
    model: str | None = None
    part_number: str | None = None
    serial_number: str | None = None
    hardware_version: str | None = None
    product_revision: str | None = None
    software_version: str | None = None
    firmware_version: str | None = None
    operating_system: str | None = None
    software: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    authentication: dict[str, Any] = field(default_factory=dict)
    authorization: dict[str, Any] = field(default_factory=dict)
    remote_access: dict[str, Any] = field(default_factory=dict)
    network_zone: str | None = None
    interfaces: list[dict[str, Any]] = field(default_factory=list)
    operational_states: list[str] = field(default_factory=list)
    provided_fields: set[str] = field(default_factory=set)
    source: ComponentSource | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ComponentModel:
        source_data = data.get("source") or {}
        source = ComponentSource(
            origin=str(source_data.get("origin") or ""),
            evidence=str(source_data.get("evidence") or ""),
            reference=source_data.get("reference"),
        )
        services_raw = data.get("services") or []
        services: list[str] = []
        if isinstance(services_raw, list):
            for item in services_raw:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("service") or item.get("type")
                    if name:
                        services.append(str(name))
                elif item:
                    services.append(str(item))
        authentication = data.get("authentication") if isinstance(data.get("authentication"), dict) else {}
        authorization = data.get("authorization") if isinstance(data.get("authorization"), dict) else {}
        remote_access = data.get("remote_access") if isinstance(data.get("remote_access"), dict) else {}
        interfaces = [dict(item) for item in data.get("interfaces") or [] if isinstance(item, dict)]
        protocols = [str(item) for item in data.get("communication_protocols") or [] if item]
        for interface in interfaces:
            protocols.extend(str(item) for item in interface.get("protocols") or [] if item)
        software_entries: list[str] = []
        for item in data.get("software") or []:
            if isinstance(item, dict):
                name = str(item.get("name") or item.get("product") or "").strip()
                version = str(item.get("version") or "").strip()
                if name and version:
                    software_entries.append(f"{name} version {version}")
                elif version:
                    software_entries.append(f"version {version}")
                elif name:
                    software_entries.append(name)
            elif item:
                software_entries.append(str(item))
        return cls(
            id=str(data.get("id") or ""),
            name=str(data.get("name") or ""),
            type=str(data.get("type") or ""),
            subtype=str(data.get("subtype") or ""),
            vendor=data.get("vendor"),
            manufacturer=data.get("manufacturer"),
            product_family=data.get("product_family"),
            model=data.get("model"),
            part_number=data.get("part_number"),
            serial_number=_optional_text(data.get("serial_number")),
            hardware_version=_optional_text(data.get("hardware_version")),
            product_revision=_optional_text(data.get("product_revision")),
            software_version=_optional_text(data.get("software_version")),
            firmware_version=data.get("firmware_version"),
            operating_system=data.get("operating_system"),
            software=software_entries,
            services=services,
            protocols=list(dict.fromkeys(protocols)),
            authentication=dict(authentication or {}),
            authorization=dict(authorization or {}),
            remote_access=dict(remote_access or {}),
            network_zone=data.get("network_zone"),
            interfaces=interfaces,
            operational_states=[str(item) for item in data.get("operational_states") or [] if item],
            provided_fields=set(data),
            source=source,
        )

    def advisory_reference(self) -> str | None:
        if self.source and self.source.reference:
            return str(self.source.reference)
        return None

    def product_label(self) -> str:
        parts = [part for part in (self.vendor, self.product_family, self.model) if part]
        deduped: list[str] = []
        seen: set[str] = set()
        for part in parts:
            normalized = part.strip()
            if not normalized or normalized.lower() in seen:
                continue
            seen.add(normalized.lower())
            deduped.append(normalized)
        return " ".join(deduped)


@dataclass(slots=True)
class AttackerProfile:
    id: str = ""
    type: str = ""
    description: str = ""
    capabilities: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ComponentReference:
    component_id: str
    component_name: str
    role: str = ""


@dataclass(slots=True)
class AttackStep:
    sequence: int
    step_id: str
    name: str
    source_component_id: str | None
    target_component_id: str | None
    description: str
    required_conditions: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScenarioImpact:
    affected_component_id: str = ""
    confidentiality: str = ""
    integrity: str = ""
    availability: str = ""
    safety: str = ""
    impact_categories: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScenarioModel:
    scenario_id: str
    title: str
    scenario_type: str = ""
    operational_state: str = ""
    attacker_profile: AttackerProfile | None = None
    entry_point: ComponentReference | None = None
    target: ComponentReference | None = None
    attack_path: list[AttackStep] = field(default_factory=list)
    impact: ScenarioImpact | None = None
    global_preconditions: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScenarioBundle:
    scenario: ScenarioModel
    components_by_id: dict[str, ComponentModel]
    scenario_dir: str = ""


@dataclass(slots=True)
class StepQuery:
    step: AttackStep
    query: str
    query_type: str = "primary"


@dataclass(slots=True)
class StepEnrichment:
    step: AttackStep
    primary_query: str
    primary_answer: str
    advisory_query: str | None = None
    advisory_answer: str | None = None
    advisory_context: str | None = None
    retrieved_text: str | None = None
    sources: list[SourceReference] = field(default_factory=list)
    evidence: StepEvidence | None = None


@dataclass(slots=True)
class ScenarioNarrativeResult:
    scenario_id: str
    title: str
    narrative: str
    sources: list[SourceReference] = field(default_factory=list)
    step_enrichments: list[StepEnrichment] = field(default_factory=list)
    evidence: list[StepEvidence] = field(default_factory=list)
