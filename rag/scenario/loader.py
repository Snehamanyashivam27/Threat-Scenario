from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rag.scenario.models import (
    AttackStep,
    AttackerProfile,
    ComponentModel,
    ComponentReference,
    ScenarioBundle,
    ScenarioImpact,
    ScenarioModel,
)


class ScenarioLoadError(ValueError):
    pass


def load_scenario_bundle(scenario_dir: str | Path) -> ScenarioBundle:
    directory = Path(scenario_dir)
    scenario_path = directory / "scenario.json"
    attack_path_file = directory / "attack_path.json"

    if not scenario_path.is_file():
        raise ScenarioLoadError(f"Missing scenario.json in {directory}")
    if not attack_path_file.is_file():
        raise ScenarioLoadError(f"Missing attack_path.json in {directory}")

    scenario_data = _load_json(scenario_path)
    attack_path_data = _load_json(attack_path_file)

    components = _parse_components(attack_path_data)
    scenario = _parse_scenario(scenario_data)
    _validate_scenario(scenario, components)

    return ScenarioBundle(
        scenario=scenario,
        components_by_id=components,
        scenario_dir=str(directory.resolve()),
    )


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ScenarioLoadError(f"Expected JSON object in {path}")
    return data


def _parse_components(data: dict[str, Any]) -> dict[str, ComponentModel]:
    raw_components = data.get("components")
    if not isinstance(raw_components, list) or not raw_components:
        raise ScenarioLoadError("attack_path.json must contain a non-empty components array")

    components: dict[str, ComponentModel] = {}
    for item in raw_components:
        if not isinstance(item, dict):
            raise ScenarioLoadError("Each component entry must be an object")
        component = ComponentModel.from_dict(item)
        if not component.id:
            raise ScenarioLoadError("Each component must have an id")
        if component.id in components:
            raise ScenarioLoadError(f"Duplicate component id: {component.id}")
        components[component.id] = component
    return components


def _parse_scenario(data: dict[str, Any]) -> ScenarioModel:
    scenario_id = str(data.get("scenario_id") or "").strip()
    title = str(data.get("title") or "").strip()
    if not scenario_id:
        raise ScenarioLoadError("scenario.json must contain scenario_id")
    if not title:
        raise ScenarioLoadError("scenario.json must contain title")

    attacker_data = data.get("attacker_profile") or {}
    attacker_profile = AttackerProfile(
        id=str(attacker_data.get("id") or ""),
        type=str(attacker_data.get("type") or ""),
        description=str(attacker_data.get("description") or ""),
        capabilities=[str(item) for item in attacker_data.get("capabilities") or []],
    )

    entry_point = _parse_component_reference(data.get("entry_point"))
    target = _parse_component_reference(data.get("target"))
    attack_path = _parse_attack_path(data.get("attack_path"))
    impact = _parse_impact(data.get("impact"))

    return ScenarioModel(
        scenario_id=scenario_id,
        title=title,
        scenario_type=str(data.get("scenario_type") or ""),
        operational_state=str(data.get("operational_state") or ""),
        attacker_profile=attacker_profile,
        entry_point=entry_point,
        target=target,
        attack_path=attack_path,
        impact=impact,
        global_preconditions=[str(item) for item in data.get("global_preconditions") or []],
        assumptions=[str(item) for item in data.get("assumptions") or []],
    )


def _parse_component_reference(data: Any) -> ComponentReference | None:
    if not isinstance(data, dict):
        return None
    component_id = str(data.get("component_id") or "").strip()
    if not component_id:
        return None
    return ComponentReference(
        component_id=component_id,
        component_name=str(data.get("component_name") or ""),
        role="",
    )


def _parse_attack_path(data: Any) -> list[AttackStep]:
    if not isinstance(data, list) or not data:
        raise ScenarioLoadError("scenario.json must contain a non-empty attack_path array")

    steps: list[AttackStep] = []
    seen_sequences: set[int] = set()
    for item in data:
        if not isinstance(item, dict):
            raise ScenarioLoadError("Each attack_path entry must be an object")
        sequence = int(item.get("sequence") or 0)
        step_id = str(item.get("step_id") or "").strip()
        name = str(item.get("name") or "").strip()
        if sequence <= 0:
            raise ScenarioLoadError("Each attack step must have a positive sequence number")
        if not step_id:
            raise ScenarioLoadError(f"Attack step {sequence} is missing step_id")
        if not name:
            raise ScenarioLoadError(f"Attack step {sequence} is missing name")
        if sequence in seen_sequences:
            raise ScenarioLoadError(f"Duplicate attack step sequence: {sequence}")
        seen_sequences.add(sequence)

        steps.append(
            AttackStep(
                sequence=sequence,
                step_id=step_id,
                name=name,
                source_component_id=item.get("source_component_id"),
                target_component_id=item.get("target_component_id"),
                description=str(item.get("description") or ""),
                required_conditions=[str(value) for value in item.get("required_conditions") or []],
            )
        )

    steps.sort(key=lambda step: step.sequence)
    return steps


def _parse_impact(data: Any) -> ScenarioImpact | None:
    if not isinstance(data, dict):
        return None
    return ScenarioImpact(
        affected_component_id=str(data.get("affected_component_id") or ""),
        confidentiality=str(data.get("confidentiality") or ""),
        integrity=str(data.get("integrity") or ""),
        availability=str(data.get("availability") or ""),
        safety=str(data.get("safety") or ""),
        impact_categories=[str(item) for item in data.get("impact_categories") or []],
    )


def _validate_scenario(scenario: ScenarioModel, components: dict[str, ComponentModel]) -> None:
    for step in scenario.attack_path:
        if step.source_component_id and step.source_component_id not in components:
            raise ScenarioLoadError(
                f"Step {step.sequence} references unknown source component: {step.source_component_id}"
            )
        if step.target_component_id and step.target_component_id not in components:
            raise ScenarioLoadError(
                f"Step {step.sequence} references unknown target component: {step.target_component_id}"
            )
