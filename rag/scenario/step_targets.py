from __future__ import annotations

# PRODUCT MATCH != STEP APPLICABILITY.
# Downstream operational impact must not be treated as the exploit target
# unless a separate validated exploitation step exists for that component.

from dataclasses import dataclass
import re

from rag.scenario.models import AttackStep, ComponentModel, ScenarioBundle


@dataclass(frozen=True, slots=True)
class StepTargetRoles:
    """Separate exploit identity from action and downstream impact targets."""

    vulnerable_component_id: str | None
    action_target_id: str | None
    downstream_affected_id: str | None


def resolve_step_targets(
    step: AttackStep,
    bundle: ScenarioBundle | None = None,
) -> StepTargetRoles:
    del bundle  # reserved for role-aware refinements
    action_target = step.target_component_id
    source = step.source_component_id

    if _is_downstream_consequence_step(step):
        # CVE product identity belongs to the already-compromised source, not the
        # downstream operational component named as the action/effect target.
        vulnerable = source or action_target
        downstream = action_target if action_target and action_target != vulnerable else None
        return StepTargetRoles(
            vulnerable_component_id=vulnerable,
            action_target_id=action_target,
            downstream_affected_id=downstream,
        )

    return StepTargetRoles(
        vulnerable_component_id=action_target,
        action_target_id=action_target,
        downstream_affected_id=None,
    )


def vulnerable_component(
    step: AttackStep,
    bundle: ScenarioBundle | None,
) -> ComponentModel | None:
    roles = resolve_step_targets(step, bundle)
    if not roles.vulnerable_component_id or bundle is None:
        return None
    return bundle.components_by_id.get(roles.vulnerable_component_id)


def is_downstream_consequence_step(step: AttackStep) -> bool:
    return _is_downstream_consequence_step(step)


def _is_downstream_consequence_step(step: AttackStep) -> bool:
    blob = f"{step.name} {step.description}".lower()
    if step.step_id.lower() in {"effect", "impact", "consequence"}:
        return True
    if re.search(
        r"\bmay affect\b|\baffect(?:s|ing)?\b.*(command|visualization|operator|process)",
        blob,
    ):
        return True
    if "compromise" in step.name.lower() and "function" in step.name.lower():
        return True
    return False
