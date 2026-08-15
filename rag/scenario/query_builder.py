from __future__ import annotations

from rag.scenario.models import AttackStep, ComponentModel, ScenarioBundle, StepQuery


class StepQueryBuilder:
    def build_step_queries(self, bundle: ScenarioBundle, step: AttackStep) -> list[StepQuery]:
        queries = [
            StepQuery(
                step=step,
                query=self.build_primary_query(bundle, step),
                query_type="primary",
            )
        ]
        advisory_queries = self.build_advisory_queries(bundle, step)
        for advisory_query in advisory_queries:
            queries.append(
                StepQuery(
                    step=step,
                    query=advisory_query,
                    query_type="advisory",
                )
            )
        return queries

    def build_primary_query(self, bundle: ScenarioBundle, step: AttackStep) -> str:
        scenario = bundle.scenario
        source = self._resolve_component(bundle, step.source_component_id)
        target = self._resolve_component(bundle, step.target_component_id)

        source_label = self._component_label(source, fallback="external attacker")
        target_label = self._component_label(target, fallback="unknown component")

        return (
            f"Generate threat scenario step {step.sequence}: {step.name}. "
            f"{step.description} "
            f"Source: {source_label}. "
            f"Target: {target_label}. "
            f"Operational state: {scenario.operational_state or 'unknown'}. "
            f"ICS threat scenario."
        )

    def build_step_context(self, bundle: ScenarioBundle, step: AttackStep) -> dict[str, object]:
        source = self._resolve_component(bundle, step.source_component_id)
        target = self._resolve_component(bundle, step.target_component_id)
        attacker = bundle.scenario.attacker_profile
        return {
            "step_name": step.name,
            "step_description": step.description,
            "required_conditions": list(step.required_conditions),
            "source": self._component_context(source),
            "target": self._component_context(target),
            "operational_state": bundle.scenario.operational_state or None,
            "global_preconditions": list(bundle.scenario.global_preconditions),
            "attacker_capabilities": list(attacker.capabilities) if attacker else [],
            "prior_steps": [
                {
                    "name": prior.name,
                    "description": prior.description,
                    "required_conditions": list(prior.required_conditions),
                }
                for prior in bundle.scenario.attack_path
                if prior.sequence < step.sequence
            ],
        }

    def build_advisory_queries(self, bundle: ScenarioBundle, step: AttackStep) -> list[str]:
        components = [
            self._resolve_component(bundle, step.target_component_id),
            self._resolve_component(bundle, step.source_component_id),
        ]
        queries: list[str] = []
        seen: set[str] = set()
        step_terms = " ".join(
            [
                step.name,
                step.description,
                " ".join(step.required_conditions),
                " ".join(bundle.scenario.attacker_profile.capabilities)
                if bundle.scenario.attacker_profile
                else "",
            ]
        )

        def _add(query: str) -> None:
            normalized = query.strip()
            if not normalized or normalized in seen:
                return
            seen.add(normalized)
            queries.append(normalized)

        for component in components:
            if component is None:
                continue
            reference = component.advisory_reference()
            label = component.product_label() or component.name
            identity = " ".join(
                str(value)
                for value in (
                    component.vendor or component.manufacturer,
                    component.product_family,
                    component.model,
                    component.part_number,
                    component.firmware_version,
                )
                if value
            )
            if reference:
                _add(f"{reference} {label} advisory")
            _add(
                f"{identity or label} CVE advisory affected versions prerequisites technical effect"
            )
            _add(
                f"{identity or label} {step_terms} CVE vulnerability"
            )
            environment = " ".join(
                component.services
                + component.protocols
                + component.software
                + ([component.operating_system] if component.operating_system else [])
            )
            if environment:
                _add(f"{identity or label} {environment} {step.name} CVE")
        return queries

    def build_advisory_query(self, bundle: ScenarioBundle, step: AttackStep) -> str | None:
        queries = self.build_advisory_queries(bundle, step)
        return queries[0] if queries else None

    @staticmethod
    def _resolve_component(bundle: ScenarioBundle, component_id: str | None) -> ComponentModel | None:
        if not component_id:
            return None
        return bundle.components_by_id.get(component_id)

    @staticmethod
    def _component_label(component: ComponentModel | None, fallback: str) -> str:
        if component is None:
            return fallback
        details = [component.name]
        if component.type:
            details.append(f"type {component.type}")
        product = component.product_label()
        if product and not _label_already_contains(product, component.name):
            details.append(product)
        if component.operating_system:
            details.append(f"OS {component.operating_system}")
        return ", ".join(details)

    @staticmethod
    def _component_context(component: ComponentModel | None) -> dict[str, object] | None:
        if component is None:
            return None
        return {
            "id": component.id,
            "name": component.name,
            "type": component.type or None,
            "subtype": component.subtype or None,
            "vendor": component.vendor or component.manufacturer,
            "product_family": component.product_family,
            "model": component.model,
            "part_number": component.part_number,
            "firmware_version": component.firmware_version,
            "operating_system": component.operating_system,
            "software": list(component.software),
            "services": list(component.services),
            "protocols": list(component.protocols),
            "authentication": dict(component.authentication),
            "authorization": dict(component.authorization),
            "remote_access": dict(component.remote_access),
            "network_zone": component.network_zone,
            "operational_states": list(component.operational_states),
        }


def _label_already_contains(product: str, name: str) -> bool:
    name_lower = name.lower()
    return all(token.lower() in name_lower for token in product.split() if token)
