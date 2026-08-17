from __future__ import annotations

from rag.ingestion.csaf.documents import build_cve_retrieval_text
from rag.ingestion.csaf.parser import parse_csaf_file
from rag.scenario.applicability import extract_vulnerability_effects, effect_supports_objective, classify_step_objective
from rag.scenario.cve_validation import evaluate_cve_candidates
from rag.scenario.models import AttackStep, ComponentModel, StepEnrichment
from rag.scenario.product_evidence import format_product_evidence_blocks, evidence_from_csv_product
from rag.scenario.step_cve_selection import select_best_step_candidate


def _switch(**overrides) -> ComponentModel:
    values = {
        "id": "cmp-switch-01",
        "name": "Northbound Switch S2400",
        "vendor": "Acme Controls",
        "product_family": "Northbound",
        "model": "S2400",
        "part_number": "NB-S2400-1",
    }
    values.update(overrides)
    return ComponentModel(**values)


def _controller(**overrides) -> ComponentModel:
    values = {
        "id": "cmp-rtu-01",
        "name": "Field RTU Module R80",
        "vendor": "Acme Controls",
        "product_family": "FieldRTU",
        "model": "R80",
        "part_number": "FR-R80-1",
    }
    values.update(overrides)
    return ComponentModel(**values)


def _bypass_step() -> AttackStep:
    return AttackStep(
        sequence=3,
        step_id="step-bypass-segmentation",
        name="Manipulation or Bypass of Network Segmentation",
        source_component_id="cmp-switch-01",
        target_component_id="cmp-switch-01",
        description="The attacker attempts to modify or bypass network and access controls.",
    )


def _compromise_step() -> AttackStep:
    return AttackStep(
        sequence=5,
        step_id="step-compromise-control-component",
        name="Compromise of the Control Component",
        source_component_id="cmp-switch-01",
        target_component_id="cmp-rtu-01",
        description="The attacker exploits an applicable vulnerability affecting the Field RTU Module R80.",
    )


def _csaf(
    *,
    cve: str,
    advisory: str,
    product: str,
    model: str = "",
    part: str = "",
    versions: str = "prior to V2.0",
    description: str,
    cwe: str = "CWE-77",
    effect: str = "",
    evidence_product: str | None = None,
) -> str:
    lines = [
        f"CVE: {cve}",
        f"Advisory: {advisory}",
        "Vendor: Acme Controls",
        f"Product: {product}",
        f"Model: {model}" if model else "",
        f"Part Number: {part}" if part else "",
        f"Affected Products: {product}",
        f"Affected Product Constraints: {product}@@{versions}@@{part}",
        f"Affected Versions: {versions}",
        f"CWE: {cwe}",
        f"Description: {description}",
        "document_type: csaf_security_advisory",
    ]
    if effect:
        lines.append(f"Effect: {effect}")
    evidence_name = evidence_product or product
    lines.append(
        format_product_evidence_blocks(
            [
                {
                    "cve_id": cve,
                    "product_name": evidence_name,
                    "vendor": "Acme Controls",
                    "model": model,
                    "part_number": part,
                    "source": "cisa_csaf",
                    "provenance": f"{advisory}::product_status.known_affected",
                    "identity_origin": "product_tree_resolved",
                    "evidence_strength": "SOURCE_MEMBERSHIP",
                    "polarity": "POSITIVE",
                    "scope": "cve_specific",
                    "version_constraint": versions,
                }
            ]
        )
    )
    return "\n".join(line for line in lines if line)


def _csv_header(*, title: str, advisory: str, product: str, versions: str, cve: str) -> str:
    evidence = evidence_from_csv_product(
        cve_id=cve,
        advisory_id=advisory,
        product_name=product,
        vendor="Acme Controls",
    )
    return "\n".join(
        [
            f"Advisory: {title}",
            f"ICS Advisory: {advisory}",
            f"Identifier: {advisory}",
            "Vendor: Acme Controls",
            f"Product: {product}",
            f"Affected Products: {product}",
            f"Affected Versions: {versions}",
            f"CVE: {cve}",
            format_product_evidence_blocks([evidence]),
        ]
    )


def _evaluate(text: str, component: ComponentModel, step: AttackStep):
    enrichment = StepEnrichment(
        step=step,
        primary_query="q",
        primary_answer="a",
        advisory_context=text,
        retrieved_text=text,
    )
    return evaluate_cve_candidates(enrichment, component, step, None)


def _gate(candidate, name: str) -> str:
    return next(item.status.value for item in candidate.checks if item.name == name)


def test_unrelated_controller_cve_is_not_product_true_for_switch():
    text = _csaf(
        cve="CVE-2030-61001",
        advisory="ICSA-30-010-01",
        product="Field RTU Module R80",
        model="R80",
        part="FR-R80-1",
        description="A command injection vulnerability in the web interface could allow code execution.",
    )
    candidate = next(item for item in _evaluate(text, _switch(), _bypass_step()) if item.cve_id == "CVE-2030-61001")
    assert _gate(candidate, "product") != "known_true"
    assert candidate.disposition == "rejected"


def test_product_evidence_from_another_step_does_not_authorize_this_target():
    switch_text = _csaf(
        cve="CVE-2030-61002",
        advisory="ICSA-30-010-02",
        product="Northbound Switch S2400",
        model="S2400",
        part="NB-S2400-1",
        description="Incorrect authorization allows an attacker to modify network access-control settings.",
        cwe="CWE-863",
        effect="unauthorized modification of network configuration",
    )
    controller_text = _csaf(
        cve="CVE-2030-61003",
        advisory="ICSA-30-010-03",
        product="Field RTU Module R80",
        model="R80",
        part="FR-R80-1",
        description="A command injection vulnerability in the web interface could allow code execution.",
    )
    mixed = "\n\n".join([switch_text, controller_text])
    switch_candidates = _evaluate(mixed, _switch(), _bypass_step())
    controller_on_switch = next(item for item in switch_candidates if item.cve_id == "CVE-2030-61003")
    assert _gate(controller_on_switch, "product") != "known_true"


def test_downstream_component_evidence_does_not_leak_into_upstream_target():
    upstream = _csaf(
        cve="CVE-2030-61004",
        advisory="ICSA-30-010-04",
        product="Field RTU Module R80",
        model="R80",
        part="FR-R80-1",
        versions="prior to V9.00",
        description="A command injection vulnerability in the web interface could allow code execution.",
    )
    downstream_csv = _csv_header(
        title="Northbound Switch S2400 advisory",
        advisory="ICSA-30-010-99",
        product="Northbound Switch S2400",
        versions="prior to V5.80",
        cve="CVE-2030-61999",
    )
    mixed = " ".join([upstream.replace("\n", " "), downstream_csv.replace("\n", " ")])
    candidate = next(item for item in _evaluate(mixed, _switch(), _bypass_step()) if item.cve_id == "CVE-2030-61004")
    assert _gate(candidate, "product") != "known_true"
    assert "V5.80" not in (candidate.version_bound or "")
    assert not any("V5.80" in value for value in candidate.affected_versions)


def test_product_specific_version_stays_attached_to_that_product():
    text = _csaf(
        cve="CVE-2030-61005",
        advisory="ICSA-30-010-05",
        product="Field RTU Module R80",
        model="R80",
        part="FR-R80-1",
        versions="prior to V9.00",
        description="A command injection vulnerability in the web interface could allow code execution.",
    )
    controller = next(item for item in _evaluate(text, _controller(), _compromise_step()) if item.cve_id == "CVE-2030-61005")
    switch = next(item for item in _evaluate(text, _switch(), _bypass_step()) if item.cve_id == "CVE-2030-61005")
    assert "V9.00" in (controller.version_bound or "") or any("V9.00" in value for value in controller.affected_versions)
    assert not any("V9.00" in value for value in switch.affected_versions)


def test_version_for_product_a_is_not_narrated_for_product_b():
    text = (
        _csaf(
            cve="CVE-2030-61006",
            advisory="ICSA-30-010-06",
            product="Field RTU Module R80",
            model="R80",
            part="FR-R80-1",
            versions="prior to V9.00",
            description="A command injection vulnerability in the web interface could allow code execution.",
        )
        + "\n\n"
        + _csv_header(
            title="Unrelated configurator",
            advisory="ICSA-30-010-98",
            product="Northbound Switch S2400",
            versions="prior to V5.80",
            cve="CVE-2030-61006",
        )
    )
    candidate = next(item for item in _evaluate(text, _switch(), _bypass_step()) if item.cve_id == "CVE-2030-61006")
    assert candidate.version_bound != "V5.80"
    assert "V5.80" not in " ".join(candidate.affected_versions)


def test_vendor_only_match_is_not_product_true():
    text = _csaf(
        cve="CVE-2030-61007",
        advisory="ICSA-30-010-07",
        product="Other Vendor Line Z9",
        description="A command injection vulnerability in the web interface could allow code execution.",
    )
    candidate = next(item for item in _evaluate(text, _switch(), _bypass_step()) if item.cve_id == "CVE-2030-61007")
    assert _gate(candidate, "vendor") == "known_true"
    assert _gate(candidate, "product") != "known_true"


def test_family_only_match_is_not_product_true():
    component = _switch(product_family="FieldRTU")
    text = _csaf(
        cve="CVE-2030-61008",
        advisory="ICSA-30-010-08",
        product="FieldRTU Sibling Module Q12",
        model="Q12",
        part="FR-Q12-1",
        description="A command injection vulnerability in the web interface could allow code execution.",
    )
    candidate = next(item for item in _evaluate(text, component, _bypass_step()) if item.cve_id == "CVE-2030-61008")
    assert _gate(candidate, "product") != "known_true"


def test_exact_matching_product_still_works():
    text = _csaf(
        cve="CVE-2030-61009",
        advisory="ICSA-30-010-09",
        product="Northbound Switch S2400",
        model="S2400",
        part="NB-S2400-1",
        description="Incorrect authorization allows an attacker to modify network access-control settings.",
        cwe="CWE-863",
        effect="unauthorized modification of network configuration",
    )
    candidate = next(item for item in _evaluate(text, _switch(), _bypass_step()) if item.cve_id == "CVE-2030-61009")
    assert _gate(candidate, "product") == "known_true"


def test_explicit_valid_product_relationship_still_works():
    component = ComponentModel(
        id="controller-1",
        name="Acme Controller X100",
        vendor="Acme Controls",
    )
    text = "\n".join(
        [
            "CVE: CVE-2030-61010",
            "Advisory: ICSA-30-010-10",
            "Vendor: Acme Controls",
            "Product: Module Z50 installed-on Acme Controller X100",
            "Affected Versions: prior to V2.0",
            "CWE: CWE-77",
            "Description: A command injection vulnerability could allow a remote attacker to execute arbitrary code.",
            "document_type: csaf_security_advisory",
        ]
    )
    candidate = next(item for item in _evaluate(text, component, _compromise_step()) if item.cve_id == "CVE-2030-61010")
    assert _gate(candidate, "product") == "known_true"
    assert _gate(candidate, "relationship") == "known_true"


def test_segmentation_bypass_rejects_command_injection_without_network_control_effect():
    text = _csaf(
        cve="CVE-2030-61011",
        advisory="ICSA-30-010-11",
        product="Northbound Switch S2400",
        model="S2400",
        part="NB-S2400-1",
        description=(
            "The network configuration service of affected devices contains a flaw. "
            "By uploading specially crafted network configuration, an authenticated "
            "remote attacker could inject commands that are executed with root privileges."
        ),
    )
    step = _bypass_step()
    candidate = next(item for item in _evaluate(text, _switch(), step) if item.cve_id == "CVE-2030-61011")
    effects = extract_vulnerability_effects(
        cwes=frozenset(),
        description=candidate.description,
        effects=candidate.effects,
    )
    assert not effect_supports_objective(effects, classify_step_objective(step))
    if _gate(candidate, "product") == "known_true":
        assert _gate(candidate, "technical_effect") != "known_true"
    selection = select_best_step_candidate(step.step_id, [candidate], step=step, component=_switch())
    assert selection.selected is None


def test_step_abstains_when_no_eligible_cve_remains():
    text = _csaf(
        cve="CVE-2030-61012",
        advisory="ICSA-30-010-12",
        product="Field RTU Module R80",
        model="R80",
        part="FR-R80-1",
        description="A command injection vulnerability in the web interface could allow code execution.",
    )
    step = _bypass_step()
    candidates = _evaluate(text, _switch(), step)
    selection = select_best_step_candidate(step.step_id, candidates, step=step, component=_switch())
    assert selection.selected is None
    assert selection.reason == "no_eligible_candidate"


def test_controller_step_still_selects_matching_controller_candidate():
    text = _csaf(
        cve="CVE-2030-61013",
        advisory="ICSA-30-010-13",
        product="Field RTU Module R80",
        model="R80",
        part="FR-R80-1",
        description="A command injection vulnerability in the web interface could allow a remote attacker to execute arbitrary code.",
    )
    step = _compromise_step()
    candidates = _evaluate(text, _controller(), step)
    selection = select_best_step_candidate(step.step_id, candidates, step=step, component=_controller())
    assert selection.selected is not None
    assert selection.selected.cve_id == "CVE-2030-61013"
    assert _gate(selection.selected, "product") == "known_true"


def test_live_cpci85_advisory_is_not_product_true_for_name_only_switch():
    record = next(item for item in parse_csaf_file("data/cisa_csaf/ICSA-24-011-08.json") if item.cve_id == "CVE-2023-42797")
    text = build_cve_retrieval_text(record)
    switch = ComponentModel(id="cmp-station-switch-01", name="RUGGEDCOM RST2428P", vendor="Siemens")
    candidate = next(item for item in _evaluate(text, switch, _bypass_step()) if item.cve_id == "CVE-2023-42797")
    assert _gate(candidate, "product") != "known_true"


def test_sicam_step_still_selects_valid_cpci85_candidate():
    record = next(item for item in parse_csaf_file("data/cisa_csaf/ICSA-24-137-02.json") if item.cve_id == "CVE-2024-31485")
    text = build_cve_retrieval_text(record)
    rtu = ComponentModel(
        id="cmp-station-rtu-01",
        name="SICAM 8 CPCI85",
        vendor="Siemens",
        product_family="SICAM",
        model="CPCI85 Central Processing/Communication",
        firmware_version="V5.20",
    )
    step = AttackStep(
        sequence=5,
        step_id="step-compromise-control-component",
        name="Compromise of the Control Component",
        source_component_id="cmp-station-switch-01",
        target_component_id="cmp-station-rtu-01",
        description="The attacker exploits an applicable vulnerability affecting the SICAM 8 CPCI85.",
    )
    candidates = _evaluate(text, rtu, step)
    selection = select_best_step_candidate(step.step_id, candidates, step=step, component=rtu)
    assert selection.selected is not None
    assert selection.selected.cve_id == "CVE-2024-31485"
    assert _gate(selection.selected, "product") == "known_true"
