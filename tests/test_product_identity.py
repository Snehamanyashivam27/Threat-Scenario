from __future__ import annotations

from rag.ingestion.csaf.documents import build_cve_retrieval_text
from rag.ingestion.csaf.parser import parse_csaf_file
from rag.scenario.cve_validation import evaluate_cve_candidates
from rag.scenario.models import AttackStep, ComponentModel, StepEnrichment


def _step(description: str = "The attacker compromises the control component.") -> AttackStep:
    return AttackStep(
        sequence=3,
        step_id="exploit",
        name="Compromise Controller",
        source_component_id="source-1",
        target_component_id="target-1",
        description=description,
    )


def _evaluate(path: str, cve_id: str, component: ComponentModel, step: AttackStep | None = None):
    record = next(item for item in parse_csaf_file(path) if item.cve_id == cve_id)
    text = build_cve_retrieval_text(record)
    actual_step = step or _step()
    enrichment = StepEnrichment(
        step=actual_step,
        primary_query="q",
        primary_answer="a",
        advisory_context=text,
        retrieved_text=text,
    )
    candidates = evaluate_cve_candidates(enrichment, component, actual_step, None)
    return next(candidate for candidate in candidates if candidate.cve_id == cve_id)


def _check(candidate, name: str) -> str:
    return next(check for check in candidate.checks if check.name == name).status.value


def test_rst2428p_rejects_ape1808_cve_2024_4465():
    component = ComponentModel(
        id="switch-1",
        name="RUGGEDCOM RST2428P",
        vendor="Siemens",
        product_family="RUGGEDCOM",
        model="RST2428P",
        part_number="6GK6242-6PA00",
    )

    candidate = _evaluate("data/cisa_csaf/ICSA-24-284-11.json", "CVE-2024-4465", component)

    assert candidate.disposition == "rejected"
    assert _check(candidate, "product") == "known_false"
    assert _check(candidate, "model") == "known_false"
    assert _check(candidate, "part_number") == "known_false"


def test_cpci85_rejects_sm2556_cve_2017_12739():
    component = ComponentModel(
        id="rtu-1",
        name="SICAM 8 CPCI85",
        vendor="Siemens",
        product_family="SICAM",
        model="CPCI85 Central Processing/Communication",
    )

    candidate = _evaluate("data/cisa_csaf/ICSA-17-320-02.json", "CVE-2017-12739", component)

    assert candidate.disposition == "rejected"
    assert _check(candidate, "product") == "known_false"
    assert _check(candidate, "model") == "known_false"


def test_cpci85_accepts_cve_2024_31485_conditionally():
    component = ComponentModel(
        id="rtu-1",
        name="SICAM 8 CPCI85",
        vendor="Siemens",
        product_family="SICAM",
        model="CPCI85 Central Processing/Communication",
        firmware_version="V5.20",
    )

    candidate = _evaluate("data/cisa_csaf/ICSA-24-137-02.json", "CVE-2024-31485", component)

    assert _check(candidate, "product") == "known_true"
    assert candidate.disposition in {"applicable", "conditional"}
    assert candidate.final_status.startswith("conditional") or candidate.final_status in {
        "applicable",
        "verified_applicable",
    }


def test_rst2428p_specific_cve_passes_product_but_still_validates_effect():
    component = ComponentModel(
        id="switch-1",
        name="RUGGEDCOM RST2428P",
        vendor="Siemens",
        product_family="RUGGEDCOM",
        model="RST2428P",
        part_number="6GK6242-6PA00",
        firmware_version="V3.0",
    )
    step = _step(
        "The attacker in a man-in-the-middle position compromises session confidentiality and integrity."
    )

    candidate = _evaluate("data/cisa_csaf/ICSA-25-162-04.json", "CVE-2025-40567", component, step)

    assert _check(candidate, "product") == "known_true"
    assert candidate.final_status != "insufficient_context"


def test_same_family_siblings_never_exact_match():
    ruggedcom_switch = ComponentModel(
        id="switch-1",
        name="RUGGEDCOM RST2428P",
        vendor="Siemens",
        product_family="RUGGEDCOM",
        model="RST2428P",
        part_number="6GK6242-6PA00",
    )
    ape1808 = ComponentModel(
        id="ape-1",
        name="RUGGEDCOM APE1808LNX",
        vendor="Siemens",
        product_family="RUGGEDCOM",
        model="APE1808LNX",
        part_number="6GK6015-0AL20-0GH0",
    )

    switch_on_ape_cve = _evaluate(
        "data/cisa_csaf/ICSA-24-284-11.json",
        "CVE-2024-4465",
        ruggedcom_switch,
    )
    ape_on_switch_cve = _evaluate(
        "data/cisa_csaf/ICSA-25-162-04.json",
        "CVE-2025-40567",
        ape1808,
    )

    assert switch_on_ape_cve.disposition == "rejected"
    assert _check(switch_on_ape_cve, "family") == "known_true"
    assert _check(switch_on_ape_cve, "product") == "known_false"

    assert ape_on_switch_cve.disposition == "rejected"
    assert _check(ape_on_switch_cve, "family") == "known_true"
    assert _check(ape_on_switch_cve, "product") == "known_false"


def _synthetic_evidence(*, product: str, part: str = "", model: str = "") -> str:
    lines = [
        "CVE: CVE-2030-10001",
        "Advisory: ICSA-30-001-01",
        "Vendor: Acme Controls",
        f"Product: {product}",
        "Affected Versions: prior to V2.0",
        "CWE: CWE-77",
        "Description: A command injection vulnerability could allow a remote attacker to execute arbitrary code.",
        "Prerequisites: network_access=remote; authentication_required=false; physical_access=false",
    ]
    if model:
        lines.insert(5, f"Model: {model}")
    if part:
        lines.insert(5, f"Part Number: {part}")
    return "\n".join(lines)


def _evaluate_synthetic(component: ComponentModel, product: str, part: str = "", model: str = ""):
    text = _synthetic_evidence(product=product, part=part, model=model)
    enrichment = StepEnrichment(
        step=_step(),
        primary_query="q",
        primary_answer="a",
        advisory_context=text,
        retrieved_text=text,
    )
    candidates = evaluate_cve_candidates(enrichment, component, _step(), None)
    return next(candidate for candidate in candidates if candidate.cve_id == "CVE-2030-10001")


def test_same_vendor_family_different_model_is_not_an_exact_match():
    component = ComponentModel(
        id="bridge-1",
        name="Acme Bridge X100",
        vendor="Acme Controls",
    )

    candidate = _evaluate_synthetic(component, "Acme Bridge Y200")

    assert _check(candidate, "product") == "known_false"


def test_exact_model_in_name_is_an_exact_match():
    component = ComponentModel(
        id="bridge-1",
        name="Acme Bridge X100",
        vendor="Acme Controls",
    )

    candidate = _evaluate_synthetic(component, "Acme Bridge X100")

    assert _check(candidate, "product") == "unknown"


def test_exact_part_number_is_an_exact_match():
    component = ComponentModel(
        id="bridge-1",
        name="Acme Bridge X100",
        vendor="Acme Controls",
        part_number="AB-X100-1",
    )

    candidate = _evaluate_synthetic(component, "Acme Bridge X100", part="AB-X100-1")

    assert _check(candidate, "product") == "known_true"
    assert _check(candidate, "part_number") == "known_true"


def test_vendor_only_identity_is_not_an_exact_match():
    component = ComponentModel(
        id="ws-1",
        name="Engineering Workstation",
        vendor="Acme Controls",
    )

    candidate = _evaluate_synthetic(component, "Acme Bridge X100")

    assert _check(candidate, "product") != "known_true"


def test_family_only_identity_is_not_an_exact_match():
    component = ComponentModel(
        id="bridge-1",
        name="Acme Bridge",
        vendor="Acme Controls",
        product_family="Bridge",
    )

    candidate = _evaluate_synthetic(component, "Acme Bridge X100")

    assert _check(candidate, "product") != "known_true"


def test_sibling_advisory_entries_are_not_exact_matches():
    component = ComponentModel(
        id="bridge-1",
        name="Acme Bridge X100",
        vendor="Acme Controls",
        product_family="Bridge",
        model="X100",
    )

    candidate = _evaluate_synthetic(component, "Acme Bridge Y200")

    assert candidate.disposition == "rejected"
    assert _check(candidate, "product") == "known_false"


def test_punctuation_and_case_variants_of_exact_model_still_match():
    component = ComponentModel(
        id="bridge-1",
        name="Acme Bridge X100",
        vendor="Acme Controls",
        model="X-100",
    )

    candidate = _evaluate_synthetic(component, "ACME BRIDGE X100", model="X-100")

    assert _check(candidate, "product") == "known_true"


def test_structured_alphabetic_model_matches_and_rejects_siblings():
    component = ComponentModel(
        id="hmi-1",
        name="Acme View SE HMI Server",
        vendor="Acme Controls",
        product_family="Acme View Site Edition",
        model="Acme View SE",
    )

    exact = _evaluate_synthetic(component, "Acme View SE", model="Acme View SE")
    sibling = _evaluate_synthetic(component, "Acme View ME", model="Acme View ME")

    assert _check(exact, "product") == "known_true"
    assert _check(sibling, "product") == "known_false"


def test_digit_bearing_product_name_used_as_family_is_still_exact():
    component = ComponentModel(
        id="app-1",
        name="Helix8 Server",
        vendor="Acme Controls",
        product_family="Helix8",
        model="Helix8",
    )

    candidate = _evaluate_synthetic(component, "Helix8", model="Helix8")

    assert _check(candidate, "product") == "known_true"


def test_name_only_switch_rejects_same_vendor_router_advisory():
    component = ComponentModel(
        id="switch-1",
        name="RUGGEDCOM RST2428P",
        vendor="Siemens",
    )

    candidate = _evaluate("data/cisa_csaf/ICSA-24-319-06.json", "CVE-2024-50557", component)

    assert candidate.disposition == "rejected"
    assert _check(candidate, "product") == "known_false"


def test_name_only_controller_rejects_same_family_meter_advisory():
    component = ComponentModel(
        id="rtu-1",
        name="SICAM 8 CPCI85",
        vendor="Siemens",
    )

    candidate = _evaluate("data/cisa_csaf/ICSA-22-132-07.json", "CVE-2022-29872", component)

    assert candidate.disposition == "rejected"
    assert _check(candidate, "product") == "known_false"


def test_shared_firmware_token_alone_is_unknown_not_exact_identity():
    component = ComponentModel(
        id="rtu-1",
        name="Acme Device X100",
        vendor="Acme Controls",
    )

    firmware_title = _evaluate_synthetic(component, "X100 Firmware of Acme Line Devices")
    firmware_version_phrase = _evaluate_synthetic(
        component,
        "Acme Module Z50: All versions prior to X100 V05",
    )

    assert _check(firmware_title, "product") == "unknown"
    assert _check(firmware_version_phrase, "product") == "unknown"
    assert _check(firmware_title, "model") != "known_true"
    assert _check(firmware_version_phrase, "model") != "known_true"


def test_exact_module_model_match_is_true():
    component = ComponentModel(
        id="module-1",
        name="Acme Module Z50",
        vendor="Acme Controls",
        model="Z50",
    )

    candidate = _evaluate_synthetic(component, "Acme Module Z50", model="Z50")

    assert _check(candidate, "product") == "known_true"
    assert _check(candidate, "model") == "known_true"


def test_exact_part_match_remains_true():
    component = ComponentModel(
        id="bridge-1",
        name="Acme Bridge X100",
        vendor="Acme Controls",
        part_number="AB-X100-1",
    )

    candidate = _evaluate_synthetic(component, "Acme Bridge Y200", part="AB-X100-1")

    assert _check(candidate, "product") == "known_true"
    assert _check(candidate, "part_number") == "known_true"


def test_same_family_different_device_model_is_false():
    component = ComponentModel(
        id="bridge-1",
        name="Acme Bridge X100",
        vendor="Acme Controls",
        product_family="Bridge",
        model="X100",
    )

    candidate = _evaluate_synthetic(component, "Acme Bridge Y200")

    assert _check(candidate, "product") == "known_false"


def test_no_relationship_metadata_does_not_mark_relationship_true():
    component = ComponentModel(
        id="bridge-1",
        name="Acme Bridge X100",
        vendor="Acme Controls",
        model="X100",
    )

    candidate = _evaluate_synthetic(component, "Acme Bridge X100", model="X100")

    assert _check(candidate, "product") == "known_true"
    assert _check(candidate, "relationship") != "known_true"


def test_explicit_contains_relationship_is_true():
    component = ComponentModel(
        id="controller-1",
        name="Acme Controller X100",
        vendor="Acme Controls",
    )

    contains = _evaluate_synthetic(component, "Acme Controller X100 contains Module Z50")
    installed = _evaluate_synthetic(component, "Module Z50 installed-on Acme Controller X100")
    identity = _evaluate_synthetic(component, "Acme Controller X100 is Acme Module Z50")

    assert _check(contains, "product") == "known_true"
    assert _check(contains, "relationship") == "known_true"
    assert _check(installed, "product") == "known_true"
    assert _check(installed, "relationship") == "known_true"
    assert _check(identity, "product") == "known_true"
    assert _check(identity, "relationship") == "known_true"


def test_name_token_match_is_not_labeled_model_when_model_is_empty():
    component = ComponentModel(
        id="bridge-1",
        name="Acme Bridge X100",
        vendor="Acme Controls",
    )

    candidate = _evaluate_synthetic(component, "Acme Bridge X100")

    assert _check(candidate, "product") == "unknown"
    assert _check(candidate, "model") != "known_true"
