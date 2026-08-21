from __future__ import annotations

from rag.ingestion.loaders import load_cisa_advisories
from rag.ingestion.parser import parse_cisa_advisories
from rag.scenario.affected_product_clauses import parse_affected_product_clauses
from rag.scenario.cve_validation import evaluate_cve_candidates
from rag.scenario.loader import load_scenario_bundle
from rag.scenario.models import AttackStep, ComponentModel, StepEnrichment
from rag.scenario.step_cve_selection import select_best_step_candidate


def _component(**overrides) -> ComponentModel:
    values = {
        "id": "cmp-if-01",
        "name": "Northbound Interface MODEL-X",
        "vendor": "Acme Controls",
        "product_family": "Northbound Series",
        "model": "MODEL-X",
        "part_number": "PN-111",
    }
    values.update(overrides)
    return ComponentModel(**values)


def _step() -> AttackStep:
    return AttackStep(
        sequence=3,
        step_id="exploit",
        name="Compromise Controller",
        source_component_id="src-1",
        target_component_id="cmp-if-01",
        description="The attacker compromises the controller.",
    )


def _csv_text(
    *,
    cve: str = "CVE-2033-11001",
    advisory: str = "ICSA-33-001-01",
    product: str = "Northbound Series",
    affected: str = "MODEL-X: All serial numbers",
    vendor: str = "Acme Controls",
    description: str = "",
) -> str:
    lines = [
        f"Advisory: {vendor} {product}",
        f"ICS Advisory: {advisory}",
        f"Vendor: {vendor}",
        f"Product: {product}",
        f"Affected Products: {affected}",
        f"CVE: {cve}",
        "CWE: CWE-294",
    ]
    if description:
        lines.append(f"Description: {description}")
    return "\n".join(lines)


def _evaluate(text: str, component: ComponentModel, step: AttackStep | None = None, cve: str = "CVE-2033-11001"):
    actual = step or _step()
    enrichment = StepEnrichment(
        step=actual,
        primary_query="q",
        primary_answer="a",
        retrieved_text=text,
        advisory_context=text,
    )
    candidates = evaluate_cve_candidates(enrichment, component, actual, None)
    return next(item for item in candidates if item.cve_id == cve)


def _status(candidate, name: str) -> str:
    return next(item.status.value for item in candidate.checks if item.name == name)


def test_parser_extracts_discrete_model_clause():
    clauses = parse_affected_product_clauses("MODEL-X: All serial numbers")
    assert len(clauses) == 1
    assert clauses[0].identity == "MODEL-X"
    assert clauses[0].constraints[0].dimension == "serial_number"
    assert clauses[0].constraints[0].operator == "all"


def test_parser_keeps_dotted_version_bounds():
    clauses = parse_affected_product_clauses("AppServer: All versions prior to V5.20")
    assert len(clauses) == 1
    assert clauses[0].identity == "AppServer"
    values = {(item.operator, item.value) for item in clauses[0].constraints}
    assert ("<", "V5.20") in values
    assert ("all", "") not in values


def test_parser_extracts_spaced_product_version_clause():
    clauses = parse_affected_product_clauses(
        "The following versions are affected: View Site Edition: version 13.0."
    )
    assert any(item.identity == "View Site Edition" for item in clauses)
    match = next(item for item in clauses if item.identity == "View Site Edition")
    assert any(item.operator == "=" and item.value == "13.0" for item in match.constraints)


def test_parser_does_not_treat_and_prior_as_product_join():
    clauses = parse_affected_product_clauses('CPU-04: Versions "52" and prior')
    assert len(clauses) == 1
    assert clauses[0].identity == "CPU-04"
    assert any(item.operator == "<=" and item.value == "52" for item in clauses[0].constraints)


def test_parser_keeps_family_and_vendor_prose_unparsed():
    assert parse_affected_product_clauses("Northbound Series devices") == []
    assert parse_affected_product_clauses("Vendor Y products") == []


def test_parser_does_not_guess_ambiguous_multi_product_prose():
    assert parse_affected_product_clauses("MODEL-X and MODEL-Y and various other devices are affected") == []


def test_exact_model_all_serial_is_product_true_and_firmware_not_applicable():
    candidate = _evaluate(_csv_text(), _component(firmware_version=None))
    assert _status(candidate, "product") == "known_true"
    assert _status(candidate, "serial_number") == "known_true"
    assert _status(candidate, "version") == "not_applicable"
    assert candidate.disposition != "rejected"


def test_exact_model_without_firmware_is_not_rejected_for_missing_firmware():
    candidate = _evaluate(_csv_text(), _component(firmware_version=None))
    assert _status(candidate, "product") == "known_true"
    assert _status(candidate, "version") != "known_false"


def test_family_only_source_is_not_product_true():
    candidate = _evaluate(_csv_text(affected="Northbound Series devices"), _component())
    assert _status(candidate, "product") != "known_true"


def test_vendor_only_source_is_not_product_true():
    candidate = _evaluate(_csv_text(product="Acme Controls", affected="Acme Controls products"), _component())
    assert _status(candidate, "product") != "known_true"


def test_sibling_model_is_not_product_true():
    candidate = _evaluate(_csv_text(affected="MODEL-Y: All serial numbers"), _component())
    assert _status(candidate, "product") != "known_true"


def test_exact_part_number_clause_is_strong_identity():
    candidate = _evaluate(
        _csv_text(affected="Part Number PN-111: All serial numbers"),
        _component(model="OTHER-1"),
    )
    assert _status(candidate, "product") == "known_true"
    assert _status(candidate, "part_number") == "known_true"


def test_bounded_serial_without_input_serial_is_unknown_conditional():
    candidate = _evaluate(
        _csv_text(
            affected="MODEL-X: serial numbers 2310**** and prior",
            description="A command injection vulnerability could allow a remote attacker to execute arbitrary code.",
        ),
        _component(serial_number=None),
    )
    assert _status(candidate, "product") == "known_true"
    assert _status(candidate, "serial_number") == "unknown"
    assert candidate.disposition == "conditional"


def test_bounded_serial_matching_input_is_true():
    candidate = _evaluate(
        _csv_text(affected="MODEL-X: serial numbers 2310**** and prior"),
        _component(serial_number="23051234"),
    )
    assert _status(candidate, "serial_number") == "known_true"


def test_bounded_serial_non_matching_input_is_false_reject():
    candidate = _evaluate(
        _csv_text(affected="MODEL-X: serial numbers 2310**** and prior"),
        _component(serial_number="24001234"),
    )
    assert _status(candidate, "serial_number") == "known_false"
    assert candidate.disposition == "rejected"


def test_firmware_constraint_stays_firmware_only():
    text = _csv_text(affected="MODEL-X: firmware prior to V2.0")
    candidate = _evaluate(text, _component(firmware_version="V1.5", serial_number="9999"))
    assert _status(candidate, "version") == "known_true"
    assert _status(candidate, "serial_number") == "not_applicable"


def test_serial_constraint_does_not_leak_into_firmware():
    candidate = _evaluate(_csv_text(), _component(firmware_version="V9.9"))
    assert _status(candidate, "serial_number") == "known_true"
    assert _status(candidate, "version") == "not_applicable"


def test_software_constraint_does_not_leak_into_firmware():
    candidate = _evaluate(
        _csv_text(affected="MODEL-X: software versions prior to 3.0"),
        _component(firmware_version="V9.9", software_version="2.1"),
    )
    assert _status(candidate, "software_version") == "known_true"
    assert _status(candidate, "version") == "not_applicable"


def test_unlabeled_version_binds_to_populated_software_field():
    candidate = _evaluate(
        _csv_text(affected="MODEL-X: All versions prior to V5.20"),
        _component(firmware_version=None, software_version="5.10"),
    )
    assert _status(candidate, "software_version") == "known_true"
    assert _status(candidate, "version") == "not_applicable"


def test_unlabeled_version_outside_software_range_is_rejected():
    candidate = _evaluate(
        _csv_text(affected="MODEL-X: All versions prior to V5.20"),
        _component(firmware_version=None, software_version="5.20"),
    )
    assert _status(candidate, "software_version") == "known_false"
    assert candidate.disposition == "rejected"
    assert candidate.final_status == "rejected_version_mismatch"


def test_two_explicit_models_share_serial_scope():
    candidate = _evaluate(
        _csv_text(affected="MODEL-X / MODEL-Y: All serial numbers"),
        _component(),
    )
    assert _status(candidate, "product") == "known_true"
    other = _evaluate(
        _csv_text(affected="MODEL-X / MODEL-Y: All serial numbers"),
        _component(model="MODEL-Y", name="Northbound Interface MODEL-Y", part_number="PN-222"),
    )
    assert _status(other, "product") == "known_true"


def test_empty_description_leaves_effect_unknown_and_may_abstain():
    candidate = _evaluate(_csv_text(), _component())
    assert _status(candidate, "product") == "known_true"
    assert _status(candidate, "technical_effect") == "unknown"
    selection = select_best_step_candidate("exploit", [candidate], step=_step(), component=_component())
    assert selection.selected is None


def test_test003_csv_probe_confirms_product_and_serial_but_may_abstain(tmp_path):
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    bundle = load_scenario_bundle(root / "examples" / "TS-OT-TEST-003")
    step = next(item for item in bundle.scenario.attack_path if item.step_id == "replay")
    target = bundle.components_by_id[step.target_component_id or ""]
    reference = target.advisory_reference()
    assert reference
    row = next(
        item
        for item in load_cisa_advisories(root / "CISA_ICS_ADV_Master.csv")
        if str(item.get("ICS-CERT_Number") or "").upper() == reference.upper()
    )
    text = parse_cisa_advisories([row], "CISA_ICS_ADV_Master.csv")[0].text
    enrichment = StepEnrichment(
        step=step,
        primary_query="q",
        primary_answer="a",
        retrieved_text=text,
        advisory_context=text,
    )
    empty = tmp_path / "empty_nvd"
    empty.mkdir()
    candidates = evaluate_cve_candidates(enrichment, target, step, bundle, nvd_store_dir=str(empty))
    assert candidates
    candidate = candidates[0]
    assert _status(candidate, "product") == "known_true"
    assert _status(candidate, "serial_number") == "known_true"
    assert _status(candidate, "version") == "not_applicable"
    assert _status(candidate, "technical_effect") == "unknown"
    selection = select_best_step_candidate(step.step_id, candidates, step=step, component=target)
    assert selection.selected is None
    selection = select_best_step_candidate(step.step_id, candidates, step=step, component=target)
    assert selection.selected is None
