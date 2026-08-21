from __future__ import annotations

from pathlib import Path

from rag.defense.csaf_remediation import load_csaf_remediation_records, lookup_csaf_remediations
from rag.defense.inventory import format_inventory_text, inventory_scenario_result, inventory_step_evidence
from rag.ingestion.csaf.documents import build_cve_retrieval_text
from rag.ingestion.csaf.parser import parse_csaf_file
from rag.scenario.evidence import CandidateEvidence, StepEvidence
from rag.scenario.models import ScenarioNarrativeResult

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "cisa_csaf"
PRIMARY = FIXTURES / "remediation-inventory.json"


def _candidate(cve: str, advisory: str | None = "ICSA-30-001-01") -> CandidateEvidence:
    return CandidateEvidence(
        cve_id=cve,
        advisory_id=advisory,
        disposition="conditional",
        final_status="conditional_version_unknown",
        lifecycle=["SELECTED"],
    )


def _step(*, step_id: str, sequence: int, selected: str | None, candidates: list[CandidateEvidence] | None = None) -> StepEvidence:
    return StepEvidence(
        step_id=step_id,
        sequence=sequence,
        candidates=candidates or [],
        selected_cve=selected,
        selected_cves=[selected] if selected else [],
    )


def _actions(cve: str) -> list:
    records = {item.cve_id: item for item in load_csaf_remediation_records(PRIMARY)}
    return records[cve].remediations


def test_vendor_fix_extracted():
    actions = _actions("CVE-2030-80001")
    assert any(item.category == "vendor_fix" and item.details == "Update to V2.0." for item in actions)


def test_mitigation_extracted():
    actions = _actions("CVE-2030-80001")
    assert any(item.category == "mitigation" for item in actions)


def test_workaround_extracted():
    actions = _actions("CVE-2030-80001")
    assert any(item.category == "workaround" for item in actions)


def test_none_available_extracted():
    actions = _actions("CVE-2030-80003")
    assert [item.category for item in actions] == ["none_available"]
    assert actions[0].details == "Currently no fix is available"


def test_remediation_urls_extracted():
    vendor_fix = next(item for item in _actions("CVE-2030-80001") if item.category == "vendor_fix")
    assert vendor_fix.urls == ["https://example.invalid/update"]


def test_remediation_product_ids_extracted():
    vendor_fix = next(item for item in _actions("CVE-2030-80001") if item.category == "vendor_fix")
    assert vendor_fix.product_ids == ["CSAFPID-0001"]
    assert vendor_fix.scope == "product_specific"


def test_product_status_fixed_extracted():
    record = next(item for item in load_csaf_remediation_records(PRIMARY) if item.cve_id == "CVE-2030-80001")
    assert record.fixed_product_ids == ["CSAFPID-0002"]
    assert "CSAFPID-0001" not in record.fixed_product_ids


def test_selected_cve_with_no_remediation_is_empty_not_invented():
    record = next(item for item in load_csaf_remediation_records(PRIMARY) if item.cve_id == "CVE-2030-80002")
    assert record.remediations == []
    assert record.fixed_product_ids == []
    rows = inventory_step_evidence(
        [
            _step(
                step_id="step-compromise",
                sequence=5,
                selected="CVE-2030-80002",
                candidates=[_candidate("CVE-2030-80002")],
            )
        ],
        FIXTURES,
    )
    assert rows[0].note == "no_csaf_remediation_fields"
    assert rows[0].records[0].remediations == []


def test_same_cve_in_multiple_csaf_sources_is_preserved():
    records = lookup_csaf_remediations(FIXTURES, cve_id="CVE-2030-80001")
    advisories = [item.advisory_id for item in records]
    assert "ICSA-30-001-01" in advisories
    assert "ICSA-30-001-02" in advisories
    assert len(records) >= 2
    provenances = [item.provenance for item in records]
    assert len(provenances) == len(set(provenances))


def test_advisory_id_orders_matching_source_first_without_dropping_others():
    records = lookup_csaf_remediations(
        FIXTURES,
        cve_id="CVE-2030-80001",
        advisory_id="ICSA-30-001-02",
    )
    assert records[0].advisory_id == "ICSA-30-001-02"
    assert {item.advisory_id for item in records} >= {"ICSA-30-001-01", "ICSA-30-001-02"}


def test_duplicate_remediation_entries_are_deduped_deterministically():
    actions = _actions("CVE-2030-80001")
    vendor_fixes = [item for item in actions if item.category == "vendor_fix"]
    assert len(vendor_fixes) == 1
    categories = [item.category for item in actions]
    assert categories == ["vendor_fix", "mitigation", "workaround"]


def test_malformed_optional_fields_do_not_crash():
    records = load_csaf_remediation_records(PRIMARY)
    assert {item.cve_id for item in records} >= {"CVE-2030-80001", "CVE-2030-80002", "CVE-2030-80003"}
    empty = load_csaf_remediation_records(FIXTURES / "malformed.json")
    assert empty == []
    missing = lookup_csaf_remediations("/no/such/csaf/dir", cve_id="CVE-2030-80001")
    assert missing == []


def test_blank_line_details_become_separate_sentences(tmp_path):
    path = tmp_path / "paragraph-details.json"
    path.write_text(
        """
{
  "document": {
    "category": "csaf_security_advisory",
    "csaf_version": "2.0",
    "title": "Paragraph Details",
    "tracking": {"id": "ICSA-30-004-01", "status": "final", "version": "1"},
    "publisher": {"category": "coordinator", "name": "Example", "namespace": "https://example.invalid/"}
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2030-80040",
      "remediations": [
        {
          "category": "vendor_fix",
          "details": "Update to V2.0 or later version\\n\\nThe firmware ModuleA V2.0 is present within \\"Package\\" V2.0"
        },
        {
          "category": "vendor_fix",
          "details": "Update to V3.0 or later version.\\n\\nThe firmware ModuleB V3.0 is present within Package V3.0"
        }
      ]
    },
    {
      "cve": "CVE-2030-80041",
      "remediations": [
        {
          "category": "none_available",
          "details": "Currently no fix is available"
        }
      ]
    }
  ]
}
""".strip(),
        encoding="utf-8",
    )
    records = {item.cve_id: item for item in load_csaf_remediation_records(path)}
    first, second = records["CVE-2030-80040"].remediations[:2]
    assert first.details == (
        'Update to V2.0 or later version. The firmware ModuleA V2.0 is present within "Package" V2.0.'
    )
    assert "later version The firmware" not in first.details
    assert second.details == (
        "Update to V3.0 or later version. The firmware ModuleB V3.0 is present within Package V3.0."
    )
    assert ".." not in second.details
    assert records["CVE-2030-80041"].remediations[0].details == "Currently no fix is available"


def test_inventory_does_not_mutate_scenario_result():
    candidate = _candidate("CVE-2030-80001")
    step = _step(
        step_id="step-compromise",
        sequence=5,
        selected="CVE-2030-80001",
        candidates=[candidate],
    )
    result = ScenarioNarrativeResult(
        scenario_id="EFF-1",
        title="Inventory",
        narrative="placeholder",
        evidence=[step],
    )
    evidence_id = id(result.evidence)
    step_obj_id = id(step)
    candidate_id = id(candidate)
    lifecycle_before = list(candidate.lifecycle)
    rows = inventory_scenario_result(result, FIXTURES)
    assert result.narrative == "placeholder"
    assert id(result.evidence) == evidence_id
    assert id(result.evidence[0]) == step_obj_id
    assert id(result.evidence[0].candidates[0]) == candidate_id
    assert step.selected_cve == "CVE-2030-80001"
    assert candidate.lifecycle == lifecycle_before
    assert candidate.advisory_id == "ICSA-30-001-01"
    assert rows[0].selected_cve == "CVE-2030-80001"
    assert rows[0].records
    assert rows[0].records[0] is not candidate


def test_threat_parser_still_omits_remediation_prose_from_retrieval_text():
    parsed = parse_csaf_file(PRIMARY)
    by_cve = {item.cve_id: item for item in parsed}
    text = build_cve_retrieval_text(by_cve["CVE-2030-80001"])
    assert "Update to V2.0." not in text
    assert "Disable unused services" not in text
    assert "Restrict management-plane access" not in text


def test_inventory_binds_selected_cve_only():
    rows = inventory_step_evidence(
        [
            _step(step_id="step-bypass", sequence=3, selected=None),
            _step(
                step_id="step-compromise",
                sequence=5,
                selected="CVE-2030-80001",
                candidates=[_candidate("CVE-2030-80001"), _candidate("CVE-2030-80002")],
            ),
        ],
        FIXTURES,
    )
    assert rows[0].note == "no_selected_cve"
    assert rows[0].records == []
    assert rows[1].selected_cve == "CVE-2030-80001"
    assert any(item.category == "vendor_fix" for record in rows[1].records for item in record.remediations)


def test_inventory_reports_missing_csaf():
    rows = inventory_step_evidence(
        [
            _step(
                step_id="step-compromise",
                sequence=5,
                selected="CVE-2030-99999",
                candidates=[_candidate("CVE-2030-99999", advisory="ICSA-30-999-99")],
            )
        ],
        FIXTURES,
    )
    assert rows[0].note == "csaf_not_found"
    assert rows[0].records == []


def test_format_inventory_text_is_structured_not_recommendation_prose():
    rows = inventory_step_evidence(
        [
            _step(
                step_id="step-compromise",
                sequence=5,
                selected="CVE-2030-80001",
                candidates=[_candidate("CVE-2030-80001")],
            )
        ],
        FIXTURES,
    )
    text = format_inventory_text(rows)
    assert "category=vendor_fix" in text
    assert "You should patch" not in text
    assert "recommend" not in text.lower()
