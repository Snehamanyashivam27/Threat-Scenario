from __future__ import annotations

from rag.ingestion.csaf.parser import parse_csaf_document
from rag.scenario.cve_validation import evaluate_cve_candidates
from rag.scenario.evidence import TruthValue
from rag.scenario.models import AttackStep, ComponentModel, StepEnrichment
from rag.scenario.product_evidence import (
    NEGATIVE,
    NOTE_VECTOR_SHARED,
    POLARITY_NEGATIVE,
    SOURCE_MEMBERSHIP,
    STRONG_IDENTITY,
    WEAK_DISCOVERY,
    ProductEvidence,
    decide_product_applicability,
    evidence_from_csv_product,
    merge_product_evidence,
)


def _component(**overrides) -> ComponentModel:
    values = {
        "id": "asset-1",
        "name": "Family-F Model-M1",
        "vendor": "Vendor-A",
        "product_family": "Family-F",
        "model": "Model-M1",
        "part_number": "PN-111",
    }
    values.update(overrides)
    return ComponentModel(**values)


def _step() -> AttackStep:
    return AttackStep(
        sequence=1,
        step_id="exploit",
        name="Compromise",
        source_component_id="src-1",
        target_component_id="asset-1",
        description="The attacker compromises the controller.",
    )


def _evaluate(text: str, component: ComponentModel, cve: str = "CVE-2030-90001"):
    step = _step()
    enrichment = StepEnrichment(
        step=step,
        primary_query="q",
        primary_answer="a",
        advisory_context=text,
        retrieved_text=text,
    )
    candidates = evaluate_cve_candidates(enrichment, component, step, None)
    return next(item for item in candidates if item.cve_id == cve)


def _check(candidate, name: str) -> str:
    return next(item.status.value for item in candidate.checks if item.name == name)


def _csaf(
    *,
    cve: str = "CVE-2030-90001",
    known_affected: list[str] | None = None,
    known_not_affected: list[str] | None = None,
    first_affected: list[str] | None = None,
    last_affected: list[str] | None = None,
    fixed: list[str] | None = None,
    extra_vulns: list[dict] | None = None,
    relationships: list[dict] | None = None,
    helper_part: str | None = None,
) -> dict:
    product = {
        "name": "Family-F Model-M1 (PN-111)",
        "product_id": "PID-1",
    }
    if helper_part:
        product["product_identification_helper"] = {"sku": helper_part}
    sibling = {"name": "Family-F Model-M2 (PN-222)", "product_id": "PID-2"}
    status = {}
    if known_affected is not None:
        status["known_affected"] = known_affected
    if known_not_affected is not None:
        status["known_not_affected"] = known_not_affected
    if first_affected is not None:
        status["first_affected"] = first_affected
    if last_affected is not None:
        status["last_affected"] = last_affected
    if fixed is not None:
        status["fixed"] = fixed
    document = {
        "document": {
            "title": "Synthetic advisory",
            "tracking": {"id": "ADV-30-001-01"},
        },
        "product_tree": {
            "branches": [
                {
                    "category": "vendor",
                    "name": "Vendor-A",
                    "branches": [
                        {
                            "category": "product_family",
                            "name": "Family-F",
                            "branches": [
                                {"category": "product_name", "name": "Family-F Model-M1", "product": product},
                                {"category": "product_name", "name": "Family-F Model-M2", "product": sibling},
                            ],
                        }
                    ],
                }
            ]
        },
        "vulnerabilities": [
            {
                "cve": cve,
                "title": cve,
                "notes": [{"category": "description", "text": "A command injection flaw."}],
                "cwe": {"id": "CWE-77"},
                "product_status": status,
            }
        ],
    }
    if relationships:
        document["product_tree"]["relationships"] = relationships
    if extra_vulns:
        document["vulnerabilities"].extend(extra_vulns)
    return document


def _strong_text(*, model: str = "Model-M1", part: str = "PN-111", product: str = "Family-F Model-M1") -> str:
    return "\n".join(
        [
            "CVE: CVE-2030-90001",
            "Advisory: ADV-30-001-01",
            "Vendor: Vendor-A",
            f"Product: {product}",
            f"Model: {model}",
            f"Part Number: {part}",
            "Affected Versions: prior to V2.0",
            "CWE: CWE-77",
            "Description: A command injection vulnerability could allow a remote attacker to execute arbitrary code.",
            "Prerequisites: network_access=remote; authentication_required=false; physical_access=false",
        ]
    )


def test_a_known_affected_is_source_membership_and_true_when_product_is_specific():
    for key in ("known_affected", "first_affected", "last_affected"):
        records = parse_csaf_document(_csaf(**{key: ["PID-1"]}))
        item = records[0].product_evidence[0]
        assert item["evidence_strength"] == SOURCE_MEMBERSHIP
        assert f"product_status.{key}" in item["provenance"]
    records = parse_csaf_document(_csaf(known_affected=["PID-1"]))
    assert records[0].product_evidence
    item = records[0].product_evidence[0]
    assert item["evidence_strength"] == SOURCE_MEMBERSHIP
    assert item["scope"] == "cve_specific"
    assert item["identity_origin"] == "product_tree_resolved"
    assert "product_status.known_affected" in item["provenance"]

    from rag.ingestion.csaf.documents import build_cve_retrieval_text
    from rag.utils.text import clean_text
    from rag.scenario.product_evidence import parse_product_evidence_blocks

    text = build_cve_retrieval_text(records[0])
    parsed = parse_product_evidence_blocks(clean_text(text), default_cve="CVE-2030-90001")
    assert parsed
    assert "product_status.known_affected" in parsed[0].provenance

    candidate = _evaluate(text, _component())
    assert _check(candidate, "product") == "known_true"
    assert candidate.product_evidence_trace
    assert "product_status.known_affected" in candidate.product_evidence_trace[0]["provenance"]


def test_b_known_not_affected_match_is_false():
    records = parse_csaf_document(_csaf(known_not_affected=["PID-1"]))
    item = records[0].product_evidence[0]
    assert item["polarity"] == POLARITY_NEGATIVE
    assert item["evidence_strength"] == NEGATIVE
    assert "product_status.known_not_affected" in item["provenance"]

    from rag.ingestion.csaf.documents import build_cve_retrieval_text

    candidate = _evaluate(build_cve_retrieval_text(records[0]), _component())
    assert _check(candidate, "product") == "known_false"


def test_c_fixed_never_creates_positive_affected_evidence():
    records = parse_csaf_document(_csaf(fixed=["PID-1"]))
    assert records[0].raw_product_ids == []
    assert all(item["polarity"] != "POSITIVE" or item["evidence_strength"] == "NONE" for item in records[0].product_evidence)
    assert records[0].product_evidence == []


def test_d_inferred_tree_model_part_is_not_strong_identity():
    records = parse_csaf_document(_csaf(known_affected=["PID-1"]))
    item = records[0].product_evidence[0]
    assert item["evidence_strength"] != STRONG_IDENTITY
    assert item["identity_origin"] == "product_tree_resolved"
    assert not item["model"]
    assert not item["part_number"]


def test_e_relationship_type_is_preserved_and_not_implied():
    data = _csaf(known_affected=["PID-REL"])
    data["product_tree"]["relationships"] = [
        {
            "category": "installed_on",
            "product_reference": "PID-1",
            "relates_to_product_reference": "PID-2",
            "full_product_name": {"product_id": "PID-REL", "name": "Firmware of Family-F Model-M1"},
        }
    ]
    records = parse_csaf_document(data)
    item = next(row for row in records[0].product_evidence if row["product_id"] == "PID-REL")
    assert item["relationship_type"] == "installed-on"
    candidate = _evaluate(_strong_text(), _component())
    assert _check(candidate, "relationship") != "known_true"


def test_f_csv_aggregate_is_weak_discovery_unknown():
    text = "\n".join(
        [
            "Advisory: Aggregate row",
            "Identifier: ADV-30-001-01",
            "Vendor: Vendor-A",
            "Product: Family-F Model-M1",
            "CVE: CVE-2030-90001",
        ]
    )
    candidate = _evaluate(text, _component())
    assert candidate.product_evidence_trace
    assert candidate.product_evidence_trace[0]["evidence_strength"] == WEAK_DISCOVERY
    assert _check(candidate, "product") == "unknown"


def test_g_source_stated_model_part_same_dimension_is_true():
    candidate = _evaluate(_strong_text(), _component())
    assert _check(candidate, "product") == "known_true"
    assert _check(candidate, "part_number") == "known_true"
    model_only = _evaluate(_strong_text(part=""), _component(part_number=""))
    assert _check(model_only, "product") == "known_true"
    assert _check(model_only, "model") == "known_true"


def test_h_membership_plus_independent_second_source_is_true():
    membership = ProductEvidence(
        cve_id="CVE-2030-90001",
        product_name="Family-F Model-M1",
        source="cisa_csaf",
        evidence_strength=SOURCE_MEMBERSHIP,
        identity_origin="product_tree_resolved",
        scope="cve_specific",
        polarity="POSITIVE",
    )
    weak = evidence_from_csv_product(
        cve_id="CVE-2030-90001",
        advisory_id="ADV-30-001-01",
        product_name="Family-F Model-M1",
        vendor="Vendor-A",
        source="cisa_csv",
    )
    from rag.scenario.cve_validation import _entry_matches_component

    decision = decide_product_applicability(
        _component(),
        [membership, weak],
        _entry_matches_component,
        input_identity="Model-M1",
    )
    assert decision.product_match == TruthValue.TRUE
    assert decision.corroborating


def test_i_sibling_model_part_mismatch_is_false():
    candidate = _evaluate(
        _strong_text(model="Model-M2", part="PN-222", product="Family-F Model-M2"),
        _component(),
    )
    assert _check(candidate, "product") == "known_false"


def test_j_positive_authoritative_plus_negative_is_conflicting():
    text = "\n".join(
        [
            _strong_text(),
            "--- Product Evidence ---",
            "Source: cisa_csaf",
            "Provenance: ADV-30-001-01",
            "Scope: cve_specific",
            "Identity Origin: source_stated",
            "Evidence Strength: STRONG_IDENTITY",
            "Polarity: POSITIVE",
            "Product Name: Family-F Model-M1",
            "Model: Model-M1",
            "Part Number: PN-111",
            "--- End Product Evidence ---",
            "--- Product Evidence ---",
            "Source: cisa_csaf",
            "Provenance: ADV-30-001-02",
            "Scope: cve_specific",
            "Identity Origin: product_tree_resolved",
            "Evidence Strength: NEGATIVE",
            "Polarity: NEGATIVE",
            "Product Name: Family-F Model-M1",
            "Model: Model-M1",
            "Part Number: PN-111",
            "--- End Product Evidence ---",
        ]
    )
    candidate = _evaluate(text, _component())
    assert candidate.final_status == "conflicting_evidence"


def test_k_firmware_without_device_relationship_is_unknown():
    text = "\n".join(
        [
            "CVE: CVE-2030-90001",
            "Advisory: ADV-30-001-01",
            "Vendor: Vendor-A",
            "Product: Model-M1 Firmware of Family-F Line Devices",
            "Affected Versions: prior to V2.0",
            "CWE: CWE-77",
            "Description: Firmware advisory text.",
        ]
    )
    candidate = _evaluate(text, _component(model="", part_number=""))
    assert _check(candidate, "product") == "unknown"


def test_l_family_or_vendor_only_never_true():
    family_only = _evaluate(
        "\n".join(
            [
                "CVE: CVE-2030-90001",
                "Advisory: ADV-30-001-01",
                "Vendor: Vendor-A",
                "Product: Family-F",
                "Product Family: Family-F",
                "Affected Versions: prior to V2.0",
                "CWE: CWE-77",
                "Description: Family-level advisory.",
            ]
        ),
        _component(model="", part_number="", name="Family-F Gateway"),
    )
    assert _check(family_only, "product") != "known_true"


def test_m_union_keeps_weaker_and_negative_and_shared_vector_is_metadata():
    data = _csaf(known_affected=["PID-1"], extra_vulns=[
        {
            "cve": "CVE-2030-90002",
            "title": "CVE-2030-90002",
            "notes": [{"category": "description", "text": "Another issue."}],
            "cwe": {"id": "CWE-20"},
            "product_status": {"known_affected": ["PID-1"]},
        }
    ])
    records = parse_csaf_document(data)
    notes = records[0].product_evidence[0]["specificity_notes"]
    assert NOTE_VECTOR_SHARED in notes
    assert records[0].product_evidence[0]["evidence_strength"] == SOURCE_MEMBERSHIP

    membership = ProductEvidence(
        cve_id="CVE-2030-90001",
        product_name="Family-F Model-M1",
        source="cisa_csaf",
        evidence_strength=SOURCE_MEMBERSHIP,
        polarity="POSITIVE",
    )
    negative = ProductEvidence(
        cve_id="CVE-2030-90001",
        product_name="Family-F Model-M1",
        source="cisa_csv",
        evidence_strength=NEGATIVE,
        polarity=POLARITY_NEGATIVE,
    )
    merged = merge_product_evidence([membership], [negative])
    assert len(merged) == 2
    assert {item.polarity for item in merged} == {"POSITIVE", "NEGATIVE"}

    unknown = _evaluate(
        "\n".join(
            [
                "CVE: CVE-2030-90001",
                "Advisory: ADV-30-001-01",
                "Vendor: Vendor-A",
                "Product: Family-F Model-M1",
                "Affected Versions: prior to V2.0",
                "CWE: CWE-77",
                "Description: Membership-only product listing.",
            ]
        ),
        _component(),
    )
    assert _check(unknown, "product") == "unknown"
    assert unknown.final_status == "insufficient_context"
    assert _check(unknown, "product") != "known_false"


def test_cve_specific_membership_family_only_stays_unknown():
    data = _csaf(known_affected=["PID-1"])
    data["product_tree"]["branches"][0]["branches"][0]["branches"][0]["product"]["name"] = "Family-F"
    data["product_tree"]["branches"][0]["branches"][0]["branches"][0]["name"] = "Family-F"
    records = parse_csaf_document(data)
    from rag.ingestion.csaf.documents import build_cve_retrieval_text

    candidate = _evaluate(
        build_cve_retrieval_text(records[0]),
        _component(name="Family-F Gateway", model="", part_number=""),
    )
    assert _check(candidate, "product") != "known_true"


def test_cve_specific_membership_sibling_specific_mismatch_is_false():
    records = parse_csaf_document(_csaf(known_affected=["PID-2"]))
    from rag.ingestion.csaf.documents import build_cve_retrieval_text

    candidate = _evaluate(build_cve_retrieval_text(records[0]), _component())
    assert _check(candidate, "product") == "known_false"


def test_explicit_relationship_membership_of_contained_component_is_true():
    data = _csaf(known_affected=["PID-REL"])
    data["product_tree"]["relationships"] = [
        {
            "category": "installed_on",
            "product_reference": "PID-FW",
            "relates_to_product_reference": "PID-1",
            "full_product_name": {
                "product_id": "PID-REL",
                "name": "Firmware of Family-F Model-M1 installed-on Family-F Model-M1",
            },
        }
    ]
    records = parse_csaf_document(data)
    item = next(row for row in records[0].product_evidence if row["product_id"] == "PID-REL")
    assert item["relationship_type"] == "installed-on"
    from rag.ingestion.csaf.documents import build_cve_retrieval_text

    candidate = _evaluate(build_cve_retrieval_text(records[0]), _component())
    assert _check(candidate, "product") == "known_true"


def test_sparse_asset_exact_product_name_membership_is_true():
    records = parse_csaf_document(_csaf(known_affected=["PID-1"]))
    from rag.ingestion.csaf.documents import build_cve_retrieval_text

    candidate = _evaluate(
        build_cve_retrieval_text(records[0]),
        _component(model="", part_number=""),
    )
    assert _check(candidate, "product") == "known_true"
    assert "product_status.known_affected" in candidate.product_evidence_trace[0]["provenance"]


def test_authoritative_membership_plus_negative_same_asset_is_conflicting():
    from rag.scenario.cve_validation import _entry_matches_component

    positive = ProductEvidence(
        cve_id="CVE-2030-90001",
        product_name="Family-F Model-M1",
        source="cisa_csaf",
        provenance="ADV-30-001-01::product_status.known_affected",
        evidence_strength=SOURCE_MEMBERSHIP,
        identity_origin="product_tree_resolved",
        scope="cve_specific",
        polarity="POSITIVE",
    )
    negative = ProductEvidence(
        cve_id="CVE-2030-90001",
        product_name="Family-F Model-M1",
        source="cisa_csaf",
        provenance="ADV-30-001-01::product_status.known_not_affected",
        evidence_strength=NEGATIVE,
        polarity=POLARITY_NEGATIVE,
        scope="cve_specific",
    )
    decision = decide_product_applicability(
        _component(),
        [positive, negative],
        _entry_matches_component,
        input_identity="Model-M1",
    )
    assert decision.product_match == TruthValue.CONFLICT
    assert decision.has_conflicting_evidence
