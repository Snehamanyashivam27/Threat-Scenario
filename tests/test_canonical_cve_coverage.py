from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from rag.ingestion.nvd.downloader import NvdCveDownloader
from rag.ingestion.nvd.parser import parse_nvd_cve_document
from rag.ingestion.nvd.store import NvdCveStore
from rag.scenario.canonical_lookup import lookup_nvd_cve_detail
from rag.scenario.cve_validation import evaluate_cve_candidates
from rag.scenario.loader import load_scenario_bundle
from rag.scenario.models import AttackStep, ComponentModel, StepEnrichment
from rag.scenario.step_cve_selection import select_best_step_candidate
from rag.ingest_nvd_cve import main as ingest_nvd_main


CVE = "CVE-2033-44001"


def _component(**overrides) -> ComponentModel:
    values = {
        "id": "target-1",
        "name": "Acme FlowMaster X100",
        "vendor": "Acme Controls",
        "product_family": "FlowMaster",
        "model": "X100",
        "firmware_version": "V1.0",
    }
    values.update(overrides)
    return ComponentModel(**values)


def _step(
    description: str = "The attacker compromises the controller.",
    *,
    name: str = "Compromise Controller",
    step_id: str = "exploit",
) -> AttackStep:
    return AttackStep(
        sequence=3,
        step_id=step_id,
        name=name,
        source_component_id="source-1",
        target_component_id="target-1",
        description=description,
    )


def _csaf_text(
    *,
    cve: str = CVE,
    description: str = "This vulnerability allows authentication bypass.",
    product: str = "FlowMaster X100",
    version: str = "prior to V2.0",
) -> str:
    lines = [
        f"CVE: {cve}",
        "Advisory: ICSA-33-044-01",
        "Vendor: Acme Controls",
        f"Product: {product}",
        "Model: X100",
        f"Affected Versions: {version}",
        "CWE: CWE-287",
        f"Description: {description}" if description else "",
        "document_type: csaf_security_advisory",
    ]
    return "\n".join(line for line in lines if line)


def _csv_text(
    *,
    cve: str = CVE,
    product: str = "FlowMaster",
    affected: str = "X100: All serial numbers",
    description: str = "",
) -> str:
    lines = [
        "Advisory: Acme Controls FlowMaster",
        "ICS Advisory: ICSA-33-044-01",
        "Vendor: Acme Controls",
        f"Product: {product}",
        f"Affected Products: {affected}",
        f"CVE: {cve}",
        "CWE: CWE-287",
        f"Description: {description}" if description else "",
    ]
    return "\n".join(line for line in lines if line)


def _nvd_payload(
    *,
    cve: str = CVE,
    description: str = "",
    cwe: str = "",
    cpes: list[dict] | None = None,
) -> dict:
    cve_obj: dict = {
        "id": cve,
        "descriptions": [{"lang": "en", "value": description}] if description else [],
        "weaknesses": (
            [{"description": [{"lang": "en", "value": cwe}]}] if cwe else []
        ),
        "metrics": {
            "cvssMetricV31": [
                {"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
            ]
        },
        "references": [{"url": "https://example.invalid/nvd"}],
        "configurations": [],
    }
    if cpes:
        cve_obj["configurations"] = [{"nodes": [{"operator": "OR", "cpeMatch": cpes}]}]
    return {"vulnerabilities": [{"cve": cve_obj}]}


def _cpe(
    product: str,
    *,
    vendor: str = "acme",
    part: str = "a",
    version: str = "*",
    **bounds,
) -> dict:
    criteria = f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*"
    item = {"vulnerable": True, "criteria": criteria}
    item.update(bounds)
    return item


def _write_nvd(tmp_path: Path, payload: dict, cve: str = CVE) -> Path:
    store = tmp_path / "nvd_cve"
    store.mkdir()
    path = store / f"{cve}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return store


def _evaluate(text: str, component: ComponentModel, store_dir: Path, step: AttackStep | None = None):
    enrichment = StepEnrichment(
        step=step or _step(),
        primary_query="q",
        primary_answer="a",
        retrieved_text=text,
    )
    candidates = evaluate_cve_candidates(
        enrichment,
        component,
        step or _step(),
        nvd_store_dir=str(store_dir),
    )
    assert candidates
    return candidates[0]


def _status(candidate, name: str) -> str:
    return next(check.status.value for check in candidate.checks if check.name == name)


def test_csaf_description_wins_over_nvd(tmp_path):
    store = _write_nvd(
        tmp_path,
        _nvd_payload(description="NVD-only denial of service in an unrelated subsystem."),
    )
    candidate = _evaluate(_csaf_text(), _component(), store)
    assert _status(candidate, "technical_effect") == "known_true"
    assert candidate.vulnerability_phrase
    assert "denial of service" not in (candidate.vulnerability_phrase or "").lower()


def test_nvd_fills_missing_csaf_description_without_changing_version(tmp_path):
    store = _write_nvd(
        tmp_path,
        _nvd_payload(
            description="This vulnerability allows authentication bypass.",
            cpes=[_cpe("flowmaster_x100", versionEndExcluding="9.0")],
        ),
    )
    candidate = _evaluate(
        _csaf_text(description=""),
        _component(firmware_version="V5.0"),
        store,
    )
    assert _status(candidate, "product") == "known_true"
    assert _status(candidate, "version") == "known_false"
    assert _status(candidate, "technical_effect") == "known_true"


def test_boilerplate_csaf_description_is_filled_from_nvd(tmp_path):
    store = _write_nvd(
        tmp_path,
        _nvd_payload(description="This vulnerability allows authentication bypass."),
    )
    candidate = _evaluate(
        _csaf_text(description="See the advisory."),
        _component(),
        store,
    )
    assert _status(candidate, "technical_effect") == "known_true"
    assert _status(candidate, "product") == "known_true"


def test_csv_plus_nvd_makes_canonical_detail_available(tmp_path):
    store = _write_nvd(
        tmp_path,
        _nvd_payload(description="This vulnerability allows authentication bypass."),
    )
    candidate = _evaluate(_csv_text(), _component(), store)
    assert candidate.cve_id == CVE
    assert _status(candidate, "product") == "known_true"
    assert _status(candidate, "technical_effect") == "known_true"


def test_nvd_description_supports_cve_local_effect(tmp_path):
    store = _write_nvd(
        tmp_path,
        _nvd_payload(description="An unauthenticated remote attackers condition allows authentication bypass."),
    )
    candidate = _evaluate(_csv_text(), _component(), store)
    assert _status(candidate, "technical_effect") == "known_true"


def test_cwe_alone_does_not_authorize_effect(tmp_path):
    store = _write_nvd(tmp_path, _nvd_payload(cwe="CWE-294"))
    candidate = _evaluate(_csv_text(), _component(), store)
    assert _status(candidate, "product") == "known_true"
    assert _status(candidate, "technical_effect") == "unknown"
    selection = select_best_step_candidate("exploit", [candidate], step=_step(), component=_component())
    assert selection.selected is None


def test_nvd_family_cpe_cannot_create_exact_model_true(tmp_path):
    store = _write_nvd(
        tmp_path,
        _nvd_payload(cpes=[_cpe("flowmaster_series")]),
    )
    candidate = _evaluate(
        _csv_text(product="FlowMaster", affected="FlowMaster Series devices"),
        _component(),
        store,
    )
    assert _status(candidate, "product") != "known_true"


def test_nvd_exact_model_cpe_follows_identity_rules(tmp_path):
    store = _write_nvd(
        tmp_path,
        _nvd_payload(
            description="This vulnerability allows authentication bypass.",
            cpes=[_cpe("x100")],
        ),
    )
    candidate = _evaluate(
        _csv_text(product="FlowMaster", affected="FlowMaster family products"),
        _component(),
        store,
    )
    assert _status(candidate, "product") == "known_true"
    assert _status(candidate, "model") == "known_true"


def test_nvd_product_a_version_does_not_apply_to_product_b(tmp_path):
    store = _write_nvd(
        tmp_path,
        _nvd_payload(
            description="This vulnerability allows authentication bypass.",
            cpes=[
                _cpe("x100", versionEndExcluding="2.0"),
                _cpe("x200", versionStartIncluding="8.0", versionEndExcluding="9.0"),
            ],
        ),
    )
    matched = _evaluate(_csv_text(affected="FlowMaster family products"), _component(), store)
    x200_high = _evaluate(
        _csv_text(affected="FlowMaster family products"),
        _component(model="X200", name="Acme FlowMaster X200", firmware_version="V8.5"),
        store,
    )
    x200_low = _evaluate(
        _csv_text(affected="FlowMaster family products"),
        _component(model="X200", name="Acme FlowMaster X200", firmware_version="V1.5"),
        store,
    )
    assert _status(matched, "version") == "known_true"
    assert _status(x200_high, "version") == "known_true"
    assert _status(x200_low, "version") == "known_false"


def test_vendor_version_wins_over_conflicting_nvd_version(tmp_path):
    store = _write_nvd(
        tmp_path,
        _nvd_payload(
            description="This vulnerability allows authentication bypass.",
            cpes=[_cpe("x100", versionEndExcluding="9.0")],
        ),
    )
    candidate = _evaluate(
        _csaf_text(description="This vulnerability allows authentication bypass."),
        _component(firmware_version="V5.0"),
        store,
    )
    assert _status(candidate, "version") == "known_false"
    assert candidate.final_status == "rejected_version_mismatch"


def test_missing_nvd_record_abstains_without_crash(tmp_path):
    store = tmp_path / "empty"
    store.mkdir()
    candidate = _evaluate(_csv_text(), _component(), store)
    assert _status(candidate, "product") == "known_true"
    assert _status(candidate, "technical_effect") == "unknown"
    assert lookup_nvd_cve_detail(CVE, store_dir=str(store)) is None


def test_exact_lookup_is_deterministic(tmp_path):
    store = _write_nvd(tmp_path, _nvd_payload(description="This vulnerability allows authentication bypass."))
    first = lookup_nvd_cve_detail(CVE, store_dir=str(store))
    second = lookup_nvd_cve_detail(CVE, store_dir=str(store))
    assert first is not None and second is not None
    assert first.to_dict() == second.to_dict()


def test_canonical_record_serialization_is_deterministic():
    record = parse_nvd_cve_document(
        _nvd_payload(
            description="This vulnerability allows authentication bypass.",
            cwe="CWE-287",
            cpes=[_cpe("x100", versionEndExcluding="2.0")],
        )
    )
    encoded = json.dumps(record.to_dict(), sort_keys=True)
    assert encoded == json.dumps(record.to_dict(), sort_keys=True)
    assert record.field_provenance.get("description") == "nvd"
    assert record.cpe_matches
    assert record.cwe_ids == ["CWE-287"]


def test_runtime_lookup_does_not_call_http(tmp_path, monkeypatch):
    store = _write_nvd(tmp_path, _nvd_payload(description="This vulnerability allows authentication bypass."))
    boom = MagicMock(side_effect=AssertionError("runtime must not call NVD"))
    monkeypatch.setattr("urllib.request.urlopen", boom)
    candidate = _evaluate(_csv_text(), _component(), store)
    assert _status(candidate, "technical_effect") == "known_true"
    boom.assert_not_called()


def test_ingest_from_file_is_offline(tmp_path, monkeypatch):
    source = tmp_path / "source.json"
    source.write_text(json.dumps(_nvd_payload(description="This vulnerability allows authentication bypass.")), encoding="utf-8")
    dest = tmp_path / "store"
    boom = MagicMock(side_effect=AssertionError("ingest --from-file must not call NVD"))
    monkeypatch.setattr("urllib.request.urlopen", boom)
    assert ingest_nvd_main(["--from-file", str(source), "--store-dir", str(dest)]) == 0
    boom.assert_not_called()
    stored = NvdCveStore(dest).lookup(CVE)
    assert stored is not None
    assert stored.description


def test_cached_nvd_download_skips_http(tmp_path):
    cached = tmp_path / "CVE-2033-44001.json"
    cached.write_text(json.dumps(_nvd_payload()), encoding="utf-8")
    opener = MagicMock()
    downloader = NvdCveDownloader(cache_dir=tmp_path, opener=opener)
    result = downloader.download(CVE, refresh=False)
    assert result.status == "cached"
    opener.assert_not_called()


def test_malformed_nvd_file_does_not_crash_lookup(tmp_path):
    store = tmp_path / "nvd_cve"
    store.mkdir()
    (store / f"{CVE}.json").write_text("{not-json", encoding="utf-8")
    assert lookup_nvd_cve_detail(CVE, store_dir=str(store)) is None
    candidate = _evaluate(_csv_text(), _component(), store)
    assert _status(candidate, "technical_effect") == "unknown"


def test_test003_probe_still_depends_on_local_canonical_evidence(tmp_path):
    root = Path(__file__).resolve().parents[1]
    bundle = load_scenario_bundle(root / "examples" / "TS-OT-TEST-003")
    step = next(item for item in bundle.scenario.attack_path if item.step_id == "replay")
    target = bundle.components_by_id[step.target_component_id or ""]
    from rag.ingestion.loaders import load_cisa_advisories
    from rag.ingestion.parser import parse_cisa_advisories

    reference = target.advisory_reference()
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
    )
    empty = tmp_path / "empty"
    empty.mkdir()
    candidates = evaluate_cve_candidates(enrichment, target, step, bundle, nvd_store_dir=str(empty))
    assert candidates
    candidate = candidates[0]
    assert _status(candidate, "product") == "known_true"
    assert _status(candidate, "technical_effect") == "unknown"
    selection = select_best_step_candidate(step.step_id, candidates, step=step, component=target)
    assert selection.selected is None
