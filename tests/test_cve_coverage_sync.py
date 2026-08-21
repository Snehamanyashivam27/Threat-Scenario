from __future__ import annotations

import inspect
import json
from unittest.mock import MagicMock

from rag.defense.inventory import inventory_step_evidence
from rag.defense.recommendation_policy import apply_recommendation_policy
from rag.defense.recommendation_renderer import render_actionable_recommendations
from rag.defense.unified_evidence import unify_step_defense_evidence
from rag.defense.validation import validate_step_evidence
from rag.ingestion.cisa_advisory.downloader import CisaAdvisoryDownloader
from rag.ingestion.cisa_advisory.parser import parse_cisa_advisory_html
from rag.ingestion.cisa_advisory.store import AdvisoryDetailStore
from rag.ingestion.coverage import (
    assess_corpus_coverage,
    is_sufficient_cve_description,
    summarize_coverage,
)
from rag.ingestion.csaf.downloader import CsafDownloader
from rag.ingestion.nvd.downloader import NvdCveDownloader
from rag.scenario.cli import main as scenario_main
from rag.scenario.evidence import ApplicabilityCheck, CandidateEvidence, StepEvidence, TruthValue
from rag.sync_cve_coverage import main as sync_main

CVE = "CVE-2033-55001"
ADV = "ICSA-33-001-01"
CSV_HEADER = (
    "icsad_ID,Original_Release_Date,Last_Updated,Year,ICS-CERT_Number,"
    "ICS-CERT_Advisory_Title,Vendor,Product,Products_Affected,CVE_Number,"
    "Cumulative_CVSS,CVSS_Severity,CWE_Number,Critical_Infrastructure_Sector,"
    "Product_Distribution,Company_Headquarters,License"
)


class _Response:
    def __init__(self, payload: bytes, status: int = 200):
        self._payload = payload
        self.status = status

    def read(self) -> bytes:
        return self._payload

    def getcode(self) -> int:
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _csv(path, cve: str = CVE, advisory: str = ADV):
    path.write_text(
        CSV_HEADER
        + "\n"
        + f"1,1/1/2033,1/1/2033,2033,{advisory},Title,Vendor,Product,Affected,{cve},"
        + "1,Low,CWE-1,Sector,WW,US,ODbL\n",
        encoding="utf-8",
    )
    return path


def _csaf_json(
    *,
    cve: str = CVE,
    advisory: str = ADV,
    description: str = "This vulnerability allows authentication bypass on the web interface.",
    remediation: str | None = "Update to V2.0.",
) -> dict:
    vulnerability: dict = {
        "cve": cve,
        "notes": [{"category": "description", "text": description}] if description else [],
        "product_status": {"known_affected": ["CSAFPID-0001"]},
    }
    if remediation:
        vulnerability["remediations"] = [{"category": "vendor_fix", "details": remediation}]
    return {
        "document": {
            "category": "csaf_security_advisory",
            "csaf_version": "2.0",
            "title": "Synthetic",
            "tracking": {"id": advisory, "status": "final", "version": "1"},
            "publisher": {
                "category": "coordinator",
                "name": "Example",
                "namespace": "https://example.invalid/",
            },
        },
        "product_tree": {
            "branches": [
                {
                    "category": "vendor",
                    "name": "Example Vendor",
                    "branches": [
                        {
                            "category": "product_name",
                            "name": "Example Product",
                            "product": {"name": "Example Product", "product_id": "CSAFPID-0001"},
                        }
                    ],
                }
            ]
        },
        "vulnerabilities": [vulnerability],
    }


def _nvd_payload(
    *,
    cve: str = CVE,
    description: str = "This vulnerability allows authentication bypass on the web interface.",
) -> dict:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve,
                    "descriptions": [{"lang": "en", "value": description}] if description else [],
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-77"}]}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
                    "references": [{"url": "https://example.invalid/nvd"}],
                    "configurations": [],
                }
            }
        ]
    }


def _html(
    *,
    advisory: str = ADV,
    cve: str = CVE,
    cve_fix: str = "For CVE-2033-55001: Update firmware to V9.0 or later.",
    general: str = "Restrict management-plane access to trusted networks only.",
) -> str:
    return f"""
    <html><head><title>{advisory}</title></head><body>
    <h1>{advisory} Example Advisory</h1>
    <p>This advisory covers {cve}.</p>
    <h2>Vulnerability Overview</h2>
    <p>{cve} allows command injection through the authenticated web interface of the controller.</p>
    <h2>Vendor Mitigation</h2>
    <p>{cve_fix}</p>
    <h2>Mitigations</h2>
    <p>{general}</p>
    <h2>CISA Recommended Practices</h2>
    <p>CISA recommends users take defensive measures. Minimize network exposure for ICS networks.</p>
    </body></html>
    """


def _candidate(cve: str = CVE, advisory: str | None = ADV) -> CandidateEvidence:
    return CandidateEvidence(
        cve_id=cve,
        advisory_id=advisory,
        disposition="applicable",
        final_status="verified_applicable",
        checks=[
            ApplicabilityCheck(name="product", status=TruthValue.TRUE),
            ApplicabilityCheck(name="version", status=TruthValue.TRUE),
            ApplicabilityCheck(name="technical_effect", status=TruthValue.TRUE),
        ],
        lifecycle=["SELECTED"],
        product_evidence_trace=[
            {
                "source": "cisa_csaf",
                "provenance": "product_status.known_affected",
                "scope": "cve_specific",
                "identity_origin": "product_tree_resolved",
                "evidence_strength": "SOURCE_MEMBERSHIP",
                "polarity": "POSITIVE",
                "matched_dimension": "model",
                "conflicting_evidence": "",
                "product_id": "CSAFPID-0001",
            }
        ],
    )


def _step(selected: str | None = CVE, advisory: str | None = ADV) -> StepEvidence:
    candidates = [_candidate(selected, advisory)] if selected else []
    return StepEvidence(
        step_id="step-compromise",
        sequence=5,
        candidates=candidates,
        selected_cve=selected,
        selected_cves=[selected] if selected else [],
    )


def test_cve_id_or_cwe_only_is_not_effect_coverage():
    assert not is_sufficient_cve_description("CVE-2033-55001")
    assert not is_sufficient_cve_description("CWE-77")
    assert not is_sufficient_cve_description("See the advisory.")
    assert is_sufficient_cve_description(
        "This vulnerability allows authentication bypass on the web interface."
    )


def test_coverage_tracks_dimensions_separately(tmp_path):
    csv_path = _csv(tmp_path / "master.csv")
    csaf_dir = tmp_path / "csaf"
    nvd_dir = tmp_path / "nvd"
    advisory_dir = tmp_path / "advisory"
    csaf_dir.mkdir()
    nvd_dir.mkdir()
    advisory_dir.mkdir()
    (csaf_dir / f"{ADV}.json").write_text(
        json.dumps(_csaf_json(description="", remediation=None)),
        encoding="utf-8",
    )
    rows = assess_corpus_coverage(
        csv_path=csv_path,
        csaf_dir=csaf_dir,
        nvd_dir=nvd_dir,
        advisory_dir=advisory_dir,
    )
    summary = summarize_coverage(rows, csv_advisories={ADV})
    assert summary.discovered_cves == 1
    assert rows[CVE].csaf_detail
    assert not rows[CVE].effect_description
    assert not rows[CVE].csaf_remediation
    assert summary.missing_effect_description == 1


def test_coverage_summary_reports_required_evidence_buckets(tmp_path):
    csv_path = _csv(tmp_path / "master.csv")
    csaf_dir = tmp_path / "csaf"
    nvd_dir = tmp_path / "nvd"
    advisory_dir = tmp_path / "advisory"
    csaf_dir.mkdir()
    nvd_dir.mkdir()
    advisory_dir.mkdir()
    payload = _csaf_json()
    product_name = payload["product_tree"]["branches"][0]["branches"][0]
    product_name["name"] = "Example Product 1.0"
    product_name["product"]["name"] = "Example Product 1.0"
    payload["product_tree"]["branches"][0]["branches"].append(
        {
            "category": "product_name",
            "name": "Other Product",
            "product": {"name": "Other Product", "product_id": "CSAFPID-0002"},
        }
    )
    payload["vulnerabilities"][0]["product_status"]["known_not_affected"] = ["CSAFPID-0002"]
    (csaf_dir / f"{ADV}.json").write_text(json.dumps(payload), encoding="utf-8")
    rows = assess_corpus_coverage(
        csv_path=csv_path,
        csaf_dir=csaf_dir,
        nvd_dir=nvd_dir,
        advisory_dir=advisory_dir,
    )
    summary = summarize_coverage(
        rows,
        csv_advisories={ADV},
        csv_cve_ids={CVE},
        csaf_dir=csaf_dir,
        nvd_dir=nvd_dir,
    )
    assert summary.csv_cves == 1
    assert rows[CVE].identity
    assert rows[CVE].effect_description
    assert rows[CVE].remediation
    assert rows[CVE].non_affected
    assert summary.missing_identity == 0
    assert summary.missing_effect_description == 0
    assert summary.missing_remediation == 0
    assert summary.non_affected == 1
    assert summary.csaf_advisories_to_acquire == 0
    assert summary.complete_evidence == int(rows[CVE].has_all_required())


def test_sync_from_local_files_is_offline(tmp_path, monkeypatch):
    boom = MagicMock(side_effect=AssertionError("sync --no-network must not fetch"))
    monkeypatch.setattr("urllib.request.urlopen", boom)
    csv_path = _csv(tmp_path / "master.csv")
    nvd_src = tmp_path / "nvd-src.json"
    nvd_src.write_text(json.dumps(_nvd_payload()), encoding="utf-8")
    html_src = tmp_path / "advisory.html"
    html_src.write_text(_html(), encoding="utf-8")
    nvd_dir = tmp_path / "nvd"
    advisory_dir = tmp_path / "advisory"
    csaf_dir = tmp_path / "csaf"
    csaf_dir.mkdir()
    code = sync_main(
        [
            "--root",
            str(tmp_path),
            "--csv",
            str(csv_path),
            "--csaf-dir",
            str(csaf_dir),
            "--nvd-dir",
            str(nvd_dir),
            "--advisory-dir",
            str(advisory_dir),
            "--from-nvd-file",
            str(nvd_src),
            "--from-advisory-file",
            str(html_src),
            "--no-network",
            "--cve",
            CVE,
        ]
    )
    assert code == 0
    boom.assert_not_called()
    rows = assess_corpus_coverage(
        csv_path=csv_path,
        csaf_dir=csaf_dir,
        nvd_dir=nvd_dir,
        advisory_dir=advisory_dir,
        cve_ids=[CVE],
    )
    assert rows[CVE].nvd_detail
    assert rows[CVE].effect_description
    assert rows[CVE].advisory_remediation


def test_dry_run_does_not_write(tmp_path, monkeypatch, capsys):
    boom = MagicMock(side_effect=AssertionError("dry-run must not fetch"))
    monkeypatch.setattr("urllib.request.urlopen", boom)
    csv_path = _csv(tmp_path / "master.csv")
    nvd_dir = tmp_path / "nvd"
    csaf_dir = tmp_path / "csaf"
    advisory_dir = tmp_path / "advisory"
    nvd_src = tmp_path / "nvd-src.json"
    nvd_src.write_text(json.dumps(_nvd_payload()), encoding="utf-8")
    code = sync_main(
        [
            "--csv",
            str(csv_path),
            "--csaf-dir",
            str(csaf_dir),
            "--nvd-dir",
            str(nvd_dir),
            "--advisory-dir",
            str(advisory_dir),
            "--from-nvd-file",
            str(nvd_src),
            "--dry-run",
            "--cve",
            CVE,
        ]
    )
    assert code == 0
    boom.assert_not_called()
    assert not nvd_dir.exists() or not any(nvd_dir.glob("*.json"))
    captured = capsys.readouterr().out
    assert "missing_effect_description" in captured


def test_nvd_download_is_atomic_and_preserves_existing(tmp_path):
    dest = tmp_path / f"{CVE}.json"
    dest.write_text(json.dumps(_nvd_payload(description="Original local NVD description text.")), encoding="utf-8")
    opener = MagicMock(return_value=_Response(json.dumps(_nvd_payload(description="Replacement")).encode()))
    downloader = NvdCveDownloader(cache_dir=tmp_path, opener=opener)
    result = downloader.download(CVE, refresh=False)
    assert result.status == "cached"
    opener.assert_not_called()
    assert "Original local NVD description text." in dest.read_text(encoding="utf-8")


def test_failed_nvd_parse_leaves_no_partial_file(tmp_path):
    opener = MagicMock(return_value=_Response(b"{not-json"))
    downloader = NvdCveDownloader(
        cache_dir=tmp_path,
        opener=opener,
        max_retries=2,
        backoff_seconds=0.0,
    )
    result = downloader.download(CVE, refresh=True)
    assert result.status == "unavailable"
    assert not (tmp_path / f"{CVE}.json").exists()
    assert not list(tmp_path.glob("*.tmp"))


def test_failed_csaf_parse_leaves_no_partial_file(tmp_path):
    opener = MagicMock(return_value=_Response(b"{not-json"))
    downloader = CsafDownloader(
        cache_dir=tmp_path,
        opener=opener,
        max_retries=1,
        backoff_seconds=0.0,
        base_urls=("https://example.invalid/{year}/{advisory_lower}.json",),
    )
    result = downloader.download(ADV, refresh=True)
    assert result.status == "unavailable"
    assert not (tmp_path / f"{ADV}.json").exists()
    assert not list(tmp_path.glob("*.tmp"))


def test_csaf_download_skips_existing_without_refresh(tmp_path):
    dest = tmp_path / f"{ADV}.json"
    dest.write_text(json.dumps(_csaf_json()), encoding="utf-8")
    opener = MagicMock()
    downloader = CsafDownloader(cache_dir=tmp_path, opener=opener)
    result = downloader.download(ADV, refresh=False)
    assert result.status == "cached"
    opener.assert_not_called()


def test_advisory_html_download_is_atomic(tmp_path):
    opener = MagicMock(return_value=_Response(_html().encode()))
    downloader = CisaAdvisoryDownloader(
        cache_dir=tmp_path,
        opener=opener,
        max_retries=1,
        backoff_seconds=0.0,
    )
    result = downloader.download(ADV, refresh=False)
    assert result.status == "downloaded"
    stored = AdvisoryDetailStore(tmp_path).lookup(ADV)
    assert stored is not None
    assert stored.advisory_id == ADV
    assert not list(tmp_path.glob("*.tmp"))
    opener.return_value = _Response(_html(cve_fix="Replacement text that should not land.").encode())
    cached = downloader.download(ADV, refresh=False)
    assert cached.status == "cached"
    assert all("Replacement text" not in item.get("details", "") for item in stored.remediations)


def test_failed_advisory_fetch_leaves_no_file(tmp_path):
    def failing_opener(request, timeout=30):  # noqa: ARG001
        raise TimeoutError("network down")

    downloader = CisaAdvisoryDownloader(
        cache_dir=tmp_path,
        opener=failing_opener,
        max_retries=2,
        backoff_seconds=0.0,
    )
    result = downloader.download(ADV, refresh=True)
    assert result.status == "unavailable"
    assert not (tmp_path / f"{ADV}.json").exists()


def test_html_parser_is_conservative_about_binding():
    parsed = parse_cisa_advisory_html(_html(), advisory_id=ADV)
    scopes = {item["scope"] for item in parsed.remediations}
    assert "cve_specific" in scopes
    assert "advisory_level" in scopes
    assert all(item["scope"] != "product_specific" for item in parsed.remediations)
    assert not any("CISA recommends" in item["details"] for item in parsed.remediations)
    cve_bound = [item for item in parsed.remediations if item["scope"] == "cve_specific"]
    assert cve_bound[0]["cve_ids"] == [CVE]
    ambiguous = parse_cisa_advisory_html(
        _html(cve_fix="Update firmware to V9.0 or later for the affected products."),
        advisory_id=ADV,
    )
    assert any(
        item["scope"] == "advisory_level" and "affected products" in item["details"]
        for item in ambiguous.remediations
    )


def test_defense_fallback_used_only_when_csaf_empty(tmp_path):
    csaf_dir = tmp_path / "csaf"
    advisory_dir = tmp_path / "advisory"
    csaf_dir.mkdir()
    store = AdvisoryDetailStore(advisory_dir)
    store.write(parse_cisa_advisory_html(_html(), advisory_id=ADV), refresh=True)
    rows = inventory_step_evidence([_step()], csaf_dir, advisory_dir=advisory_dir)
    assert rows[0].note == "advisory_detail_fallback"
    assert rows[0].records
    assert rows[0].records[0].source_type == "cisa_ics_advisory_detail"


def test_csaf_remediation_wins_and_is_not_duplicated(tmp_path):
    csaf_dir = tmp_path / "csaf"
    advisory_dir = tmp_path / "advisory"
    csaf_dir.mkdir()
    (csaf_dir / f"{ADV}.json").write_text(json.dumps(_csaf_json()), encoding="utf-8")
    store = AdvisoryDetailStore(advisory_dir)
    store.write(
        parse_cisa_advisory_html(
            _html(cve_fix="For CVE-2033-55001: Update to V2.0."),
            advisory_id=ADV,
        ),
        refresh=True,
    )
    rows = inventory_step_evidence([_step()], csaf_dir, advisory_dir=advisory_dir)
    assert rows[0].note == ""
    details = [action.details for record in rows[0].records for action in record.remediations]
    assert details.count("Update to V2.0.") == 1
    assert all(record.source_type != "cisa_ics_advisory_detail" for record in rows[0].records)


def test_unrelated_advisory_cannot_supply_fallback(tmp_path):
    csaf_dir = tmp_path / "csaf"
    advisory_dir = tmp_path / "advisory"
    csaf_dir.mkdir()
    store = AdvisoryDetailStore(advisory_dir)
    store.write(
        parse_cisa_advisory_html(_html(advisory="ICSA-33-099-09", cve="CVE-2033-55999"), advisory_id="ICSA-33-099-09"),
        refresh=True,
    )
    rows = inventory_step_evidence([_step()], csaf_dir, advisory_dir=advisory_dir)
    assert rows[0].records == []
    assert rows[0].note == "csaf_not_found"


def test_missing_advisory_id_does_not_fallback(tmp_path):
    csaf_dir = tmp_path / "csaf"
    advisory_dir = tmp_path / "advisory"
    csaf_dir.mkdir()
    store = AdvisoryDetailStore(advisory_dir)
    store.write(parse_cisa_advisory_html(_html(), advisory_id=ADV), refresh=True)
    rows = inventory_step_evidence([_step(advisory=None)], csaf_dir, advisory_dir=advisory_dir)
    assert rows[0].records == []


def test_nvd_is_not_converted_into_defense(tmp_path):
    csaf_dir = tmp_path / "csaf"
    advisory_dir = tmp_path / "advisory"
    nvd_dir = tmp_path / "nvd"
    csaf_dir.mkdir()
    advisory_dir.mkdir()
    nvd_dir.mkdir()
    (nvd_dir / f"{CVE}.json").write_text(json.dumps(_nvd_payload()), encoding="utf-8")
    rows = inventory_step_evidence([_step()], csaf_dir, advisory_dir=advisory_dir)
    assert rows[0].records == []
    csaf = validate_step_evidence([_step()], rows)
    texts = [
        item.rendered_text
        for step in render_actionable_recommendations(
            apply_recommendation_policy(unify_step_defense_evidence(csaf, []))
        ).steps
        for item in step.recommendations
    ]
    assert texts == []


def test_no_source_yields_no_defense(tmp_path):
    rows = inventory_step_evidence(
        [_step()],
        tmp_path / "csaf",
        advisory_dir=tmp_path / "advisory",
    )
    assert rows[0].records == []
    assert rows[0].note == "csaf_not_found"


def test_html_vendor_fix_renders_when_csaf_empty(tmp_path):
    csaf_dir = tmp_path / "csaf"
    advisory_dir = tmp_path / "advisory"
    csaf_dir.mkdir()
    AdvisoryDetailStore(advisory_dir).write(parse_cisa_advisory_html(_html(), advisory_id=ADV), refresh=True)
    inventory = inventory_step_evidence([_step()], csaf_dir, advisory_dir=advisory_dir)
    report = render_actionable_recommendations(
        apply_recommendation_policy(
            unify_step_defense_evidence(validate_step_evidence([_step()], inventory), [])
        )
    )
    texts = [item.rendered_text for step in report.steps for item in step.recommendations]
    assert any("Update firmware to V9.0" in text for text in texts)
    assert any(text.startswith("Vendor remediation:") or text.startswith("Advisory-level") for text in texts)


def test_runtime_cli_does_not_invoke_coverage_sync():
    source = inspect.getsource(scenario_main)
    assert "sync_cve_coverage" not in source
    assert "NvdCveDownloader" not in source
    assert "CsafDownloader" not in source
    assert "CisaAdvisoryDownloader" not in source
    assert "urlopen" not in source


def test_sync_fetches_csaf_for_wanted_cve_even_if_nvd_covers_effect(tmp_path, monkeypatch):
    csv_path = _csv(tmp_path / "master.csv")
    csaf_dir = tmp_path / "csaf"
    nvd_dir = tmp_path / "nvd"
    advisory_dir = tmp_path / "advisory"
    csaf_dir.mkdir()
    nvd_dir.mkdir()
    (nvd_dir / f"{CVE}.json").write_text(json.dumps(_nvd_payload()), encoding="utf-8")
    calls: list[str] = []

    def opener(request, timeout=30):  # noqa: ARG001
        url = getattr(request, "full_url", str(request))
        calls.append(url)
        if "cves/2.0" in url:
            raise AssertionError("NVD should not be fetched when description already exists")
        if "ics-advisories" in url:
            return _Response(_html().encode())
        return _Response(json.dumps(_csaf_json()).encode())

    monkeypatch.setattr("urllib.request.urlopen", opener)
    code = sync_main(
        [
            "--csv",
            str(csv_path),
            "--csaf-dir",
            str(csaf_dir),
            "--nvd-dir",
            str(nvd_dir),
            "--advisory-dir",
            str(advisory_dir),
            "--cve",
            CVE,
            "--skip-advisory-html",
        ]
    )
    assert code == 0
    assert any("csaf" in url.lower() or "github" in url.lower() or ADV.lower() in url.lower() for url in calls)
    assert (csaf_dir / f"{ADV}.json").exists()


def test_sync_mocked_network_respects_limit(tmp_path, monkeypatch):
    csv_path = tmp_path / "master.csv"
    csv_path.write_text(
        CSV_HEADER
        + "\n"
        + f"1,1/1/2033,1/1/2033,2033,{ADV},Title,Vendor,Product,Affected,{CVE},1,Low,CWE-1,S,WW,US,ODbL\n"
        + "2,1/1/2033,1/1/2033,2033,ICSA-33-001-02,Title,Vendor,Product,Affected,CVE-2033-55002,1,Low,CWE-1,S,WW,US,ODbL\n",
        encoding="utf-8",
    )
    csaf_dir = tmp_path / "csaf"
    nvd_dir = tmp_path / "nvd"
    advisory_dir = tmp_path / "advisory"
    csaf_dir.mkdir()

    def opener(request, timeout=30):  # noqa: ARG001
        url = getattr(request, "full_url", str(request))
        if "cves/2.0" in url:
            cve = url.rsplit("cveId=", 1)[-1]
            return _Response(json.dumps(_nvd_payload(cve=cve)).encode())
        if "ics-advisories" in url:
            return _Response(_html().encode())
        return _Response(json.dumps(_csaf_json()).encode())

    monkeypatch.setattr("urllib.request.urlopen", opener)
    code = sync_main(
        [
            "--csv",
            str(csv_path),
            "--csaf-dir",
            str(csaf_dir),
            "--nvd-dir",
            str(nvd_dir),
            "--advisory-dir",
            str(advisory_dir),
            "--limit",
            "1",
            "--skip-csaf",
            "--skip-advisory-html",
        ]
    )
    assert code == 0
    nvd_files = list(nvd_dir.glob("CVE-*.json"))
    assert len(nvd_files) == 1
