from __future__ import annotations

from rag.generation.context_builder import ContextBuilder
from rag.models.document import RetrievedChunk
from rag.retrieval.context_selector import ContextSelector


def _siemens_scalance_advisory_chunk() -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id="ICSA-21-075-02::chunk-1",
        score=0.95,
        source="CISA_ICS_ADV_Master.csv",
        document_id="ICSA-21-075-02",
        metadata={
            "title": "Siemens Web Server of SCALANCE X200 (Update A)",
            "sections": {
                "advisory_id": "ICSA-21-075-02",
                "title": "Siemens Web Server of SCALANCE X200 (Update A)",
                "vendor": "Siemens",
                "product": "Web Server of SCALANCE X200",
                "products_affected": "SCALANCE X200-4P IRT, SCALANCE X200-4P IRT PRO, SCALANCE X200RNA",
                "cves": "CVE-2021-25668, CVE-2021-25669",
                "cwes": "CWE-121, CWE-122",
                "severity": "Critical",
                "sector": "Critical Manufacturing",
            },
        },
        text=(
            "Advisory: Siemens Web Server of SCALANCE X200 (Update A) "
            "Identifier: ICSA-21-075-02 "
            "Vendor: Siemens "
            "Product: Web Server of SCALANCE X200 "
            "Affected Products: SCALANCE X200-4P IRT, SCALANCE X200-4P IRT PRO, SCALANCE X200RNA "
            "CVE: CVE-2021-25668, CVE-2021-25669 "
            "CWE: CWE-121, CWE-122 "
            "Severity: Critical "
            "Sector: Critical Manufacturing"
        ),
    )


def test_render_advisories_includes_structured_fields():
    context = ContextBuilder().build([_siemens_scalance_advisory_chunk()], query="Explain CVE-2021-25668")

    assert "Supporting Advisories" in context
    assert "Vendor: Siemens" in context
    assert "Product: Web Server of SCALANCE X200" in context
    assert "Severity: Critical" in context
    assert "CVE: CVE-2021-25668, CVE-2021-25669" in context
    assert "CWE: CWE-121, CWE-122" in context
    assert "Affected Products: SCALANCE X200-4P IRT" in context
    assert "Sector: Critical Manufacturing" in context
    assert "affects Siemens" not in context
    assert "references CVE" not in context


def test_cve_query_context_preserves_target_cve():
    selected = ContextSelector().select("Explain CVE-2021-25668", [_siemens_scalance_advisory_chunk()])
    context = ContextBuilder().build(selected, query="Explain CVE-2021-25668")

    assert "CVE-2021-25668" in context
    assert selected
    assert selected[0].document_id == "ICSA-21-075-02"


def test_attack_context_strips_markdown_links():
    chunk = RetrievedChunk(
        chunk_id="attack-pattern--remote-services::chunk-1",
        score=0.95,
        source="enterprise-attack.json",
        document_id="attack-pattern--remote-services",
        metadata={"attack_id": "T1021", "title": "Remote Services"},
        text=(
            "Technique Name: Remote Services ATT&CK ID: T1021 "
            "Description: Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) "
            "to log into a service that accepts remote connections, such as telnet, SSH, and VNC."
        ),
    )

    context = ContextBuilder().build([chunk], query="explain remote services")

    assert "Valid Accounts" in context
    assert "[Valid Accounts]" not in context
    assert "attack.mitre.org" not in context


def test_build_sources_lists_each_rendered_chunk_in_order():
    builder = ContextBuilder()
    chunks = [
        RetrievedChunk(
            chunk_id="T1136.002::chunk-1",
            score=0.9,
            source="enterprise-attack.json",
            document_id="attack-pattern--T1136.002",
            metadata={"attack_id": "T1136.002", "title": "Create Account: Domain Account"},
            text=(
                "Technique Name: Create Account: Domain Account ATT&CK ID: T1136.002 "
                "Description: Adversaries may create a domain account to maintain access."
            ),
        ),
        RetrievedChunk(
            chunk_id="T1078.002::chunk-1",
            score=0.85,
            source="enterprise-attack.json",
            document_id="attack-pattern--T1078.002",
            metadata={"attack_id": "T1078.002", "title": "Domain Accounts"},
            text=(
                "Technique Name: Domain Accounts ATT&CK ID: T1078.002 "
                "Description: Adversaries may obtain and abuse credentials of a domain account."
            ),
        ),
    ]

    sources = builder.build_sources(chunks)

    assert len(sources) == 2
    assert sources[0].attack_id == "T1136.002"
    assert sources[1].attack_id == "T1078.002"


def test_build_sources_dedupes_framework_without_attack_id():
    builder = ContextBuilder()
    chunks = [
        RetrievedChunk(
            chunk_id="chunk-1",
            score=0.9,
            source="enterprise-attack.json",
            document_id="attack-pattern--1",
            metadata={"title": "Exploit Public-Facing Application"},
            text="Technique Name: Exploit Public-Facing Application Description: Adversaries may exploit a weakness.",
        ),
        RetrievedChunk(
            chunk_id="chunk-2",
            score=0.8,
            source="enterprise-attack.json",
            document_id="attack-pattern--1",
            metadata={"attack_id": "T1190", "title": "Exploit Public-Facing Application"},
            text="Technique Name: Exploit Public-Facing Application ATT&CK ID: T1190 Detection: Monitor logs.",
        ),
    ]

    sources = builder.build_sources(chunks)

    assert len(sources) == 1
    assert sources[0].document_source == "Enterprise ATT&CK"
    assert sources[0].attack_id == "T1190"
