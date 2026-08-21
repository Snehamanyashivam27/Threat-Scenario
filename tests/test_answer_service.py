from __future__ import annotations

from rag.generation.answer_service import DeterministicAnswerService


def test_deterministic_answer_uses_only_retrieved_context():
    context = """Enterprise ATT&CK
Technique: Spearphishing Attachment (T1566.001)
Description: Adversaries may send spearphishing emails with a malicious attachment to gain access to victim systems.

ICS ATT&CK
Technique: Spearphishing Attachment (T0865)
Description: Adversaries may send spearphishing emails with malicious attachments to compromise ICS users or systems."""

    answer = DeterministicAnswerService().generate("What is Spearphishing Attachment?", context)

    assert "T1566.001" in answer
    assert "T0865" in answer
    assert "Internet-facing" not in answer
    assert "web servers" not in answer
    assert "industrial control systems" not in answer or "compromise ICS users or systems" in answer


def test_deterministic_answer_omits_platform_sentence_when_missing():
    context = """Enterprise ATT&CK
Technique: Exploit Public-Facing Application (T1190)
Description: Adversaries may exploit a weakness in an Internet-facing host or system."""

    answer = DeterministicAnswerService().generate("What is Exploit Public-Facing Application?", context)

    assert "T1190" in answer
    assert "platforms such as" not in answer
    assert "VPN gateways" not in answer


def test_deterministic_answer_strips_markdown_and_avoids_repetition():
    context = """Enterprise ATT&CK
Technique: Remote Services (T1021)
Description: Adversaries may use Valid Accounts to log into a service that accepts remote connections, such as telnet, SSH, and VNC.

ICS ATT&CK
Technique: Remote Services (T0886)
Description: Adversaries may leverage remote services to move between assets and network segments."""

    answer = DeterministicAnswerService().generate("Explain the Remote Services ATT&CK technique.", context)

    assert "T1021" in answer
    assert "T0886" in answer
    assert "Valid Accounts" in answer
    assert "[" not in answer
    assert "http" not in answer
    assert answer.count("telnet, SSH, and VNC") == 1
    assert "move between assets and network segments" in answer


def test_deterministic_valid_accounts_uses_descriptions_without_generic_advice():
    context = """Enterprise ATT&CK
Technique: Valid Accounts (T1078)
Tactic: initial-access; persistence; privilege-escalation; defense-evasion
Description: Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.

ICS ATT&CK
Technique: Valid Accounts (T0859)
Tactic: initial-access
Description: Adversaries may steal the credentials of a user or service account to gain access to the ICS environment."""

    answer = DeterministicAnswerService().generate("What is the Valid Accounts ATT&CK technique?", context)

    assert "T1078" in answer
    assert "T0859" in answer
    assert "obtain and abuse credentials" in answer.lower() or "abuse credentials" in answer.lower()
    assert "related products" not in answer.lower()
    assert "objectives including" not in answer.lower()
    assert "multi-factor" not in answer.lower()
    assert "password polic" not in answer.lower()
    assert "user training" not in answer.lower()
    assert "default credentials" not in answer.lower()
    assert "Both contexts highlight" not in answer
    assert "where adversaries" in answer.lower()
    assert ";" not in answer
    assert "adversariesmay" not in answer.lower()


def test_deterministic_cve_answer_summarizes_advisory_fields():
    context = """Supporting Advisories
Advisory: Siemens Web Server of SCALANCE X200 (Update A)
Identifier: 1749
Vendor: Siemens
Product: Siemens Web Server of SCALANCE X200
Severity: Critical
CVE: CVE-2021-25668, CVE-2021-25669
CWE: CWE-122, CWE-121
Affected Products: The following Siemens products are affected: SCALANCE X200-4P IRT: All versions prior to 5.5.1
Sector: Critical Manufacturing"""

    answer = DeterministicAnswerService().generate("Explain CVE-2021-25668", context)

    assert "CVE-2021-25668" in answer
    assert "CISA ICS Advisory 1749" in answer
    assert "Critical" in answer
    assert "CWE-122" in answer
    assert "prior to version 5.5.1" in answer
    assert "Critical Manufacturing" in answer
    assert "not contain enough information" not in answer


def test_deterministic_unknown_cve_does_not_crash_or_attribute_wrong_advisory():
    context = """Supporting Advisories
Advisory: Siemens Web Server of SCALANCE X200 (Update A)
Identifier: 1749
Vendor: Siemens
Product: Siemens Web Server of SCALANCE X200
Severity: Critical
CVE: CVE-2021-25668, CVE-2021-25669
CWE: CWE-122, CWE-121
Affected Products: The following Siemens products are affected: SCALANCE X200-4P IRT: All versions prior to 5.5.1
Sector: Critical Manufacturing"""

    answer = DeterministicAnswerService().generate("CVE-2024-33919", context)

    assert "could not derive a concise answer" in answer
    assert "CVE-2024-33919 is referenced" not in answer


def test_deterministic_product_query_summarizes_advisory_fields():
    context = """Supporting Advisories
Advisory: Siemens Web Server of SCALANCE X200 (Update A)
Identifier: 1749
Vendor: Siemens
Product: Siemens Web Server of SCALANCE X200
Severity: Critical
CVE: CVE-2021-25668, CVE-2021-25669
CWE: CWE-122, CWE-121
Affected Products: SCALANCE X200-4P IRT: All versions prior to 5.5.1
Sector: Critical Manufacturing"""

    answer = DeterministicAnswerService().generate("Tell me about SCALANCE X200.", context)

    assert "CISA ICS Advisory 1749" in answer
    assert "SCALANCE X200" in answer
    assert "Critical" in answer
    assert "CVE-2021-25668" in answer
    assert "could not derive a concise answer" not in answer


def test_fused_results_title_uses_identifier_label():
    from rag.cli import _fused_results_title
    from rag.models.document import RetrievedChunk

    fused = [
        RetrievedChunk(
            chunk_id="1749::chunk-1",
            score=10.0,
            source="CISA_ICS_ADV_Master.csv",
            document_id="1749",
            metadata={"retrieval_method": "identifier"},
            text="Advisory: Siemens",
        )
    ]

    assert _fused_results_title([], [], fused) == "Exact Identifier Match"
    assert _fused_results_title([fused[0]], [], fused) == "RRF Results"


def test_normalize_description_clause_fixes_adversaries_spacing():
    from rag.generation.answer_service import DeterministicAnswerService

    context = """Enterprise ATT&CK
Technique: Valid Accounts (T1078)
Description: Adversariesmay obtain and abuse credentials of existing accounts."""

    answer = DeterministicAnswerService().generate("What is the Valid Accounts ATT&CK technique?", context)

    assert "Adversariesmay" not in answer
    assert "adversaries may" in answer.lower()
