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

    answer = DeterministicAnswerService().generate("explain remote services", context)

    assert "T1021" in answer
    assert "T0886" in answer
    assert "Valid Accounts" in answer
    assert "[" not in answer
    assert "http" not in answer
    assert answer.count("telnet, SSH, and VNC") == 1
    assert "move between assets and network segments" in answer
