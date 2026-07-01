from __future__ import annotations

from rag.utils.text import clean_text, strip_markdown_links


def test_strip_markdown_links_preserves_visible_text():
    text = "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log in."

    cleaned = strip_markdown_links(text)

    assert cleaned == "Adversaries may use Valid Accounts to log in."
    assert "http" not in cleaned
    assert "[" not in cleaned


def test_clean_text_strips_markdown_links():
    text = "Use [Remote Services](https://attack.mitre.org/techniques/T1021) for lateral movement."

    assert clean_text(text) == "Use Remote Services for lateral movement."
