from __future__ import annotations

import re

from rag.utils.text import strip_markdown_links

_EMBEDDED_SOURCES_HEADER = re.compile(r"^Sources:?\s*$", flags=re.IGNORECASE)
_EMBEDDED_SOURCE_LINE = re.compile(
    r"^\s*(?:\*|-|•|\d+\.)?\s*(?:Enterprise ATT&CK|ICS ATT&CK|CISA ICS Advisory)\b.*$",
    flags=re.IGNORECASE,
)
_GENERIC_ADVICE_PHRASES = (
    "multi-factor authentication",
    "strong password",
    "password policies",
    "password policy",
    "user training",
    "both contexts highlight",
    "underscores the importance",
    "importance of implementing",
    "default credentials",
)


def strip_ungrounded_advice(answer: str, context: str) -> str:
    context_lower = context.lower()
    sentences = re.split(r"(?<=[.!?])\s+", answer.strip())
    kept: list[str] = []
    for sentence in sentences:
        lowered = sentence.lower()
        unsupported = False
        for phrase in _GENERIC_ADVICE_PHRASES:
            if phrase in lowered and phrase not in context_lower:
                unsupported = True
                break
        if not unsupported:
            kept.append(sentence)
    return " ".join(part for part in kept if part).strip()


def strip_embedded_sources(answer: str) -> str:
    lines = answer.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    changed = True

    while changed and lines:
        changed = False

        while lines and not lines[-1].strip():
            lines.pop()
            changed = True
        if not lines:
            break

        if _EMBEDDED_SOURCE_LINE.match(lines[-1]):
            while lines and lines[-1].strip() and _EMBEDDED_SOURCE_LINE.match(lines[-1]):
                lines.pop()
                changed = True
            while lines and not lines[-1].strip():
                lines.pop()
                changed = True
            if lines and _EMBEDDED_SOURCES_HEADER.match(lines[-1].strip()):
                lines.pop()
                changed = True
            while lines and not lines[-1].strip():
                lines.pop()
                changed = True
            continue

        if _EMBEDDED_SOURCES_HEADER.match(lines[-1].strip()):
            lines.pop()
            changed = True
            continue

    return "\n".join(lines).strip()


def clean_answer_text(answer: str, context: str = "") -> str:
    cleaned = strip_markdown_links(strip_embedded_sources(answer))
    if context.strip():
        cleaned = strip_ungrounded_advice(cleaned, context)
    return cleaned
