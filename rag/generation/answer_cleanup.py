from __future__ import annotations

import re

from rag.utils.text import strip_markdown_links

_EMBEDDED_SOURCES_HEADER = re.compile(r"^Sources:?\s*$", flags=re.IGNORECASE)
_EMBEDDED_SOURCE_LINE = re.compile(
    r"^\s*(?:\*|-|•|\d+\.)?\s*(?:Enterprise ATT&CK|ICS ATT&CK|CISA ICS Advisory)\b.*$",
    flags=re.IGNORECASE,
)


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


def clean_answer_text(answer: str) -> str:
    return strip_markdown_links(strip_embedded_sources(answer))
