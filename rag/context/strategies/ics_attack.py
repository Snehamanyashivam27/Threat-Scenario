from __future__ import annotations

from rag.context.strategies.base import ContextStrategy
from rag.context.strategies.enterprise_attack import humanize_tactic, platform_phrase, retrieval_hint
from rag.models.document import ChunkDocument
from rag.utils.text import clean_text

ICS_ATTACK_SOURCE = "ics-attack.json"


class IcsAttackContextStrategy:
    def supports(self, chunk: ChunkDocument) -> bool:
        kind = str(chunk.metadata.get("kind") or "")
        source_type = str(chunk.metadata.get("source_type") or chunk.source)
        return kind == "attack-pattern" and source_type == ICS_ATTACK_SOURCE

    def generate(self, chunk: ChunkDocument) -> str:
        attack_id = clean_text(chunk.attack_id or str(chunk.metadata.get("attack_id") or ""))
        title = clean_text(chunk.title)
        tactics = chunk.tactic or list(chunk.metadata.get("tactic") or [])
        primary_tactic = humanize_tactic(tactics[0]) if tactics else "Threat"
        platforms = chunk.platform or list(chunk.metadata.get("platform") or [])

        attack_label = f"{attack_id} ({title})" if attack_id and title else attack_id or title or "an ICS ATT&CK technique"
        platform_text = platform_phrase(platforms)
        if "industrial" not in platform_text.lower() and "control" not in platform_text.lower():
            platform_text = (
                f"exploiting Internet-facing software to gain access to industrial control systems, "
                f"including {platform_text.removeprefix('systems and platforms including ')}"
                if platform_text.startswith("systems and platforms including ")
                else "exploiting Internet-facing software to gain access to industrial control systems"
            )

        return (
            f"This chunk describes MITRE ATT&CK for ICS Technique {attack_label}, "
            f"a {primary_tactic} technique focused on {platform_text}. "
            f"It may be relevant when retrieving content about ICS threats, {retrieval_hint(tactics)}, "
            f"and industrial control system security scenarios."
        )
