from __future__ import annotations

from rag.context.strategies.base import ContextStrategy
from rag.models.document import ChunkDocument
from rag.utils.text import clean_text

ENTERPRISE_ATTACK_SOURCE = "enterprise-attack.json"


def humanize_tactic(tactic: str) -> str:
    return clean_text(tactic.replace("-", " ").replace("_", " ")).title()


def platform_phrase(platforms: list[str]) -> str:
    if not platforms:
        return "exploitation of Internet-facing systems such as web servers, VPN gateways, cloud services and network devices"
    cleaned = [clean_text(platform) for platform in platforms if clean_text(platform)]
    if not cleaned:
        return "exploitation of Internet-facing systems such as web servers, VPN gateways, cloud services and network devices"
    if len(cleaned) == 1:
        return f"systems and platforms including {cleaned[0]}"
    return f"systems and platforms including {', '.join(cleaned[:-1])} and {cleaned[-1]}"


def retrieval_hint(tactics: list[str]) -> str:
    normalized = {tactic.lower().replace("-", " ").replace("_", " ") for tactic in tactics}
    if "initial access" in normalized:
        return "initial access, exploitation of Internet-facing applications, and external attack surface compromise"
    if "execution" in normalized:
        return "execution techniques, malicious code execution, and post-compromise activity"
    if "persistence" in normalized:
        return "persistence mechanisms and long-term foothold establishment"
    if "defense evasion" in normalized:
        return "defense evasion, stealth techniques, and detection avoidance"
    if "credential access" in normalized:
        return "credential theft, authentication abuse, and identity compromise"
    if "lateral movement" in normalized:
        return "lateral movement, internal network propagation, and pivoting"
    if "impact" in normalized:
        return "impact techniques, service disruption, and destructive activity"
    return "enterprise threat techniques, ATT&CK-based threat scenario generation, and security control mapping"


class EnterpriseAttackContextStrategy:
    def supports(self, chunk: ChunkDocument) -> bool:
        kind = str(chunk.metadata.get("kind") or "")
        source_type = str(chunk.metadata.get("source_type") or chunk.source)
        return kind == "attack-pattern" and source_type == ENTERPRISE_ATTACK_SOURCE

    def generate(self, chunk: ChunkDocument) -> str:
        attack_id = clean_text(chunk.attack_id or str(chunk.metadata.get("attack_id") or ""))
        title = clean_text(chunk.title)
        tactics = chunk.tactic or list(chunk.metadata.get("tactic") or [])
        primary_tactic = humanize_tactic(tactics[0]) if tactics else "Threat"
        platforms = chunk.platform or list(chunk.metadata.get("platform") or [])

        attack_label = f"{attack_id} ({title})" if attack_id and title else attack_id or title or "an Enterprise ATT&CK technique"
        return (
            f"This chunk describes MITRE ATT&CK Enterprise Technique {attack_label}, "
            f"a {primary_tactic} technique involving {platform_phrase(platforms)}. "
            f"It may be relevant when retrieving content about {retrieval_hint(tactics)}."
        )
