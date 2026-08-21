from __future__ import annotations

import os
import re
from pathlib import Path

from rag.ingestion.atomic import atomic_write_json
from rag.ingestion.csaf.models import CveDetailRecord
from rag.ingestion.nvd.parser import parse_nvd_cve_file


def default_nvd_store_dir() -> Path:
    env = (os.environ.get("RAG_NVD_CVE_DIR") or "").strip()
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[3] / "data" / "nvd_cve"


class NvdCveStore:
    """Deterministic exact-CVE lookup against a local NVD cache directory.

    Runtime callers must only read files. Network acquisition belongs in ingest.
    """

    def __init__(self, store_dir: str | Path | None = None):
        self.store_dir = Path(store_dir) if store_dir is not None else default_nvd_store_dir()

    def path_for(self, cve_id: str) -> Path:
        return self.store_dir / f"{_normalize_cve_id(cve_id)}.json"

    def lookup(self, cve_id: str) -> CveDetailRecord | None:
        normalized = _normalize_cve_id(cve_id)
        if not normalized:
            return None
        path = self.path_for(normalized)
        if not path.is_file():
            return None
        record = parse_nvd_cve_file(path)
        if record is None:
            return None
        if record.cve_id.upper() != normalized:
            return None
        return record

    def write(self, record: CveDetailRecord, *, refresh: bool = False) -> Path:
        self.store_dir.mkdir(parents=True, exist_ok=True)
        path = self.path_for(record.cve_id)
        if path.exists() and not refresh:
            return path
        atomic_write_json(path, record.to_dict())
        return path


def _normalize_cve_id(value: str) -> str:
    text = (value or "").strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d+", text):
        return ""
    return text
