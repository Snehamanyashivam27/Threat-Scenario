from __future__ import annotations

import json
import os
from pathlib import Path

from rag.ingestion.atomic import atomic_write_json
from rag.ingestion.cisa_advisory.parser import AdvisoryDetail

ADVISORY_ID_SUFFIX = ".json"


def default_advisory_store_dir() -> Path:
    env = (os.environ.get("RAG_CISA_ADVISORY_DIR") or "").strip()
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[3] / "data" / "cisa_advisory"


class AdvisoryDetailStore:
    """Exact advisory-ID lookup for normalized CISA full-advisory records."""

    def __init__(self, store_dir: str | Path | None = None):
        self.store_dir = Path(store_dir) if store_dir is not None else default_advisory_store_dir()

    def path_for(self, advisory_id: str) -> Path:
        return self.store_dir / f"{advisory_id.strip().upper()}.json"

    def lookup(self, advisory_id: str) -> AdvisoryDetail | None:
        path = self.path_for(advisory_id)
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return None
        if not isinstance(data, dict):
            return None
        record = AdvisoryDetail.from_dict(data)
        if record.advisory_id.upper() != advisory_id.strip().upper():
            return None
        return record

    def all_records(self) -> list[AdvisoryDetail]:
        if not self.store_dir.exists():
            return []
        records: list[AdvisoryDetail] = []
        for path in sorted(self.store_dir.glob("*.json")):
            record = self.lookup(path.stem)
            if record is not None:
                records.append(record)
        return records

    def write(self, record: AdvisoryDetail, *, refresh: bool = False) -> Path:
        self.store_dir.mkdir(parents=True, exist_ok=True)
        path = self.path_for(record.advisory_id)
        if path.exists() and not refresh:
            return path
        atomic_write_json(path, record.to_dict())
        return path
