from __future__ import annotations

"""Exact canonical CVE-detail lookup against the local NVD store.

NVD is not part of hybrid retrieval. Runtime lookup is file-only.
"""

from rag.ingestion.csaf.models import CveDetailRecord
from rag.ingestion.nvd.store import NvdCveStore, default_nvd_store_dir


def lookup_nvd_cve_detail(
    cve_id: str,
    store_dir: str | None = None,
    store: NvdCveStore | None = None,
) -> CveDetailRecord | None:
    resolved = store or NvdCveStore(store_dir if store_dir is not None else default_nvd_store_dir())
    return resolved.lookup(cve_id)
