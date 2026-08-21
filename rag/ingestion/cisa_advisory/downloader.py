from __future__ import annotations

import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from rag.ingestion.cisa_advisory.parser import parse_cisa_advisory_html
from rag.ingestion.cisa_advisory.store import AdvisoryDetailStore

CISA_ADVISORY_URL = "https://www.cisa.gov/news-events/ics-advisories/{advisory_lower}"


@dataclass(slots=True)
class DownloadResult:
    advisory_id: str
    path: Path | None
    status: str
    message: str = ""
    url: str | None = None


class CisaAdvisoryDownloader:
    """Ingest-time HTML downloader. Never call from scenario runtime."""

    def __init__(
        self,
        cache_dir: str | Path,
        timeout_seconds: float = 30.0,
        max_retries: int = 3,
        backoff_seconds: float = 1.0,
        opener=None,
        logger: logging.Logger | None = None,
    ):
        self.store = AdvisoryDetailStore(cache_dir)
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.opener = opener or urllib.request.urlopen
        self.logger = logger or logging.getLogger(__name__)

    def download(self, advisory_id: str, refresh: bool = False) -> DownloadResult:
        normalized = advisory_id.strip().upper()
        path = self.store.path_for(normalized)
        if path.exists() and not refresh:
            return DownloadResult(
                advisory_id=normalized,
                path=path,
                status="cached",
                message="Using cached advisory detail",
            )
        url = CISA_ADVISORY_URL.format(advisory_lower=normalized.lower())
        last_error = ""
        for attempt in range(1, self.max_retries + 1):
            try:
                request = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "ThreatScenarioGenerator-CISA-Advisory-Ingest/0.1",
                        "Accept": "text/html",
                    },
                )
                with self.opener(request, timeout=self.timeout_seconds) as response:
                    status_code = getattr(response, "status", None) or response.getcode()
                    if status_code != 200:
                        last_error = f"HTTP {status_code} for {url}"
                        break
                    payload = response.read()
                if not payload:
                    last_error = f"Empty response for {url}"
                    break
                html = payload.decode("utf-8", errors="replace")
                record = parse_cisa_advisory_html(html, advisory_id=normalized, source_url=url)
                if not record.advisory_id:
                    record.advisory_id = normalized
                written = self.store.write(record, refresh=True)
                return DownloadResult(
                    advisory_id=normalized,
                    path=written,
                    status="downloaded",
                    message="Downloaded CISA advisory HTML and normalized it",
                    url=url,
                )
            except (urllib.error.URLError, TimeoutError, OSError, UnicodeError) as exc:
                last_error = str(exc)
                if attempt < self.max_retries:
                    time.sleep(self.backoff_seconds * attempt)
        return DownloadResult(
            advisory_id=normalized,
            path=None,
            status="unavailable",
            message=last_error or "CISA advisory download failed",
            url=url,
        )
