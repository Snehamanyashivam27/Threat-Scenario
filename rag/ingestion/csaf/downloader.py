from __future__ import annotations

import logging
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ADVISORY_ID_PATTERN = re.compile(r"^(?:ICSA|ICSMA|ICSALERT)-(\d{2})-\d{3}-\d{2}$", re.IGNORECASE)

DEFAULT_CSAF_BASE_URLS = (
    "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/{year}/{advisory_lower}.json",
    "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/{year}/{advisory_lower}.json",
)


@dataclass(slots=True)
class DownloadResult:
    advisory_id: str
    path: Path | None
    status: str
    message: str = ""
    url: str | None = None


class CsafDownloader:
    """Offline downloader for official CISA CSAF JSON advisories."""

    def __init__(
        self,
        cache_dir: str | Path,
        base_urls: tuple[str, ...] = DEFAULT_CSAF_BASE_URLS,
        timeout_seconds: float = 30.0,
        max_retries: int = 3,
        backoff_seconds: float = 1.0,
        opener=None,
        logger: logging.Logger | None = None,
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.base_urls = base_urls
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.opener = opener or urllib.request.urlopen
        self.logger = logger or logging.getLogger(__name__)

    def cache_path(self, advisory_id: str) -> Path:
        return self.cache_dir / f"{advisory_id.upper()}.json"

    def download(self, advisory_id: str, refresh: bool = False) -> DownloadResult:
        normalized = advisory_id.strip().upper()
        path = self.cache_path(normalized)
        if path.exists() and not refresh:
            return DownloadResult(advisory_id=normalized, path=path, status="cached", message="Using cached CSAF file")

        urls = self._candidate_urls(normalized)
        last_error = ""
        for url in urls:
            for attempt in range(1, self.max_retries + 1):
                try:
                    request = urllib.request.Request(
                        url,
                        headers={
                            "User-Agent": "ThreatScenarioGenerator-CSAF-Ingest/0.1",
                            "Accept": "application/json",
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
                    tmp = path.with_name(path.name + ".tmp")
                    try:
                        tmp.write_bytes(payload)
                        from rag.ingestion.csaf.parser import parse_csaf_file

                        parse_csaf_file(tmp)
                        os.replace(tmp, path)
                    except Exception as exc:  # noqa: BLE001 - do not keep invalid CSAF
                        tmp.unlink(missing_ok=True)
                        last_error = f"CSAF parse failed for {url}: {exc}"
                        continue
                    self.logger.info("Downloaded %s -> %s", normalized, path)
                    return DownloadResult(
                        advisory_id=normalized,
                        path=path,
                        status="downloaded",
                        message="Downloaded CSAF JSON",
                        url=url,
                    )
                except urllib.error.HTTPError as exc:
                    last_error = f"HTTP {exc.code} for {url}"
                    if exc.code == 404:
                        break
                    if attempt < self.max_retries:
                        time.sleep(self.backoff_seconds * attempt)
                except Exception as exc:  # noqa: BLE001 - keep ingestion resilient
                    last_error = f"{type(exc).__name__}: {exc}"
                    if attempt < self.max_retries:
                        time.sleep(self.backoff_seconds * attempt)

        self.logger.warning("CSAF unavailable for %s: %s", normalized, last_error)
        return DownloadResult(
            advisory_id=normalized,
            path=None,
            status="unavailable",
            message=last_error or "CSAF not available",
        )

    def download_many(self, advisory_ids: list[str], refresh: bool = False) -> list[DownloadResult]:
        results: list[DownloadResult] = []
        for advisory_id in advisory_ids:
            results.append(self.download(advisory_id, refresh=refresh))
        return results

    def _candidate_urls(self, advisory_id: str) -> list[str]:
        match = ADVISORY_ID_PATTERN.match(advisory_id)
        if not match:
            return []
        year = 2000 + int(match.group(1))
        advisory_lower = advisory_id.lower()
        return [
            template.format(year=year, advisory_lower=advisory_lower, advisory_id=advisory_id)
            for template in self.base_urls
        ]
