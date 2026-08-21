from __future__ import annotations

import logging
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from rag.ingestion.nvd.parser import parse_nvd_cve_file

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"


@dataclass(slots=True)
class DownloadResult:
    cve_id: str
    path: Path | None
    status: str
    message: str = ""
    url: str | None = None


class NvdCveDownloader:
    """Explicit ingest-time downloader. Do not call from scenario runtime."""

    def __init__(
        self,
        cache_dir: str | Path,
        timeout_seconds: float = 30.0,
        max_retries: int = 3,
        backoff_seconds: float = 1.0,
        min_interval_seconds: float = 0.0,
        opener=None,
        logger: logging.Logger | None = None,
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.min_interval_seconds = max(0.0, float(min_interval_seconds))
        self.opener = opener or urllib.request.urlopen
        self.logger = logger or logging.getLogger(__name__)
        self._last_request_at = 0.0
        api_key = os.environ.get("NVD_API_KEY", "").strip()
        self._api_key = api_key or None

    def cache_path(self, cve_id: str) -> Path:
        return self.cache_dir / f"{cve_id.strip().upper()}.json"

    def download(self, cve_id: str, refresh: bool = False) -> DownloadResult:
        normalized = cve_id.strip().upper()
        path = self.cache_path(normalized)
        if path.exists() and not refresh:
            return DownloadResult(
                cve_id=normalized,
                path=path,
                status="cached",
                message="Using cached NVD CVE file",
            )
        url = NVD_CVE_URL.format(cve_id=normalized)
        last_error = ""
        for attempt in range(1, self.max_retries + 1):
            try:
                self._throttle()
                headers = {
                    "User-Agent": "ThreatScenarioGenerator-NVD-Ingest/0.1",
                    "Accept": "application/json",
                }
                if self._api_key:
                    headers["apiKey"] = self._api_key
                request = urllib.request.Request(url, headers=headers)
                with self.opener(request, timeout=self.timeout_seconds) as response:
                    status_code = getattr(response, "status", None) or response.getcode()
                    if status_code in {403, 429}:
                        last_error = f"HTTP {status_code} for {url}"
                        if attempt < self.max_retries:
                            time.sleep(max(self.backoff_seconds * attempt, 30.0))
                            continue
                        break
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
                    if parse_nvd_cve_file(tmp) is None:
                        tmp.unlink(missing_ok=True)
                        last_error = f"NVD JSON parse failed for {url}"
                        continue
                    os.replace(tmp, path)
                except Exception:
                    tmp.unlink(missing_ok=True)
                    raise
                return DownloadResult(
                    cve_id=normalized,
                    path=path,
                    status="downloaded",
                    message="Downloaded NVD CVE JSON",
                    url=url,
                )
            except urllib.error.HTTPError as exc:
                last_error = f"HTTP {exc.code} for {url}"
                if exc.code in {403, 429} and attempt < self.max_retries:
                    time.sleep(max(self.backoff_seconds * attempt, 30.0))
                    continue
                break
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = str(exc)
                if attempt < self.max_retries:
                    time.sleep(self.backoff_seconds * attempt)
        return DownloadResult(
            cve_id=normalized,
            path=None,
            status="unavailable",
            message=last_error or "NVD CVE download failed",
            url=url,
        )

    def _throttle(self) -> None:
        if self.min_interval_seconds <= 0:
            self._last_request_at = time.monotonic()
            return
        elapsed = time.monotonic() - self._last_request_at
        wait = self.min_interval_seconds - elapsed
        if wait > 0:
            time.sleep(wait)
        self._last_request_at = time.monotonic()
