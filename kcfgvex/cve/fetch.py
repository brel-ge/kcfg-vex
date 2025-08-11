# kcfgvex/cve/fetch.py
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    MofNCompleteColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    TextColumn,
)


CVEORG_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"  # CVE Services 2.x/5.x style


def _http_get_json(url: str, retries: int = 2, timeout: int = 20) -> dict:
    """Tiny JSON GET with basic retry + 429 handling."""
    headers = {"Accept": "application/json"}
    attempt = 0
    while True:
        attempt += 1
        try:
            with urlopen(
                Request(url, headers=headers, method="GET"), timeout=timeout
            ) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except HTTPError as e:
            # Respect rate limiting
            if e.code == 429 and attempt <= retries:
                wait = int(e.headers.get("Retry-After") or (2**attempt))
                time.sleep(wait)
                continue
            try:
                body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            raise RuntimeError(f"HTTP {e.code} from {url}\n{body}")
        except URLError as e:
            if attempt <= retries:
                time.sleep(2**attempt)
                continue
            raise RuntimeError(f"Network error fetching {url}: {e}")


def fetch_cve_cveorg(cve_id: str) -> dict:
    """Fetch a single CVE JSON from CVE.org."""
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        raise ValueError(f"Not a CVE ID: {cve_id}")
    return _http_get_json(CVEORG_URL.format(cve_id=cve_id))


def fetch_many_cveorg(
    cve_ids: Sequence[str],
    show_progress: bool = True,
    cache_dir: Path | None = None,
    force: bool = False,
) -> dict[str, dict | Exception]:
    """Fetch multiple CVEs with optional on-disk caching and Rich progress.

    Returns mapping {cve_id: json_or_exception}. Individual failures are stored
    as Exception objects; the function itself never raises (unless programmer
    error). If a cache directory is provided, existing JSON files named
    ``<CVE-ID>.json`` are loaded and *not* refetched unless ``force`` is True or
    the cached file is unreadable / mismatched.
    """
    out: dict[str, dict | Exception] = {}
    ids = [c.strip().upper() for c in cve_ids if c]
    if not ids:
        return out

    cache_dir_path = Path(cache_dir) if cache_dir else None
    if cache_dir_path:
        cache_dir_path.mkdir(parents=True, exist_ok=True)

    # Helper to attempt loading from cache
    def _load_cached(cid: str) -> dict | None:
        if not cache_dir_path:
            return None
        p = cache_dir_path / f"{cid}.json"
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text())
        except Exception:
            return None
        # Basic sanity check
        meta = (data.get("cveMetadata") or {}) if isinstance(data, dict) else {}
        if meta.get("cveId") and meta.get("cveId") != cid:
            return None
        return data if not force else None

    # Decide which need fetching
    to_fetch: list[str] = []
    for cid in ids:
        cached = _load_cached(cid)
        if cached is not None:
            out[cid] = cached
        else:
            to_fetch.append(cid)

    # If nothing to fetch we can return early
    if not to_fetch:
        return out

    # Simple path (no progress)
    if not show_progress or len(to_fetch) == 1:
        for cid in to_fetch:
            try:
                data = fetch_cve_cveorg(cid)
                out[cid] = data
                if cache_dir_path:
                    save_cve_json(data, cache_dir_path / f"{cid}.json")
            except Exception as e:  # pragma: no cover - network variability
                out[cid] = e
        return out

    total = len(to_fetch)
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=None),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        transient=True,
    ) as prog:
        task = prog.add_task("Fetching CVEs", total=total)
        for cid in to_fetch:
            prog.update(task, description=f"{cid}")
            try:
                data = fetch_cve_cveorg(cid)
                out[cid] = data
                if cache_dir_path:
                    save_cve_json(data, cache_dir_path / f"{cid}.json")
            except Exception as e:  # pragma: no cover - variability
                out[cid] = e
            prog.advance(task)
    return out


def save_cve_json(cve_obj: dict, dest: Path) -> Path:
    """Save a CVE JSON object to dest (creates parents). Returns dest."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(cve_obj, indent=2, ensure_ascii=False))
    return dest
