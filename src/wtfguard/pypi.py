#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PyPI metadata fetcher and sdist downloader/extractor."""

import hashlib
import logging
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"
PYPI_JSON_VERSION_URL = "https://pypi.org/pypi/{name}/{version}/json"
USER_AGENT = "wtfguard/0.1 (+https://github.com/wachawo/wtfguard)"
DOWNLOAD_TIMEOUT = 30
DOWNLOAD_CHUNK = 64 * 1024
DEFAULT_RETRIES = 3
RETRY_BACKOFF_BASE = 0.5
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


@dataclass(frozen=True)
class ReleaseFile:
    filename: str
    url: str
    packagetype: str
    sha256: str | None


@dataclass(frozen=True)
class PackageRelease:
    name: str
    version: str
    files: list[ReleaseFile]
    summary: str | None
    project_urls: dict[str, str]

    def pick_sdist(self) -> ReleaseFile | None:
        for f in self.files:
            if f.packagetype == "sdist":
                return f
        return None

    def pick_wheel(self) -> ReleaseFile | None:
        for f in self.files:
            if f.packagetype == "bdist_wheel":
                return f
        return None


def request_with_retry(
    url: str,
    headers: dict[str, str] | None = None,
    stream: bool = False,
    retries: int = DEFAULT_RETRIES,
    timeout: int = DOWNLOAD_TIMEOUT,
) -> requests.Response:
    """GET with exponential backoff on retryable network/server errors.

    Retries on connection errors, timeouts, and 429/5xx status codes. 4xx
    other than 429 are raised immediately — they will not heal on retry.
    """
    last_exc: BaseException | None = None
    last_resp: requests.Response | None = None
    for attempt in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout, stream=stream)
            if resp.status_code not in RETRYABLE_STATUS:
                return resp
            logger.warning(f"PyPI returned {resp.status_code} for {url} (attempt {attempt + 1}/{retries})")
            if last_resp is not None:
                last_resp.close()
            last_resp = resp
        except (requests.ConnectionError, requests.Timeout) as exc:
            logger.warning(f"PyPI network error on {url} (attempt {attempt + 1}/{retries}): {type(exc).__name__}: {exc}")
            last_exc = exc
        if attempt < retries - 1:
            time.sleep(RETRY_BACKOFF_BASE * (2 ** attempt))
    if last_resp is not None:
        return last_resp
    assert last_exc is not None
    raise last_exc


def fetch_release(name: str, version: str | None = None) -> PackageRelease:
    """Fetch release metadata from PyPI JSON API. version=None returns latest."""
    url = (
        PYPI_JSON_URL.format(name=name)
        if version is None
        else PYPI_JSON_VERSION_URL.format(name=name, version=version)
    )
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    logger.info(f"Fetching PyPI metadata {name} {version or 'latest'}")
    resp = request_with_retry(url, headers=headers)
    if resp.status_code == 404:
        raise LookupError(f"Package {name}=={version or 'latest'} not found on PyPI")
    resp.raise_for_status()
    data = resp.json()

    info = data.get("info", {})
    urls = data.get("urls", [])
    files = [
        ReleaseFile(
            filename=u["filename"],
            url=u["url"],
            packagetype=u.get("packagetype", ""),
            sha256=(u.get("digests") or {}).get("sha256"),
        )
        for u in urls
    ]
    return PackageRelease(
        name=info.get("name", name),
        version=info.get("version", version or ""),
        files=files,
        summary=info.get("summary"),
        project_urls=info.get("project_urls") or {},
    )


def download_file(release_file: ReleaseFile, dest_dir: Path) -> Path:
    """Stream-download a release file into dest_dir, return local path."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / release_file.filename
    if dest.exists():
        logger.debug(f"Reusing cached download {dest}")
        return dest

    headers = {"User-Agent": USER_AGENT}
    logger.info(f"Downloading {release_file.url}")
    resp: Any = request_with_retry(release_file.url, headers=headers, stream=True)
    with resp:
        resp.raise_for_status()
        with dest.open("wb") as fh:
            for chunk in resp.iter_content(chunk_size=DOWNLOAD_CHUNK):
                if chunk:
                    fh.write(chunk)

    if release_file.sha256:
        verify_sha256(dest, release_file.sha256)
    return dest


def verify_sha256(path: Path, expected: str) -> None:
    """Raise IOError if the file's SHA256 differs from what PyPI advertised.

    PyPI publishes sha256 digests in its JSON metadata. Verifying the
    downloaded artifact against that digest catches MITM tampering and
    wrong-mirror configurations where the file body does not match the
    advertised hash. We do not delete the file — callers may want to
    inspect it.
    """
    digest = sha256_of(path)
    if digest.lower() != expected.lower():
        raise OSError(
            f"sha256 mismatch for {path.name}: expected {expected}, got {digest}"
        )
    logger.debug(f"sha256 verified for {path.name}")


def sha256_of(path: Path, chunk: int = 1 << 16) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            buf = fh.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def extract_archive(archive: Path, dest_dir: Path) -> Path:
    """Extract sdist (.tar.gz) or wheel (.whl) into dest_dir. Returns the root of unpacked contents."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = archive.name.lower()

    if name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar")):
        with tarfile.open(archive, "r:*") as tar:
            members = [m for m in tar.getmembers() if is_safe_member(m.name, dest_dir)]
            tar.extractall(dest_dir, members=members, filter="data")
        roots = sorted({Path(m.name).parts[0] for m in members if m.name})
        return dest_dir / roots[0] if roots else dest_dir

    if name.endswith(".whl") or name.endswith(".zip"):
        with zipfile.ZipFile(archive, "r") as zf:
            safe_names = [n for n in zf.namelist() if is_safe_member(n, dest_dir)]
            zf.extractall(dest_dir, members=safe_names)
        return dest_dir

    raise ValueError(f"Unsupported archive format: {archive.name}")


def is_safe_member(member_name: str, dest_dir: Path) -> bool:
    """Reject paths that escape dest_dir (tarbombs / zipslip)."""
    try:
        normalized = (dest_dir / member_name).resolve()
        normalized.relative_to(dest_dir.resolve())
        return True
    except (ValueError, OSError):
        return False


def fetch_and_extract(name: str, version: str | None = None, workdir: Path | None = None) -> tuple[PackageRelease, Path]:
    """Download sdist (or wheel fallback) and extract. Returns (release_meta, extracted_root)."""
    release = fetch_release(name, version)
    archive_source = release.pick_sdist() or release.pick_wheel()
    if archive_source is None:
        raise LookupError(f"No sdist or wheel for {name}=={release.version}")

    if workdir is None:
        workdir = Path(tempfile.mkdtemp(prefix="wtfguard-"))

    download_dir = workdir / "downloads"
    extract_dir = workdir / "extracted" / f"{release.name}-{release.version}"
    archive = download_file(archive_source, download_dir)
    root = extract_archive(archive, extract_dir)
    return release, root
