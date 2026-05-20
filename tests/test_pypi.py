#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the PyPI fetcher and extractor (no network)."""

import io
import json
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from wtfguard import pypi


def make_response(payload: object, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = payload
    resp.raise_for_status = MagicMock()
    if status >= 400:
        resp.raise_for_status.side_effect = Exception(f"HTTP {status}")
    return resp


def sample_pypi_payload(name: str = "demo", version: str = "1.0.0") -> dict[str, object]:
    return {
        "info": {"name": name, "version": version, "summary": "demo", "project_urls": {"Home": "https://example"}},
        "urls": [
            {
                "filename":    f"{name}-{version}.tar.gz",
                "url":         f"https://files.pythonhosted.example/{name}-{version}.tar.gz",
                "packagetype": "sdist",
                "digests":     {"sha256": "deadbeef"},
            },
            {
                "filename":    f"{name}-{version}-py3-none-any.whl",
                "url":         f"https://files.pythonhosted.example/{name}-{version}.whl",
                "packagetype": "bdist_wheel",
                "digests":     {"sha256": "cafebabe"},
            },
        ],
    }


def test_fetch_release_returns_parsed_metadata() -> None:
    with patch("wtfguard.pypi.requests.get", return_value=make_response(sample_pypi_payload())):
        release = pypi.fetch_release("demo", "1.0.0")
    assert release.name == "demo"
    assert release.version == "1.0.0"
    assert len(release.files) == 2
    assert release.pick_sdist() is not None
    assert release.pick_wheel() is not None
    assert release.pick_sdist().packagetype == "sdist"


def test_fetch_release_latest_uses_index_url() -> None:
    captured = {}

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        captured["url"] = url
        return make_response(sample_pypi_payload())

    with patch("wtfguard.pypi.requests.get", side_effect=fake_get):
        pypi.fetch_release("demo")
    assert captured["url"] == "https://pypi.org/pypi/demo/json"


def test_fetch_release_versioned_uses_version_url() -> None:
    captured = {}

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        captured["url"] = url
        return make_response(sample_pypi_payload())

    with patch("wtfguard.pypi.requests.get", side_effect=fake_get):
        pypi.fetch_release("demo", "1.0.0")
    assert captured["url"] == "https://pypi.org/pypi/demo/1.0.0/json"


def test_fetch_release_404_raises_lookup() -> None:
    resp = MagicMock()
    resp.status_code = 404
    with patch("wtfguard.pypi.requests.get", return_value=resp), pytest.raises(LookupError):
        pypi.fetch_release("does-not-exist")


def test_pick_sdist_returns_none_when_only_wheels() -> None:
    payload = sample_pypi_payload()
    payload["urls"] = [payload["urls"][1]]
    with patch("wtfguard.pypi.requests.get", return_value=make_response(payload)):
        release = pypi.fetch_release("demo")
    assert release.pick_sdist() is None
    assert release.pick_wheel() is not None


def test_is_safe_member_accepts_relative(tmp_path: Path) -> None:
    assert pypi.is_safe_member("pkg/setup.py", tmp_path) is True


def test_is_safe_member_rejects_traversal(tmp_path: Path) -> None:
    assert pypi.is_safe_member("../etc/passwd", tmp_path) is False
    assert pypi.is_safe_member("/etc/passwd", tmp_path) is False


def make_tar(tmp_path: Path, contents: dict[str, bytes]) -> Path:
    archive = tmp_path / "src.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name, body in contents.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(body)
            tar.addfile(info, fileobj=io.BytesIO(body))
    return archive


def test_extract_archive_tar(tmp_path: Path) -> None:
    archive = make_tar(tmp_path, {"pkg-1.0/setup.py": b"setup(name='pkg')\n", "pkg-1.0/README.md": b"hi"})
    out = pypi.extract_archive(archive, tmp_path / "out")
    assert (out / "setup.py").exists()
    assert (out / "README.md").read_bytes() == b"hi"


def test_extract_archive_zip(tmp_path: Path) -> None:
    archive = tmp_path / "src.whl"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg/__init__.py", "x = 1\n")
    out = pypi.extract_archive(archive, tmp_path / "out")
    assert (out / "pkg" / "__init__.py").read_text(encoding="utf-8") == "x = 1\n"


def test_extract_archive_unknown_format_raises(tmp_path: Path) -> None:
    archive = tmp_path / "src.bogus"
    archive.write_bytes(b"")
    with pytest.raises(ValueError):
        pypi.extract_archive(archive, tmp_path / "out")


def test_extract_tarbomb_paths_are_skipped(tmp_path: Path) -> None:
    # Build a tar that contains both a safe path and a path-traversal entry.
    extra = tmp_path / "bomb.tar.gz"
    with tarfile.open(extra, "w:gz") as tar:
        info = tarfile.TarInfo(name="../escape.py")
        info.size = 5
        tar.addfile(info, fileobj=io.BytesIO(b"evil\n"))
        info2 = tarfile.TarInfo(name="legit/file.py")
        info2.size = 3
        tar.addfile(info2, fileobj=io.BytesIO(b"ok\n"))
    out_dir = tmp_path / "out"
    pypi.extract_archive(extra, out_dir)
    # Escape path must not have been written outside out_dir
    assert not (tmp_path / "escape.py").exists()


def test_download_file_reuses_existing(tmp_path: Path) -> None:
    rf = pypi.ReleaseFile(filename="x.tar.gz", url="http://example", packagetype="sdist", sha256=None)
    dest_dir = tmp_path / "dl"
    dest_dir.mkdir()
    (dest_dir / "x.tar.gz").write_bytes(b"cached")
    with patch("wtfguard.pypi.requests.get") as mock_get:
        path = pypi.download_file(rf, dest_dir)
    assert path.read_bytes() == b"cached"
    mock_get.assert_not_called()


def test_download_file_streams_content(tmp_path: Path) -> None:
    rf = pypi.ReleaseFile(filename="x.tar.gz", url="http://example/x", packagetype="sdist", sha256=None)
    dest_dir = tmp_path / "dl"

    class FakeResponse:
        def __init__(self) -> None:
            self.status_code = 200

        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def raise_for_status(self) -> None:
            return None

        def iter_content(self, chunk_size: int) -> object:
            return iter([b"hello ", b"world"])

    with patch("wtfguard.pypi.requests.get", return_value=FakeResponse()):
        path = pypi.download_file(rf, dest_dir)
    assert path.read_bytes() == b"hello world"


def test_fetch_and_extract_end_to_end(tmp_path: Path) -> None:
    archive = make_tar(tmp_path, {"demo-1.0.0/setup.py": b"setup(name='demo')\n"})
    payload = sample_pypi_payload()
    payload["urls"][0]["url"] = f"file://{archive}"

    def fake_download(release_file: pypi.ReleaseFile, dest_dir: Path) -> Path:
        dest_dir.mkdir(parents=True, exist_ok=True)
        local = dest_dir / release_file.filename
        local.write_bytes(archive.read_bytes())
        return local

    with patch("wtfguard.pypi.requests.get", return_value=make_response(payload)), \
         patch("wtfguard.pypi.download_file", side_effect=fake_download):
        release, root = pypi.fetch_and_extract("demo", "1.0.0", workdir=tmp_path / "work")

    assert release.version == "1.0.0"
    assert (root / "setup.py").exists()


def test_fetch_and_extract_no_archive_raises(tmp_path: Path) -> None:
    payload = sample_pypi_payload()
    payload["urls"] = []
    with patch("wtfguard.pypi.requests.get", return_value=make_response(payload)), pytest.raises(LookupError):
        pypi.fetch_and_extract("demo", "1.0.0", workdir=tmp_path)


def test_release_serialization_round_trip() -> None:
    payload = sample_pypi_payload()
    serialized = json.dumps(payload)
    parsed = json.loads(serialized)
    assert parsed == payload
