#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for sdist SHA256 verification."""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

from wtfguard import pypi


def test_sha256_of_known_bytes(tmp_path: Path) -> None:
    f = tmp_path / "x.bin"
    f.write_bytes(b"hello world")
    digest = hashlib.sha256(b"hello world").hexdigest()
    assert pypi.sha256_of(f) == digest


def test_verify_sha256_success(tmp_path: Path) -> None:
    f = tmp_path / "x.bin"
    f.write_bytes(b"contents")
    expected = hashlib.sha256(b"contents").hexdigest()
    pypi.verify_sha256(f, expected)  # must not raise


def test_verify_sha256_mismatch_raises(tmp_path: Path) -> None:
    f = tmp_path / "x.bin"
    f.write_bytes(b"contents")
    with pytest.raises(OSError, match="sha256 mismatch"):
        pypi.verify_sha256(f, "deadbeef" * 8)


def test_verify_sha256_case_insensitive(tmp_path: Path) -> None:
    f = tmp_path / "x.bin"
    f.write_bytes(b"contents")
    expected = hashlib.sha256(b"contents").hexdigest().upper()
    pypi.verify_sha256(f, expected)  # must not raise


def test_download_file_verifies_hash(tmp_path: Path) -> None:
    payload = b"correct payload bytes"
    expected_hash = hashlib.sha256(payload).hexdigest()
    rf = pypi.ReleaseFile(filename="x.tar.gz", url="http://example/x", packagetype="sdist", sha256=expected_hash)

    class FakeResponse:
        def __init__(self) -> None:
            self.status_code = 200

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def raise_for_status(self) -> None:
            return None

        def iter_content(self, chunk_size: int) -> object:
            return iter([payload])

    with patch("wtfguard.pypi.request_with_retry", return_value=FakeResponse()):
        path = pypi.download_file(rf, tmp_path / "dl")
    assert path.read_bytes() == payload


def test_download_file_rejects_bad_hash(tmp_path: Path) -> None:
    payload = b"actual content"
    bad_hash = "deadbeef" * 8
    rf = pypi.ReleaseFile(filename="x.tar.gz", url="http://example/x", packagetype="sdist", sha256=bad_hash)

    class FakeResponse:
        def __init__(self) -> None:
            self.status_code = 200

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def raise_for_status(self) -> None:
            return None

        def iter_content(self, chunk_size: int) -> object:
            return iter([payload])

    with patch("wtfguard.pypi.request_with_retry", return_value=FakeResponse()), \
         pytest.raises(OSError, match="sha256 mismatch"):
        pypi.download_file(rf, tmp_path / "dl")


def test_download_file_no_hash_skips_verify(tmp_path: Path) -> None:
    payload = b"unverified content"
    rf = pypi.ReleaseFile(filename="x.tar.gz", url="http://example/x", packagetype="sdist", sha256=None)

    class FakeResponse:
        def __init__(self) -> None:
            self.status_code = 200

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def raise_for_status(self) -> None:
            return None

        def iter_content(self, chunk_size: int) -> object:
            return iter([payload])

    with patch("wtfguard.pypi.request_with_retry", return_value=FakeResponse()):
        path = pypi.download_file(rf, tmp_path / "dl")
    assert path.read_bytes() == payload
