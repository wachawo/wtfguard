#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the sdist pre-fetcher."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from wtfguard.prefetch import PrefetchReport, format_text, run
from wtfguard.pypi import PackageRelease, ReleaseFile


def fake_release(name: str = "demo", version: str = "1.0.0") -> PackageRelease:
    return PackageRelease(
        name=name,
        version=version,
        files=[ReleaseFile(filename=f"{name}-{version}.tar.gz", url=f"http://x/{name}",
                           packagetype="sdist", sha256=None)],
        summary="",
        project_urls={},
    )


def test_run_skips_unpinned(tmp_path: Path) -> None:
    report = run([("foo", None)], dest=tmp_path)
    assert "foo==latest" in report.skipped
    assert report.succeeded == []


def test_run_downloads_pinned(tmp_path: Path) -> None:
    def fake_download(release_file, dest_dir):
        dest_dir.mkdir(parents=True, exist_ok=True)
        local = dest_dir / release_file.filename
        local.write_bytes(b"fake content")
        return local

    with patch("wtfguard.prefetch.pypi.fetch_release", return_value=fake_release()), \
         patch("wtfguard.prefetch.pypi.download_file", side_effect=fake_download):
        report = run([("demo", "1.0.0")], dest=tmp_path)
    assert "demo==1.0.0" in report.succeeded


def test_run_records_lookup_failures(tmp_path: Path) -> None:
    with patch("wtfguard.prefetch.pypi.fetch_release", side_effect=LookupError("not on PyPI")):
        report = run([("ghost", "9.9.9")], dest=tmp_path)
    assert report.failed
    assert report.failed[0][0] == "ghost==9.9.9"


def test_run_records_download_failures(tmp_path: Path) -> None:
    with patch("wtfguard.prefetch.pypi.fetch_release", return_value=fake_release()), \
         patch("wtfguard.prefetch.pypi.download_file", side_effect=OSError("disk full")):
        report = run([("demo", "1.0.0")], dest=tmp_path)
    assert report.failed


def test_run_no_sdist_no_wheel(tmp_path: Path) -> None:
    empty_release = PackageRelease(
        name="demo", version="1.0", files=[], summary="", project_urls={},
    )
    with patch("wtfguard.prefetch.pypi.fetch_release", return_value=empty_release):
        report = run([("demo", "1.0")], dest=tmp_path)
    assert report.failed
    assert "no sdist or wheel" in report.failed[0][1]


def test_report_total_counts() -> None:
    report = PrefetchReport(
        succeeded=["a==1.0", "b==2.0"],
        skipped=["c==latest"],
        failed=[("d==3.0", "reason")],
    )
    assert report.total == 4


def test_format_text_lists_failures(tmp_path: Path) -> None:
    report = PrefetchReport(failed=[("foo==1.0", "no sdist")])
    text = format_text(report)
    assert "failures" in text
    assert "foo==1.0" in text
