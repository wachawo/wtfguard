#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for PEP 740 attestation parsing."""

from __future__ import annotations

from wtfguard.pypi_signals import count_attestations, parse_metadata


def test_count_attestations_empty() -> None:
    assert count_attestations([]) == 0


def test_count_attestations_no_attestations_key() -> None:
    files = [{"filename": "x.whl"}, {"filename": "y.tar.gz"}]
    assert count_attestations(files) == 0


def test_count_attestations_empty_list_value() -> None:
    files = [{"filename": "x.whl", "attestations": []}]
    assert count_attestations(files) == 0


def test_count_attestations_one_signed() -> None:
    files = [
        {"filename": "x.whl", "attestations": [{"envelope": "..."}]},
        {"filename": "y.tar.gz"},
    ]
    assert count_attestations(files) == 1


def test_count_attestations_all_signed() -> None:
    files = [
        {"filename": "x.whl", "attestations": [{"envelope": "..."}]},
        {"filename": "y.tar.gz", "attestations": [{"envelope": "..."}]},
    ]
    assert count_attestations(files) == 2


def test_count_attestations_skips_malformed_entries() -> None:
    files = [None, "string", {"filename": "z.whl", "attestations": [{"x": 1}]}]
    assert count_attestations(files) == 1


def test_parse_metadata_extracts_attestations() -> None:
    raw = {
        "info": {"name": "demo", "version": "1.0", "summary": "x", "project_urls": {}},
        "releases": {
            "1.0": [
                {"upload_time_iso_8601": "2025-01-01T00:00:00Z",
                 "attestations": [{"envelope": "..."}]},
            ]
        },
    }
    meta = parse_metadata("demo", raw)
    assert meta.has_attestations is True
    assert meta.attestation_count == 1


def test_parse_metadata_no_attestations_flag_false() -> None:
    raw = {
        "info": {"name": "demo", "version": "1.0", "summary": "x", "project_urls": {}},
        "releases": {"1.0": [{"upload_time_iso_8601": "2025-01-01T00:00:00Z"}]},
    }
    meta = parse_metadata("demo", raw)
    assert meta.has_attestations is False
    assert meta.attestation_count == 0
