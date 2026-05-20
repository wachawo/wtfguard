#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Local SQLite cache for verdicts keyed by diff-hash."""

import json
import logging
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from wtfguard.models import Finding, Severity, Verdict

logger = logging.getLogger(__name__)

DEFAULT_CACHE_PATH = Path.home() / ".wtfguard" / "cache.sqlite"
DEFAULT_TTL = timedelta(days=30)

SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts (
    diff_hash       TEXT PRIMARY KEY,
    package         TEXT NOT NULL,
    version         TEXT NOT NULL,
    severity        INTEGER NOT NULL,
    confidence      REAL NOT NULL,
    findings_json   TEXT NOT NULL,
    llm_explanation TEXT,
    model           TEXT,
    scanned_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verdicts_package ON verdicts(package);
"""


class VerdictCache:
    """SQLite-backed cache. Connection is created lazily and closed by the caller."""

    def __init__(self, db_path: Path | None = None, ttl: timedelta = DEFAULT_TTL):
        self.db_path = db_path or DEFAULT_CACHE_PATH
        self.ttl = ttl
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.db_path)
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "VerdictCache":
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()

    def get(self, diff_hash: str) -> Verdict | None:
        cur = self.connection.execute(
            "SELECT package, version, severity, confidence, findings_json, "
            "llm_explanation, model, scanned_at FROM verdicts WHERE diff_hash = ?",
            (diff_hash,),
        )
        row = cur.fetchone()
        if row is None:
            return None

        scanned_at = datetime.fromisoformat(row[7])
        if datetime.now(UTC) - scanned_at > self.ttl:
            logger.debug(f"Cache expired for {diff_hash}")
            return None

        findings = [
            Finding(
                rule_id=f["rule_id"],
                severity=Severity.from_name(f["severity"]),
                file=f["file"],
                line=f["line"],
                snippet=f["snippet"],
                description=f["description"],
            )
            for f in json.loads(row[4])
        ]
        return Verdict(
            package=row[0],
            version=row[1],
            severity=Severity(row[2]),
            confidence=row[3],
            findings=findings,
            diff_hash=diff_hash,
            llm_explanation=row[5],
            model=row[6],
            scanned_at=scanned_at,
        )

    def put(self, verdict: Verdict) -> None:
        if verdict.diff_hash is None:
            logger.debug("Verdict has no diff_hash, skipping cache write")
            return
        findings_json = json.dumps([f.to_dict() for f in verdict.findings])
        self.connection.execute(
            "INSERT OR REPLACE INTO verdicts "
            "(diff_hash, package, version, severity, confidence, findings_json, "
            "llm_explanation, model, scanned_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                verdict.diff_hash,
                verdict.package,
                verdict.version,
                int(verdict.severity),
                verdict.confidence,
                findings_json,
                verdict.llm_explanation,
                verdict.model,
                verdict.scanned_at.isoformat(),
            ),
        )
        self.connection.commit()

    def purge_expired(self) -> int:
        cutoff = (datetime.now(UTC) - self.ttl).isoformat()
        cur = self.connection.execute("DELETE FROM verdicts WHERE scanned_at < ?", (cutoff,))
        self.connection.commit()
        return cur.rowcount
