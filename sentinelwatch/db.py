"""SQLite-backed store: dedup by source:external_id, digest bookkeeping."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from sentinelwatch.models import Vulnerability


SCHEMA = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key       TEXT    NOT NULL UNIQUE,
    source          TEXT    NOT NULL,
    external_id     TEXT    NOT NULL,
    title           TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    cvss_score      REAL,
    reported_severity TEXT,
    affected_products TEXT  NOT NULL DEFAULT '[]',
    published_date  TEXT,
    url             TEXT    NOT NULL DEFAULT '',
    references_json TEXT    NOT NULL DEFAULT '[]',
    category        TEXT    NOT NULL DEFAULT 'other',
    severity_tier   TEXT    NOT NULL DEFAULT 'unknown',
    fleet_match     INTEGER NOT NULL DEFAULT 0,
    first_seen_at   TEXT    NOT NULL,
    notified_telegram INTEGER NOT NULL DEFAULT 0,
    notified_email  INTEGER NOT NULL DEFAULT 0,
    in_digest       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS digests (
    digest_date TEXT PRIMARY KEY,
    sent_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity_tier);
CREATE INDEX IF NOT EXISTS idx_vuln_digest ON vulnerabilities(in_digest, first_seen_at);
"""


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self.connection() as conn:
            conn.executescript(SCHEMA)

    def is_seen(self, vuln: Vulnerability) -> bool:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM vulnerabilities WHERE dedup_key = ?",
                (vuln.dedup_key,),
            ).fetchone()
            return row is not None

    def insert_new(self, vuln: Vulnerability) -> bool:
        """
        Insert if unseen. Returns True when the row was newly stored.
        Only call after successful parse — never mark seen on fetch failure.
        """
        if self.is_seen(vuln):
            return False

        products = json.dumps(vuln.affected_products or [])
        refs = json.dumps(vuln.references or [])
        published = (
            vuln.published_date.isoformat() if vuln.published_date else None
        )

        with self.connection() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO vulnerabilities (
                        dedup_key, source, external_id, title, description,
                        cvss_score, reported_severity, affected_products,
                        published_date, url, references_json, category,
                        severity_tier, fleet_match, first_seen_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        vuln.dedup_key,
                        vuln.source,
                        vuln.external_id,
                        vuln.title,
                        vuln.description or "",
                        vuln.cvss_score,
                        vuln.reported_severity,
                        products,
                        published,
                        vuln.url or "",
                        refs,
                        vuln.category,
                        vuln.severity_tier,
                        1 if vuln.fleet_match else 0,
                        _utcnow_iso(),
                    ),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def mark_telegram_sent(self, dedup_key: str) -> None:
        with self.connection() as conn:
            conn.execute(
                "UPDATE vulnerabilities SET notified_telegram = 1 WHERE dedup_key = ?",
                (dedup_key,),
            )

    def mark_email_sent(self, dedup_key: str) -> None:
        with self.connection() as conn:
            conn.execute(
                "UPDATE vulnerabilities SET notified_email = 1 WHERE dedup_key = ?",
                (dedup_key,),
            )

    def mark_in_digest(self, dedup_keys: list[str]) -> None:
        if not dedup_keys:
            return
        with self.connection() as conn:
            conn.executemany(
                "UPDATE vulnerabilities SET in_digest = 1 WHERE dedup_key = ?",
                [(k,) for k in dedup_keys],
            )

    def digest_already_sent(self, day: date) -> bool:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM digests WHERE digest_date = ?",
                (day.isoformat(),),
            ).fetchone()
            return row is not None

    def record_digest_sent(self, day: date) -> None:
        with self.connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO digests (digest_date, sent_at) VALUES (?, ?)",
                (day.isoformat(), _utcnow_iso()),
            )

    def pending_digest_items(self) -> list[Vulnerability]:
        """Items not yet included in a digest (any severity)."""
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM vulnerabilities
                WHERE in_digest = 0
                ORDER BY
                    CASE severity_tier
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        WHEN 'low' THEN 3
                        ELSE 4
                    END,
                    first_seen_at
                """
            ).fetchall()
        return [self._row_to_vuln(r) for r in rows]

    @staticmethod
    def _row_to_vuln(row: sqlite3.Row) -> Vulnerability:
        published: Optional[datetime] = None
        if row["published_date"]:
            try:
                published = datetime.fromisoformat(row["published_date"])
            except ValueError:
                published = None
        return Vulnerability(
            external_id=row["external_id"],
            source=row["source"],
            title=row["title"],
            description=row["description"] or "",
            cvss_score=row["cvss_score"],
            reported_severity=row["reported_severity"],
            affected_products=json.loads(row["affected_products"] or "[]"),
            published_date=published,
            url=row["url"] or "",
            references=json.loads(row["references_json"] or "[]"),
            category=row["category"],
            severity_tier=row["severity_tier"],
            fleet_match=bool(row["fleet_match"]),
        )
