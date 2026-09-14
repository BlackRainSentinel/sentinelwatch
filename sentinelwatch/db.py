"""SQLite store: dedup, health, heartbeat, pre-CVE threads (v3)."""

from __future__ import annotations

import json
import shutil
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
    cve_ids         TEXT    NOT NULL DEFAULT '[]',
    affected_versions TEXT  NOT NULL DEFAULT '[]',
    published_date  TEXT,
    url             TEXT    NOT NULL DEFAULT '',
    references_json TEXT    NOT NULL DEFAULT '[]',
    source_tier     INTEGER NOT NULL DEFAULT 3,
    category        TEXT    NOT NULL DEFAULT 'other',
    severity_tier   TEXT    NOT NULL DEFAULT 'unknown',
    product_match   INTEGER NOT NULL DEFAULT 0,
    matched_products TEXT   NOT NULL DEFAULT '[]',
    in_kev          INTEGER NOT NULL DEFAULT 0,
    in_hosting_kev  INTEGER NOT NULL DEFAULT 0,
    always_alert    INTEGER NOT NULL DEFAULT 0,
    version_applicable INTEGER NOT NULL DEFAULT 1,
    version_unknown INTEGER NOT NULL DEFAULT 1,
    alert_score     REAL    NOT NULL DEFAULT 0,
    blast_radius    TEXT    NOT NULL DEFAULT 'normal',
    impact_note     TEXT    NOT NULL DEFAULT '',
    channel         TEXT    NOT NULL DEFAULT 'digest',
    thread_key      TEXT    NOT NULL DEFAULT '',
    first_seen_at   TEXT    NOT NULL,
    notified_telegram INTEGER NOT NULL DEFAULT 0,
    notified_email  INTEGER NOT NULL DEFAULT 0,
    in_digest       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS digests (
    digest_date TEXT PRIMARY KEY,
    sent_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS kev_cves (
    cve_id     TEXT PRIMARY KEY,
    product    TEXT NOT NULL DEFAULT '',
    vendor     TEXT NOT NULL DEFAULT '',
    date_added TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS collector_health (
    source           TEXT PRIMARY KEY,
    last_status      TEXT NOT NULL DEFAULT 'unknown',
    last_success_at  TEXT,
    last_error_at    TEXT,
    last_error       TEXT NOT NULL DEFAULT '',
    consecutive_fails INTEGER NOT NULL DEFAULT 0,
    consecutive_empty INTEGER NOT NULL DEFAULT 0,
    last_item_count  INTEGER NOT NULL DEFAULT 0,
    updated_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS heartbeats (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    last_run_at TEXT NOT NULL,
    stats_json  TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS alert_threads (
    thread_key   TEXT PRIMARY KEY,
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    cve_ids       TEXT NOT NULL DEFAULT '[]',
    title         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS mutes (
    key        TEXT PRIMARY KEY,
    muted_until TEXT,
    reason     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity_tier);
CREATE INDEX IF NOT EXISTS idx_vuln_digest ON vulnerabilities(in_digest, first_seen_at);
CREATE INDEX IF NOT EXISTS idx_vuln_channel ON vulnerabilities(channel);
CREATE INDEX IF NOT EXISTS idx_vuln_thread ON vulnerabilities(thread_key);
"""

_MIGRATE_COLUMNS: list[tuple[str, str]] = [
    ("cve_ids", "TEXT NOT NULL DEFAULT '[]'"),
    ("affected_versions", "TEXT NOT NULL DEFAULT '[]'"),
    ("source_tier", "INTEGER NOT NULL DEFAULT 3"),
    ("product_match", "INTEGER NOT NULL DEFAULT 0"),
    ("matched_products", "TEXT NOT NULL DEFAULT '[]'"),
    ("in_kev", "INTEGER NOT NULL DEFAULT 0"),
    ("in_hosting_kev", "INTEGER NOT NULL DEFAULT 0"),
    ("always_alert", "INTEGER NOT NULL DEFAULT 0"),
    ("version_applicable", "INTEGER NOT NULL DEFAULT 1"),
    ("version_unknown", "INTEGER NOT NULL DEFAULT 1"),
    ("alert_score", "REAL NOT NULL DEFAULT 0"),
    ("blast_radius", "TEXT NOT NULL DEFAULT 'normal'"),
    ("impact_note", "TEXT NOT NULL DEFAULT ''"),
    ("channel", "TEXT NOT NULL DEFAULT 'digest'"),
    ("thread_key", "TEXT NOT NULL DEFAULT ''"),
]


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
            existing = {
                row[1]
                for row in conn.execute("PRAGMA table_info(vulnerabilities)").fetchall()
            }
            for col, decl in _MIGRATE_COLUMNS:
                if col not in existing:
                    conn.execute(
                        f"ALTER TABLE vulnerabilities ADD COLUMN {col} {decl}"
                    )

    def backup(self) -> Path | None:
        """Copy DB beside itself with timestamp; returns path or None."""
        if not self.path.is_file():
            return None
        dest = self.path.with_suffix(
            self.path.suffix + f".bak-{datetime.now(timezone.utc).strftime('%Y%m%d')}"
        )
        try:
            shutil.copy2(self.path, dest)
            return dest
        except OSError:
            return None

    def is_seen(self, vuln: Vulnerability) -> bool:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM vulnerabilities WHERE dedup_key = ?",
                (vuln.dedup_key,),
            ).fetchone()
            return row is not None

    def insert_new(self, vuln: Vulnerability) -> bool:
        if self.is_seen(vuln):
            return False
        published = (
            vuln.published_date.isoformat() if vuln.published_date else None
        )
        with self.connection() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO vulnerabilities (
                        dedup_key, source, external_id, title, description,
                        cvss_score, reported_severity, affected_products, cve_ids,
                        affected_versions, published_date, url, references_json,
                        source_tier, category, severity_tier, product_match,
                        matched_products, in_kev, in_hosting_kev, always_alert,
                        version_applicable, version_unknown, alert_score,
                        blast_radius, impact_note, channel, thread_key, first_seen_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        vuln.dedup_key,
                        vuln.source,
                        vuln.external_id,
                        vuln.title,
                        vuln.description or "",
                        vuln.cvss_score,
                        vuln.reported_severity,
                        json.dumps(vuln.affected_products or []),
                        json.dumps(vuln.cve_ids or []),
                        json.dumps(vuln.affected_versions or []),
                        published,
                        vuln.url or "",
                        json.dumps(vuln.references or []),
                        int(vuln.source_tier or 3),
                        vuln.category,
                        vuln.severity_tier,
                        1 if vuln.product_match else 0,
                        json.dumps(vuln.matched_products or []),
                        1 if vuln.in_kev else 0,
                        1 if vuln.in_hosting_kev else 0,
                        1 if vuln.always_alert else 0,
                        1 if vuln.version_applicable else 0,
                        1 if vuln.version_unknown else 0,
                        float(vuln.alert_score or 0),
                        vuln.blast_radius or "normal",
                        vuln.impact_note or "",
                        vuln.channel or "digest",
                        vuln.thread_key or "",
                        _utcnow_iso(),
                    ),
                )
            except sqlite3.IntegrityError:
                return False
        self._upsert_thread(vuln)
        return True

    def _upsert_thread(self, vuln: Vulnerability) -> None:
        if not vuln.thread_key:
            return
        now = _utcnow_iso()
        with self.connection() as conn:
            row = conn.execute(
                "SELECT cve_ids FROM alert_threads WHERE thread_key = ?",
                (vuln.thread_key,),
            ).fetchone()
            if row:
                existing = set(json.loads(row["cve_ids"] or "[]"))
                existing.update(vuln.cve_ids or [])
                conn.execute(
                    """
                    UPDATE alert_threads
                    SET last_seen_at = ?, cve_ids = ?, title = COALESCE(NULLIF(title,''), ?)
                    WHERE thread_key = ?
                    """,
                    (now, json.dumps(sorted(existing)), vuln.title, vuln.thread_key),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO alert_threads (thread_key, first_seen_at, last_seen_at, cve_ids, title)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        vuln.thread_key,
                        now,
                        now,
                        json.dumps(vuln.cve_ids or []),
                        vuln.title,
                    ),
                )

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

    def pending_digest_items(self, channel: str | None = None) -> list[Vulnerability]:
        q = """
            SELECT * FROM vulnerabilities
            WHERE in_digest = 0
        """
        args: list = []
        if channel:
            q += " AND channel = ?"
            args.append(channel)
        q += """
            ORDER BY alert_score DESC,
                CASE WHEN in_kev = 1 THEN 0 ELSE 1 END,
                first_seen_at
        """
        with self.connection() as conn:
            rows = conn.execute(q, args).fetchall()
        return [self._row_to_vuln(r) for r in rows]

    def upsert_kev_cves(self, entries: list[dict[str, str]]) -> set[str]:
        now = _utcnow_iso()
        with self.connection() as conn:
            for e in entries:
                cve = (e.get("cve_id") or "").upper().strip()
                if not cve:
                    continue
                conn.execute(
                    """
                    INSERT INTO kev_cves (cve_id, product, vendor, date_added, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        product=excluded.product,
                        vendor=excluded.vendor,
                        date_added=excluded.date_added,
                        updated_at=excluded.updated_at
                    """,
                    (
                        cve,
                        e.get("product") or "",
                        e.get("vendor") or "",
                        e.get("date_added"),
                        now,
                    ),
                )
            rows = conn.execute("SELECT cve_id FROM kev_cves").fetchall()
        return {r["cve_id"] for r in rows}

    def load_kev_cves(self) -> set[str]:
        with self.connection() as conn:
            rows = conn.execute("SELECT cve_id FROM kev_cves").fetchall()
        return {r["cve_id"] for r in rows}

    def record_collector_success(self, source: str, item_count: int) -> dict:
        now = _utcnow_iso()
        empty = 1 if item_count == 0 else 0
        with self.connection() as conn:
            row = conn.execute(
                "SELECT consecutive_empty FROM collector_health WHERE source = ?",
                (source,),
            ).fetchone()
            prev_empty = int(row["consecutive_empty"]) if row else 0
            new_empty = prev_empty + 1 if empty else 0
            conn.execute(
                """
                INSERT INTO collector_health (
                    source, last_status, last_success_at, consecutive_fails,
                    consecutive_empty, last_item_count, updated_at, last_error
                ) VALUES (?, 'ok', ?, 0, ?, ?, ?, '')
                ON CONFLICT(source) DO UPDATE SET
                    last_status='ok',
                    last_success_at=excluded.last_success_at,
                    consecutive_fails=0,
                    consecutive_empty=excluded.consecutive_empty,
                    last_item_count=excluded.last_item_count,
                    updated_at=excluded.updated_at,
                    last_error=''
                """,
                (source, now, new_empty, item_count, now),
            )
        return {"consecutive_empty": new_empty, "item_count": item_count}

    def record_collector_failure(self, source: str, error: str) -> int:
        now = _utcnow_iso()
        with self.connection() as conn:
            row = conn.execute(
                "SELECT consecutive_fails FROM collector_health WHERE source = ?",
                (source,),
            ).fetchone()
            fails = (int(row["consecutive_fails"]) if row else 0) + 1
            conn.execute(
                """
                INSERT INTO collector_health (
                    source, last_status, last_error_at, last_error,
                    consecutive_fails, updated_at
                ) VALUES (?, 'error', ?, ?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET
                    last_status='error',
                    last_error_at=excluded.last_error_at,
                    last_error=excluded.last_error,
                    consecutive_fails=excluded.consecutive_fails,
                    updated_at=excluded.updated_at
                """,
                (source, now, (error or "")[:2000], fails, now),
            )
        return fails

    def heartbeat(self, stats: dict) -> None:
        now = _utcnow_iso()
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO heartbeats (id, last_run_at, stats_json)
                VALUES (1, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    last_run_at=excluded.last_run_at,
                    stats_json=excluded.stats_json
                """,
                (now, json.dumps(stats)),
            )

    def last_heartbeat_age_hours(self) -> float | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT last_run_at FROM heartbeats WHERE id = 1"
            ).fetchone()
        if not row:
            return None
        try:
            ts = datetime.fromisoformat(row["last_run_at"])
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - ts).total_seconds() / 3600.0
        except ValueError:
            return None

    def is_muted(self, key: str) -> bool:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT muted_until FROM mutes WHERE key = ?", (key,)
            ).fetchone()
        if not row:
            return False
        until = row["muted_until"]
        if not until:
            return True
        try:
            ts = datetime.fromisoformat(until)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) < ts
        except ValueError:
            return True

    def set_mute(self, key: str, muted_until: str | None, reason: str = "") -> None:
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO mutes (key, muted_until, reason) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET muted_until=excluded.muted_until, reason=excluded.reason
                """,
                (key, muted_until, reason),
            )

    def clear_mute(self, key: str) -> None:
        with self.connection() as conn:
            conn.execute("DELETE FROM mutes WHERE key = ?", (key,))

    @staticmethod
    def _row_to_vuln(row: sqlite3.Row) -> Vulnerability:
        published: Optional[datetime] = None
        if row["published_date"]:
            try:
                published = datetime.fromisoformat(row["published_date"])
            except ValueError:
                published = None
        keys = set(row.keys())

        def col(name: str, default=None):
            return row[name] if name in keys else default

        return Vulnerability(
            external_id=row["external_id"],
            source=row["source"],
            title=row["title"],
            description=row["description"] or "",
            cvss_score=row["cvss_score"],
            reported_severity=row["reported_severity"],
            affected_products=json.loads(col("affected_products") or "[]"),
            cve_ids=json.loads(col("cve_ids") or "[]"),
            affected_versions=json.loads(col("affected_versions") or "[]"),
            published_date=published,
            url=row["url"] or "",
            references=json.loads(col("references_json") or "[]"),
            source_tier=int(col("source_tier") or 3),
            category=col("category") or "other",
            severity_tier=col("severity_tier") or "unknown",
            product_match=bool(col("product_match") or 0),
            matched_products=json.loads(col("matched_products") or "[]"),
            in_kev=bool(col("in_kev") or 0),
            in_hosting_kev=bool(col("in_hosting_kev") or 0),
            always_alert=bool(col("always_alert") or 0),
            version_applicable=bool(col("version_applicable") if col("version_applicable") is not None else 1),
            version_unknown=bool(col("version_unknown") if col("version_unknown") is not None else 1),
            alert_score=float(col("alert_score") or 0),
            blast_radius=col("blast_radius") or "normal",
            impact_note=col("impact_note") or "",
            channel=col("channel") or "digest",
            thread_key=col("thread_key") or "",
        )
