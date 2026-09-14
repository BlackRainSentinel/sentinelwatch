"""
Optional long-polling Telegram command bot.

Commands:
  /watch <product_id>   — clear mute for a product
  /mute <product_id>    — mute product alerts (digest only)
  /mute wordpress       — mute WP plugin channel noise
  /why <CVE-...>        — show stored finding summary
  /status               — heartbeat + collector health snapshot

Run: python -m sentinelwatch.bot
Enable via systemd sentinelwatch-bot.service
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from sentinelwatch.config import load_config, load_env
from sentinelwatch.db import Database

log = logging.getLogger(__name__)


def _api(token: str, method: str, **params):
    url = f"https://api.telegram.org/bot{token}/{method}"
    with httpx.Client(timeout=60.0) as client:
        resp = client.post(url, json=params)
        resp.raise_for_status()
        return resp.json()


def _reply(token: str, chat_id: str, text: str) -> None:
    _api(token, "sendMessage", chat_id=chat_id, text=text, parse_mode="HTML")


def handle(db: Database, token: str, chat_id: str, text: str) -> None:
    parts = (text or "").strip().split()
    if not parts:
        return
    cmd = parts[0].split("@")[0].lower()
    arg = " ".join(parts[1:]).strip()

    if cmd == "/status":
        age = db.last_heartbeat_age_hours()
        age_s = f"{age:.1f}h ago" if age is not None else "never"
        with db.connection() as conn:
            rows = conn.execute(
                "SELECT source, last_status, consecutive_fails, consecutive_empty, "
                "last_item_count FROM collector_health ORDER BY source"
            ).fetchall()
        lines = [f"<b>Status</b>\nheartbeat: {age_s}\n"]
        for r in rows[:30]:
            lines.append(
                f"• {r['source']}: {r['last_status']} "
                f"fail={r['consecutive_fails']} empty={r['consecutive_empty']} "
                f"last_n={r['last_item_count']}"
            )
        _reply(token, chat_id, "\n".join(lines)[:3900])
        return

    if cmd == "/mute" and arg:
        until = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        db.set_mute(arg, until, reason="telegram /mute")
        _reply(token, chat_id, f"Muted <code>{arg}</code> for 30 days.")
        return

    if cmd == "/watch" and arg:
        db.clear_mute(arg)
        _reply(token, chat_id, f"Watching <code>{arg}</code> again.")
        return

    if cmd == "/why" and arg:
        cve = arg.upper()
        with db.connection() as conn:
            row = conn.execute(
                "SELECT title, source, alert_score, matched_products, impact_note, "
                "url, in_kev, channel FROM vulnerabilities "
                "WHERE cve_ids LIKE ? ORDER BY first_seen_at DESC LIMIT 1",
                (f"%{cve}%",),
            ).fetchone()
        if not row:
            _reply(token, chat_id, f"No stored finding for {cve}")
            return
        _reply(
            token,
            chat_id,
            (
                f"<b>{cve}</b>\n{row['title']}\n"
                f"source={row['source']} score={row['alert_score']} "
                f"kev={row['in_kev']} channel={row['channel']}\n"
                f"matched={row['matched_products']}\n"
                f"{row['impact_note']}\n{row['url']}"
            )[:3900],
        )
        return

    if cmd == "/help":
        _reply(
            token,
            chat_id,
            "/status\n/mute &lt;product_id|wordpress&gt;\n"
            "/watch &lt;product_id&gt;\n/why CVE-YYYY-NNNN",
        )


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    load_env()
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    allowed = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not token or not allowed:
        log.error("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID required")
        return 2

    cfg = load_config()
    root = Path(__file__).resolve().parent.parent
    db_path = Path(cfg.get("database", {}).get("path", "data/sentinelwatch.db"))
    if not db_path.is_absolute():
        db_path = root / db_path
    db = Database(db_path)

    offset = 0
    log.info("Bot started")
    while True:
        try:
            data = _api(
                token,
                "getUpdates",
                offset=offset,
                timeout=30,
                allowed_updates=["message"],
            )
            for upd in data.get("result") or []:
                offset = max(offset, int(upd["update_id"]) + 1)
                msg = upd.get("message") or {}
                chat = msg.get("chat") or {}
                chat_id = str(chat.get("id", ""))
                if chat_id != allowed and chat_id != os.environ.get(
                    "TELEGRAM_CHAT_ID_CRITICAL", ""
                ):
                    continue
                text = msg.get("text") or ""
                if text.startswith("/"):
                    handle(db, token, chat_id, text)
        except KeyboardInterrupt:
            return 0
        except Exception:
            log.exception("bot loop error")
            time.sleep(5)


if __name__ == "__main__":
    raise SystemExit(main())
