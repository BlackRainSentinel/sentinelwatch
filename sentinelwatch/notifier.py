"""Telegram + email delivery. No business logic beyond formatting/sending."""

from __future__ import annotations

import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Sequence

import httpx

from sentinelwatch.models import Vulnerability

log = logging.getLogger(__name__)


def _fmt_score(vuln: Vulnerability) -> str:
    if vuln.cvss_score is None:
        return "n/a"
    return f"{vuln.cvss_score:.1f}"


def format_alert(vuln: Vulnerability) -> str:
    fleet = "yes" if vuln.fleet_match else "no"
    products = ", ".join(vuln.affected_products) if vuln.affected_products else "—"
    return (
        f"<b>[{vuln.severity_tier.upper()}]</b> {vuln.title}\n"
        f"source: <code>{vuln.source}</code> · category: {vuln.category}\n"
        f"CVSS: {_fmt_score(vuln)} · fleet: {fleet}\n"
        f"products: {products}\n"
        f"{vuln.url}"
    )


def format_digest(items: Sequence[Vulnerability]) -> str:
    if not items:
        return "SentinelWatch daily digest — nothing new."

    by_tier: dict[str, list[Vulnerability]] = {}
    for v in items:
        by_tier.setdefault(v.severity_tier, []).append(v)

    order = ("critical", "high", "medium", "low", "unknown")
    lines = [f"<b>SentinelWatch daily digest</b> — {len(items)} item(s)\n"]
    for tier in order:
        group = by_tier.get(tier)
        if not group:
            continue
        lines.append(f"\n<b>{tier.upper()}</b> ({len(group)})")
        for v in group[:40]:
            flag = " ⚓" if v.fleet_match else ""
            score = _fmt_score(v)
            lines.append(f"• [{score}] {v.title}{flag}\n  {v.url}")
        if len(group) > 40:
            lines.append(f"  …and {len(group) - 40} more")
    return "\n".join(lines)


class TelegramNotifier:
    def __init__(
        self,
        bot_token: str | None = None,
        chat_id: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.bot_token = (bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", "")).strip()
        self.chat_id = (chat_id or os.environ.get("TELEGRAM_CHAT_ID", "")).strip()
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def send(self, text: str) -> bool:
        if not self.enabled:
            log.warning("Telegram not configured; skipping send")
            return False
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        # Telegram hard limit ~4096; truncate safely
        payload_text = text if len(text) <= 4000 else text[:3900] + "\n…"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(
                    url,
                    json={
                        "chat_id": self.chat_id,
                        "text": payload_text,
                        "parse_mode": "HTML",
                        "disable_web_page_preview": True,
                    },
                )
                resp.raise_for_status()
            return True
        except Exception:
            log.exception("Telegram send failed")
            return False

    def send_alert(self, vuln: Vulnerability) -> bool:
        return self.send(format_alert(vuln))

    def send_digest(self, items: Sequence[Vulnerability]) -> bool:
        return self.send(format_digest(items))


class EmailNotifier:
    def __init__(self, timeout: float = 30.0) -> None:
        self.host = os.environ.get("SMTP_HOST", "").strip()
        self.port = int(os.environ.get("SMTP_PORT", "587") or 587)
        self.user = os.environ.get("SMTP_USER", "").strip()
        self.password = os.environ.get("SMTP_PASSWORD", "").strip()
        self.mail_from = os.environ.get("SMTP_FROM", "").strip()
        self.mail_to = os.environ.get("SMTP_TO", "").strip()
        self.use_tls = os.environ.get("SMTP_USE_TLS", "true").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self.host and self.mail_from and self.mail_to)

    def send(self, subject: str, body: str) -> bool:
        if not self.enabled:
            log.warning("SMTP not configured; skipping email")
            return False
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.mail_from
        msg["To"] = self.mail_to
        msg.set_content(body)
        try:
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as smtp:
                if self.use_tls:
                    smtp.starttls()
                if self.user:
                    smtp.login(self.user, self.password)
                smtp.send_message(msg)
            return True
        except Exception:
            log.exception("Email send failed")
            return False

    def send_alert(self, vuln: Vulnerability) -> bool:
        score = (
            f"{vuln.cvss_score:.1f}" if vuln.cvss_score is not None else "n/a"
        )
        subject = f"[SentinelWatch {vuln.severity_tier.upper()}] {vuln.title[:80]}"
        body = (
            f"Title: {vuln.title}\n"
            f"Source: {vuln.source}\n"
            f"External ID: {vuln.external_id}\n"
            f"Severity: {vuln.severity_tier} (CVSS {score})\n"
            f"Category: {vuln.category}\n"
            f"Fleet match: {vuln.fleet_match}\n"
            f"Products: {', '.join(vuln.affected_products) or '—'}\n"
            f"URL: {vuln.url}\n\n"
            f"{vuln.description}\n"
        )
        return self.send(subject, body)

