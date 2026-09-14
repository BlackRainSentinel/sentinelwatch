"""Telegram + email delivery with channels, scoring, impact notes."""

from __future__ import annotations

import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Sequence

import httpx

from sentinelwatch.models import Vulnerability

log = logging.getLogger(__name__)

_TIER_LABEL = {1: "T1-official", 2: "T2-research", 3: "T3-aggregator"}


def _fmt_score(vuln: Vulnerability) -> str:
    if vuln.cvss_score is None:
        return "n/a"
    return f"{vuln.cvss_score:.1f}"


def _tier_label(vuln: Vulnerability) -> str:
    return _TIER_LABEL.get(int(vuln.source_tier or 3), f"T{vuln.source_tier}")


def format_alert(vuln: Vulnerability) -> str:
    flags = []
    if vuln.in_kev:
        flags.append("🚨 CISA KEV — ACTIVELY EXPLOITED")
    if vuln.in_hosting_kev:
        flags.append("🔥 HOSTING-KEV")
    if vuln.always_alert and not vuln.in_kev:
        flags.append("⚡ always-alert")
    if not vuln.version_applicable:
        flags.append("⏭ not in your fleet versions")
    head = ("\n".join(f"<b>{f}</b>" for f in flags) + "\n") if flags else ""

    matched = ", ".join(vuln.matched_products) if vuln.matched_products else "—"
    cves = ", ".join(vuln.cve_ids) if vuln.cve_ids else "—"
    impact = f"\n💡 {vuln.impact_note}" if vuln.impact_note else ""
    return (
        f"{head}"
        f"<b>[{vuln.severity_tier.upper()}]</b> score={vuln.alert_score:.0f} "
        f"blast={vuln.blast_radius}\n"
        f"{vuln.title}\n"
        f"source: <code>{vuln.source}</code> · {_tier_label(vuln)} · {vuln.category}\n"
        f"CVSS: {_fmt_score(vuln)} · applicable: "
        f"{'yes' if vuln.version_applicable else 'no'}"
        f"{' (ver unknown)' if vuln.version_unknown else ''}\n"
        f"matched: {matched}\n"
        f"CVE: {cves}\n"
        f"thread: <code>{vuln.thread_key}</code>\n"
        f"{vuln.url}"
        f"{impact}"
    )


def format_digest(items: Sequence[Vulnerability], title: str = "daily digest") -> str:
    if not items:
        return f"SentinelWatch {title} — nothing new."
    lines = [f"<b>SentinelWatch {title}</b> — {len(items)} item(s)\n"]
    for v in items[:50]:
        flags = []
        if v.in_kev:
            flags.append("KEV")
        if v.in_hosting_kev:
            flags.append("H-KEV")
        if not v.version_applicable:
            flags.append("n/a-ver")
        flag = f" [{','.join(flags)}]" if flags else ""
        lines.append(
            f"• [{v.alert_score:.0f}|{_fmt_score(v)}] {_tier_label(v)} "
            f"{v.title}{flag}\n  {v.url}"
        )
    if len(items) > 50:
        lines.append(f"  …and {len(items) - 50} more")
    return "\n".join(lines)


class TelegramNotifier:
    def __init__(
        self,
        bot_token: str | None = None,
        chat_id: str | None = None,
        *,
        critical_chat_id: str | None = None,
        wordpress_chat_id: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.bot_token = (bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", "")).strip()
        self.chat_id = (chat_id or os.environ.get("TELEGRAM_CHAT_ID", "")).strip()
        self.critical_chat_id = (
            critical_chat_id
            or os.environ.get("TELEGRAM_CHAT_ID_CRITICAL", "")
            or self.chat_id
        ).strip()
        self.wordpress_chat_id = (
            wordpress_chat_id
            or os.environ.get("TELEGRAM_CHAT_ID_WORDPRESS", "")
            or self.chat_id
        ).strip()
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def _chat_for(self, channel: str) -> str:
        if channel == "critical":
            return self.critical_chat_id or self.chat_id
        if channel == "wordpress":
            return self.wordpress_chat_id or self.chat_id
        return self.chat_id

    def send(self, text: str, *, channel: str = "digest") -> bool:
        if not self.enabled:
            log.warning("Telegram not configured; skipping send")
            return False
        chat_id = self._chat_for(channel)
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload_text = text if len(text) <= 4000 else text[:3900] + "\n…"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(
                    url,
                    json={
                        "chat_id": chat_id,
                        "text": payload_text,
                        "parse_mode": "HTML",
                        "disable_web_page_preview": True,
                    },
                )
                resp.raise_for_status()
            return True
        except Exception:
            log.exception("Telegram send failed (channel=%s)", channel)
            return False

    def send_alert(self, vuln: Vulnerability) -> bool:
        return self.send(format_alert(vuln), channel=vuln.channel or "critical")

    def send_digest(
        self, items: Sequence[Vulnerability], *, channel: str = "digest", title: str = "daily digest"
    ) -> bool:
        return self.send(format_digest(items, title=title), channel=channel)

    def send_failure(self, source: str, error: str) -> bool:
        text = (
            f"⚠️ <b>Collector failure</b>\n"
            f"source: <code>{source}</code>\n"
            f"<pre>{error[:1500]}</pre>\n"
            f"Will retry next run."
        )
        return self.send(text, channel="critical")

    def send_health(self, text: str) -> bool:
        return self.send(text, channel="critical")


class EmailNotifier:
    def __init__(self, timeout: float = 30.0) -> None:
        self.host = os.environ.get("SMTP_HOST", "").strip()
        self.port = int(os.environ.get("SMTP_PORT", "587") or 587)
        self.user = os.environ.get("SMTP_USER", "").strip()
        self.password = os.environ.get("SMTP_PASSWORD", "").strip()
        self.mail_from = os.environ.get("SMTP_FROM", "").strip()
        self.mail_to = os.environ.get("SMTP_TO", "").strip()
        self.use_tls = os.environ.get("SMTP_USE_TLS", "true").strip().lower() in {
            "1", "true", "yes", "on",
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
        score = f"{vuln.cvss_score:.1f}" if vuln.cvss_score is not None else "n/a"
        flags = []
        if vuln.in_kev:
            flags.append("CISA-KEV")
        if vuln.in_hosting_kev:
            flags.append("HOSTING-KEV")
        tag = f" [{','.join(flags)}]" if flags else ""
        subject = f"[SW {vuln.severity_tier.upper()}{tag}] {vuln.title[:80]}"
        body = (
            f"Title: {vuln.title}\n"
            f"Score: {vuln.alert_score} | blast: {vuln.blast_radius}\n"
            f"Source: {vuln.source} (tier {vuln.source_tier})\n"
            f"CVE(s): {', '.join(vuln.cve_ids) or '—'}\n"
            f"Severity: {vuln.severity_tier} (CVSS {score})\n"
            f"Matched: {', '.join(vuln.matched_products) or '—'}\n"
            f"Version applicable: {vuln.version_applicable} "
            f"(unknown={vuln.version_unknown})\n"
            f"Channel: {vuln.channel}\n"
            f"Thread: {vuln.thread_key}\n"
            f"URL: {vuln.url}\n\n"
            f"Impact: {vuln.impact_note or '—'}\n\n"
            f"{vuln.description}\n"
        )
        return self.send(subject, body)
