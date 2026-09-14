"""Telegram + email delivery with visual report cards."""

from __future__ import annotations

import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Sequence

import httpx

from sentinelwatch.models import Vulnerability
from sentinelwatch.report_card import (
    blast_emoji,
    render_alert_card,
    render_digest_card,
    score_emoji,
    score_tier,
    severity_emoji,
)
from sentinelwatch.severity_emblem import resolve_assets

log = logging.getLogger(__name__)

_TIER_LABEL = {1: "T1 · official", 2: "T2 · research", 3: "T3 · aggregator"}


def _fmt_score(vuln: Vulnerability) -> str:
    if vuln.cvss_score is None:
        return "n/a"
    return f"{vuln.cvss_score:.1f}"


def _tier_label(vuln: Vulnerability) -> str:
    return _TIER_LABEL.get(int(vuln.source_tier or 3), f"T{vuln.source_tier}")


def _header_line(vuln: Vulnerability) -> str:
    """Score-driven lead emoji + status line (not one emoji for all)."""
    score = float(vuln.alert_score or 0)
    sev = severity_emoji(vuln.severity_tier)
    sig = score_emoji(score)
    blast = blast_emoji(vuln.blast_radius)
    tier = score_tier(score)

    if vuln.in_kev:
        return f"{sig}{sev} <b>CISA KEV — ACTIVELY EXPLOITED</b> · {tier.upper()}"
    if vuln.in_hosting_kev:
        return f"{sig}{blast} <b>HOSTING-KEV</b> · {tier.upper()}"
    if score >= 90:
        return f"{sig}{sev} <b>CATASTROPHIC HOSTING RISK</b>"
    if score >= 75:
        return f"{sig}{sev} <b>SEVERE — PRIORITIZE PATCH</b>"
    if score >= 55:
        return f"{sig}{sev} <b>ELEVATED — REVIEW TODAY</b>"
    if score >= 35:
        return f"{sig} <b>MODERATE — TRACK</b>"
    return f"{sig} <b>WATCHLIST</b>"


def format_alert_caption(vuln: Vulnerability) -> str:
    """Clear, structured caption — facts here; art is in the image."""
    score = float(vuln.alert_score or 0)
    sig = score_emoji(score)
    sev = severity_emoji(vuln.severity_tier)
    tier_name = score_tier(score).upper()

    headline, summary = (vuln.title or "").split(" — ", 1) if " — " in (vuln.title or "") else (
        vuln.title or "Untitled",
        "",
    )
    headline = headline.replace("PHP CGI", "PHP-CGI")

    # Status lead
    if vuln.in_kev:
        lead = f"{sig}{sev} <b>CISA KEV — actively exploited</b> · {tier_name}"
    elif vuln.in_hosting_kev:
        lead = f"{sig}{sev} <b>Hosting KEV</b> · {tier_name}"
    else:
        lead = f"{sig}{sev} <b>{(vuln.severity_tier or 'alert').upper()}</b> · {tier_name}"

    matched = ", ".join(f"<code>{p}</code>" for p in (vuln.matched_products or [])[:4]) or "—"
    cves = ", ".join(f"<code>{c}</code>" for c in (vuln.cve_ids or [])[:4]) or (
        f"<code>{vuln.external_id}</code>" if vuln.external_id else "—"
    )

    parts = [
        lead,
        "",
        f"<b>{headline}</b>",
    ]
    if summary:
        parts.append(summary.strip())
    elif vuln.title and " — " not in vuln.title:
        pass

    parts += [
        "",
        f"<b>Scores</b>",
        f"Sentinel <b>{score:.0f}</b>/100 · CVSS <b>{_fmt_score(vuln)}</b> · "
        f"blast <b>{vuln.blast_radius}</b> {blast_emoji(vuln.blast_radius)}",
        f"Source: {_tier_label(vuln)}",
        "",
        f"<b>Target</b>",
        f"Stack {matched}",
        f"ID {cves}",
    ]
    if not vuln.version_applicable:
        parts.append("Fleet: <i>not in your configured versions</i>")
    else:
        parts.append("Fleet: matches configured stack")

    impact = vuln.impact_note.strip() if vuln.impact_note else ""
    if impact:
        parts += ["", "<b>Why it matters</b>", impact[:320]]

    if vuln.url:
        parts += ["", f"Details: {vuln.url}"]

    text = "\n".join(parts)
    return text if len(text) <= 1024 else text[:990] + "\n…"


def format_alert(vuln: Vulnerability) -> str:
    """Full text fallback when image send is unavailable."""
    return format_alert_caption(vuln)


def format_digest(items: Sequence[Vulnerability], title: str = "daily digest") -> str:
    if not items:
        return f"<b>SENTINELWATCH</b> · {title}\nnothing new."

    lines = [
        f"<b>SENTINELWATCH</b> · {title.upper()}",
        f"{len(items)} findings · ranked by alert score",
        "┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄",
    ]
    for v in items[:40]:
        marks = []
        if v.in_kev:
            marks.append("KEV")
        if v.in_hosting_kev:
            marks.append("H-KEV")
        if not v.version_applicable:
            marks.append("n/a")
        tag = f" · {'/'.join(marks)}" if marks else ""
        em = score_emoji(float(v.alert_score or 0))
        lines.append(
            f"{em} <b>{v.alert_score:5.1f}</b>  "
            f"<code>{(v.severity_tier or '?')[:4].upper():4}</code>  "
            f"{v.title[:70]}{tag}"
        )
        if v.url:
            lines.append(f"   {v.url}")
    if len(items) > 40:
        lines.append(f"… +{len(items) - 40} more")
    return "\n".join(lines)


class TelegramNotifier:
    def __init__(
        self,
        bot_token: str | None = None,
        chat_id: str | None = None,
        *,
        critical_chat_id: str | None = None,
        wordpress_chat_id: str | None = None,
        timeout: float = 45.0,
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

    def send_photo(
        self,
        image: bytes,
        caption: str,
        *,
        channel: str = "critical",
        filename: str = "sentinelwatch.jpg",
    ) -> bool:
        """Inline chat photo — big on-screen preview (never a file attachment)."""
        if not self.enabled:
            return False
        chat_id = self._chat_for(channel)
        url = f"https://api.telegram.org/bot{self.bot_token}/sendPhoto"
        cap = caption if len(caption) <= 1024 else caption[:1000] + "\n…"
        mime = "image/jpeg" if filename.lower().endswith((".jpg", ".jpeg")) else "image/png"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(
                    url,
                    data={
                        "chat_id": chat_id,
                        "caption": cap,
                        "parse_mode": "HTML",
                    },
                    files={"photo": (filename, image, mime)},
                )
                resp.raise_for_status()
            return True
        except Exception:
            log.exception("Telegram photo send failed (channel=%s)", channel)
            return False

    def send_animation(
        self,
        gif: bytes,
        caption: str,
        *,
        channel: str = "critical",
        filename: str = "sentinelwatch-severity.gif",
    ) -> bool:
        """Inline animated GIF (Telegram sendAnimation)."""
        if not self.enabled:
            return False
        chat_id = self._chat_for(channel)
        url = f"https://api.telegram.org/bot{self.bot_token}/sendAnimation"
        cap = caption if len(caption) <= 1024 else caption[:1000] + "\n…"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(
                    url,
                    data={
                        "chat_id": chat_id,
                        "caption": cap,
                        "parse_mode": "HTML",
                    },
                    files={"animation": (filename, gif, "image/gif")},
                )
                resp.raise_for_status()
            return True
        except Exception:
            log.exception("Telegram animation send failed (channel=%s)", channel)
            return False

    def send_alert(self, vuln: Vulnerability) -> bool:
        channel = vuln.channel or "critical"
        caption = format_alert_caption(vuln)
        # Branded severity emblem GIF selected from CVSS (prerecorded asset)
        try:
            _state, gif_path, png_path = resolve_assets(vuln.cvss_score)
            if gif_path.is_file():
                if self.send_animation(gif_path.read_bytes(), caption, channel=channel):
                    return True
            if png_path.is_file() and self.send_photo(
                png_path.read_bytes(),
                caption,
                channel=channel,
                filename="sentinelwatch-severity.png",
            ):
                return True
        except Exception:
            log.exception("Severity emblem delivery failed; falling back")
        photo = render_alert_card(vuln)
        if photo and self.send_photo(photo, caption, channel=channel):
            return True
        return self.send(format_alert(vuln), channel=channel)

    def send_digest(
        self,
        items: Sequence[Vulnerability],
        *,
        channel: str = "digest",
        title: str = "daily digest",
    ) -> bool:
        text = format_digest(items, title=title)
        photo = render_digest_card(list(items), title=title)
        if photo and self.send_photo(photo, text[:900], channel=channel):
            if len(items) > 6:
                self.send(text, channel=channel)
            return True
        return self.send(text, channel=channel)

    def send_failure(self, source: str, error: str) -> bool:
        text = (
            f"⚠️ <b>SENTINELWATCH · COLLECTOR FAULT</b>\n"
            f"source <code>{source}</code>\n"
            f"<pre>{error[:1200]}</pre>\n"
            f"isolated · retry next schedule"
        )
        return self.send(text, channel="critical")

    def send_health(self, text: str) -> bool:
        return self.send(f"🫀 <b>SENTINELWATCH · HEALTH</b>\n{text}", channel="critical")


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
            f"Version applicable: {vuln.version_applicable}\n"
            f"URL: {vuln.url}\n\n"
            f"Impact: {vuln.impact_note or '—'}\n\n"
            f"{vuln.description}\n"
        )
        return self.send(subject, body)
