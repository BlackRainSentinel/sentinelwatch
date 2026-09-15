#!/usr/bin/env bash
# Finish Threat Core ship after the merge conflict.
# Run as root. Always chowns .git to unitedgamer95 (not root).
set -euo pipefail

REPO="${REPO:-/home/unitedgamer95/Git/sentinelwatch}"
SHIP="${SHIP:-/tmp/sentinelwatch-ship}"
OWNER="${OWNER:-unitedgamer95}"
OPT="${OPT:-/opt/sentinelwatch}"

echo "==> Own .git as $OWNER"
chown -R "$OWNER:$OWNER" "$REPO/.git"

echo "==> Reset duplicate working-tree files, then fast-forward to 3f95458"
sudo -u "$OWNER" bash <<EOF
set -euo pipefail
cd "$REPO"
git -c safe.directory="$REPO" reset --hard HEAD
rm -f docs/preview-severity-critical.gif scripts/install_threat_core_gifs.py
git -c safe.directory="$REPO" fetch "$SHIP" main
git -c safe.directory="$REPO" merge --ff-only FETCH_HEAD
git -c safe.directory="$REPO" log -1 --oneline
git -c safe.directory="$REPO" status -sb
EOF

echo "==> Push to GitHub"
sudo -u "$OWNER" bash <<EOF
set -euo pipefail
cd "$REPO"
git -c safe.directory="$REPO" remote set-url origin git@github.com:BlackRainSentinel/sentinelwatch.git
git -c safe.directory="$REPO" push origin main
EOF

if [[ -d "$OPT/.git" ]]; then
  echo "==> Deploy $OPT"
  sudo -u sentinelwatch bash -lc "cd '$OPT' && git pull origin main && .venv/bin/pip install -e ."
  echo "==> Telegram critical sample"
  sudo -u sentinelwatch bash <<'PYEOF'
set -euo pipefail
cd /opt/sentinelwatch
set -a; source .env; set +a
.venv/bin/python - <<'PY'
from datetime import datetime, timezone
from sentinelwatch.models import Vulnerability
from sentinelwatch.notifier import TelegramNotifier
v = Vulnerability(
    external_id="CVE-2024-4577",
    source="cisa_kev",
    title="PHP CGI Argument Injection — remote code execution on shared hosts",
    description="Threat Core emblem sample (critical).",
    cvss_score=9.8,
    reported_severity="CRITICAL",
    affected_products=["php:php"],
    cve_ids=["CVE-2024-4577"],
    published_date=datetime(2024, 6, 12, tzinfo=timezone.utc),
    url="https://nvd.nist.gov/vuln/detail/CVE-2024-4577",
    source_tier=1,
    category="php",
    severity_tier="critical",
    product_match=True,
    matched_products=["php:php"],
    version_applicable=True,
    in_kev=True,
    always_alert=True,
    alert_score=96,
    blast_radius="critical",
    impact_note="PHP-FPM pools serve many tenants. Map ea-php*/alt-php* before dismissing.",
    channel="critical",
    thread_key="CVE-2024-4577",
)
print("telegram:", "OK" if TelegramNotifier().send_alert(v) else "FAILED")
PY
PYEOF
else
  echo "==> /opt/sentinelwatch not found — code pushed only."
fi

echo "Done."
