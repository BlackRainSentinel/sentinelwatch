#!/usr/bin/env bash
# Publish Threat Core emblems (v3.7.0) + optional Telegram sample.
# Needs one sudo for .git ownership (currently owned by root).
set -euo pipefail

REPO="${REPO:-/home/unitedgamer95/Git/sentinelwatch}"
SHIP="${SHIP:-/tmp/sentinelwatch-ship}"
OPT="${OPT:-/opt/sentinelwatch}"

OWNER="${OWNER:-unitedgamer95}"
echo "==> Fix .git ownership → $OWNER (not root)"
sudo chown -R "$OWNER:$OWNER" "$REPO/.git"

echo "==> Fast-forward main with Threat Core commit from $SHIP"
cd "$REPO"
sudo -u "$OWNER" bash -lc "cd \"$REPO\" && git -c safe.directory=\"$REPO\" reset --hard HEAD && rm -f docs/preview-severity-critical.gif scripts/install_threat_core_gifs.py"
sudo -u "$OWNER" bash -lc "cd \"$REPO\" && git -c safe.directory=\"$REPO\" fetch \"$SHIP\" main && git -c safe.directory=\"$REPO\" merge --ff-only FETCH_HEAD"
git -c safe.directory="$REPO" log -1 --oneline
git -c safe.directory="$REPO" log -1 --oneline

echo "==> Push to GitHub"
git -c safe.directory="$REPO" push origin main

if [[ -d "$OPT/.git" ]]; then
  echo "==> Deploy $OPT"
  sudo -u sentinelwatch bash -lc "cd '$OPT' && git pull origin main && .venv/bin/pip install -e ."
  ENV_FILE="$OPT/.env"
  PY="$OPT/.venv/bin/python"
  WORK="$OPT"
elif [[ -f "$REPO/.env" ]]; then
  echo "==> Using local $REPO/.env"
  ENV_FILE="$REPO/.env"
  PY="$REPO/.venv/bin/python"
  WORK="$REPO"
else
  echo "No /opt install and no local .env — push done. Create .env to send Telegram sample."
  exit 0
fi

echo "==> Telegram sample (critical Threat Core GIF)"
sudo -u "$( [[ -d $OPT/.git ]] && echo sentinelwatch || whoami )" bash -lc "
  cd '$WORK'
  set -a; source '$ENV_FILE'; set +a
  '$PY' - <<'PY'
from datetime import datetime, timezone
from sentinelwatch.models import Vulnerability
from sentinelwatch.notifier import TelegramNotifier

v = Vulnerability(
    external_id='CVE-2024-4577',
    source='cisa_kev',
    title='PHP CGI Argument Injection — remote code execution on shared hosts',
    description='Threat Core emblem sample (critical).',
    cvss_score=9.8,
    reported_severity='CRITICAL',
    affected_products=['php:php'],
    cve_ids=['CVE-2024-4577'],
    published_date=datetime(2024, 6, 12, tzinfo=timezone.utc),
    url='https://nvd.nist.gov/vuln/detail/CVE-2024-4577',
    source_tier=1,
    category='php',
    severity_tier='critical',
    product_match=True,
    matched_products=['php:php'],
    version_applicable=True,
    in_kev=True,
    always_alert=True,
    alert_score=96,
    blast_radius='critical',
    impact_note='PHP-FPM pools serve many tenants. Map ea-php*/alt-php* before dismissing.',
    channel='critical',
    thread_key='CVE-2024-4577',
)
print('telegram:', 'OK' if TelegramNotifier().send_alert(v) else 'FAILED')
PY
"

echo "Done."
