# Severity emblem design

## Research principles

| Reference | Takeaway |
|-----------|----------|
| [IBM Carbon status indicators](https://preview.carbondesignsystem.com/building-blocks/core/patterns/status-indicators) | Severity must use **shape + color + label**, not color alone. |
| [FIRST CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document) | Numeric bands: None 0.0, Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10.0. |
| [W3C reduced motion](https://www.w3.org/WAI/WCAG22/Techniques/css/C39) | Prefer static PNG when `prefers-reduced-motion: reduce`. |

## Production assets — **Threat Core** pack

Shipped Telegram emblems are the high-quality **threat-core** GIFs (1080×1080):

| CVSS band | State | Asset |
|-----------|-------|-------|
| 0.0 | none | `none.gif` |
| 0.1–3.9 | low | `low.gif` |
| 4.0–6.9 | medium | `medium.gif` |
| 7.0–8.9 | high | `high.gif` |
| 9.0–10.0 | critical | `critical.gif` |
| missing / invalid | unknown | `unknown.gif` ← pack `unscored.gif` |

Install / refresh from the zip:

```bash
python scripts/install_threat_core_gifs.py ~/Downloads/threat-core-6-high-quality-gifs.zip
# then: cd demo/severity-emblem && npm run sync-assets
```

PNG fallbacks are the first frame of each GIF (reduced-motion / Telegram photo fallback).

## Procedural export (optional)

`python scripts/export_severity_emblems.py` regenerates the older H2 code-rain look.
**Do not run it** if you want to keep the threat-core pack — it overwrites the GIFs.

## Application selection

`cvss_to_state(score)` → filename. The GIF never fetches data.

Multi-assessment policy: prefer `nvd`/`official`/`first`/`cna`, then highest valid score (`select_assessment`).

## Demo (React + TypeScript)

```bash
cd demo/severity-emblem
npm run sync-assets
npm install
npm run dev
```

## Telegram

`TelegramNotifier.send_alert` sends the matching severity GIF via `sendAnimation`, then falls back to PNG / poster / text.
