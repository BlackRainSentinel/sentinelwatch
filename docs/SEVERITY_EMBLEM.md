# Severity emblem design

## Research principles

| Reference | Takeaway |
|-----------|----------|
| [IBM Carbon status indicators](https://preview.carbondesignsystem.com/building-blocks/core/patterns/status-indicators) | Severity must use **shape + color + label**, not color alone. |
| [FIRST CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document) | Numeric bands: None 0.0, Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10.0. |
| [CSS gauge / conic ring patterns](https://dev.to/madsstoumann/how-to-create-gauges-in-css-3581) | Rings communicate intensity; motion should be purposeful, not decorative noise. |
| [W3C reduced motion](https://www.w3.org/WAI/WCAG22/Techniques/css/C39) | Prefer static PNG when `prefers-reduced-motion: reduce`. |
| [W3C pause/stop/hide](https://www.w3.org/WAI/WCAG22/Understanding/pause-stop-hide.html) | Continuous animation needs a pause control. |

## Concept — **SW Beacon**

Original emblem: monogram **SW** inside a core (circle → angular hex for Critical), surrounded by signal rings.

| State | Geometry | Motion | Accent |
|-------|----------|--------|--------|
| None | Single calm ring | Minimal drift | Teal |
| Low | One ring + orbital node | Slow orbit | Blue |
| Medium | Two rings | Expanding pulse | Amber |
| High | Two rings, counter-spin | Assertive orbit | Orange |
| Critical | Hex shield + three rings | Rhythmic pulse | Crimson |
| Unknown | Dashed ring | Near-static | Gray + UNRATED |

Watermark **`sentinelwatch`** is burned into every GIF frame and PNG.

## Export

```bash
python scripts/export_severity_emblems.py
# optional: --project-name sentinelwatch --out /path
```

Assets land in `sentinelwatch/assets/severity/{none,low,medium,high,critical,unknown}.{gif,png}`.

Canvas: **512×512**. Loop: **4.0s @ 20 fps** (80 frames).

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
