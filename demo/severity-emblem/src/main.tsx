import React, { useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { SeverityEmblem } from "./SeverityEmblem";
import { STATE_META, type SeverityState } from "./severityMap";
import "./styles.css";

const PRESETS: { label: string; score: number | null; state: SeverityState }[] = [
  { label: "None 0.0", score: 0.0, state: "none" },
  { label: "Low 2.1", score: 2.1, state: "low" },
  { label: "Medium 5.5", score: 5.5, state: "medium" },
  { label: "High 8.2", score: 8.2, state: "high" },
  { label: "Critical 9.8", score: 9.8, state: "critical" },
  { label: "Unknown", score: null, state: "unknown" },
];

function App() {
  const [score, setScore] = useState<number | null>(9.8);
  const [cveId, setCveId] = useState("CVE-2024-4577");
  const [source, setSource] = useState("nvd");
  const [version, setVersion] = useState("CVSS:3.1");

  const multi = useMemo(
    () => [
      { score: 7.5, source: "vendor", version: "CVSS:3.1" },
      { score: 9.8, source: "nvd", version: "CVSS:3.1" },
    ],
    []
  );

  return (
    <div className="page">
      <header>
        <h1>sentinelwatch</h1>
        <p className="lede">
          Severity emblem demo — animation selected from CVSS band (FIRST v3.1/v4.0).
          GIFs are prerecorded; controls only pick the asset.
        </p>
      </header>

      <main className="layout">
        <SeverityEmblem
          projectName="sentinelwatch"
          cveId={cveId}
          cvssScore={score}
          scoreVersion={version}
          scoreSource={source}
          assetBase="/severity"
          demoCycle
        />

        <aside className="panel" aria-label="Severity controls">
          <h2>Severity controls</h2>
          <p className="note">Production uses live data. This panel is demo-only.</p>
          <div className="presets" role="group" aria-label="CVSS presets">
            {PRESETS.map((p) => (
              <button
                key={p.label}
                type="button"
                className={score === p.score || (p.score === null && score === null) ? "active" : ""}
                onClick={() => setScore(p.score)}
                style={{ borderColor: STATE_META[p.state].color }}
              >
                {p.label}
              </button>
            ))}
          </div>

          <label>
            CVE ID
            <input value={cveId} onChange={(e) => setCveId(e.target.value)} />
          </label>
          <label>
            CVSS score
            <input
              type="number"
              step="0.1"
              min={0}
              max={10}
              value={score ?? ""}
              placeholder="empty = unknown"
              onChange={(e) => {
                const v = e.target.value;
                setScore(v === "" ? null : Number(v));
              }}
            />
          </label>
          <label>
            Score version
            <input value={version} onChange={(e) => setVersion(e.target.value)} />
          </label>
          <label>
            Score source
            <input value={source} onChange={(e) => setSource(e.target.value)} />
          </label>

          <h3>Multi-assessment policy</h3>
          <p className="note">
            Prefer NVD/official, then highest valid score. Example: vendor 7.5 + NVD 9.8 → Critical.
          </p>
          <SeverityEmblem
            projectName="sentinelwatch"
            cveId={cveId}
            assessments={multi}
            assetBase="/severity"
          />
        </aside>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
