/**
 * SentinelWatch Severity Emblem — React + TypeScript demo.
 *
 * GIFs are prerecorded. This component selects the correct asset from CVSS.
 * It does not fetch or score vulnerabilities.
 */
import React, { useCallback, useEffect, useId, useMemo, useState } from "react";
import {
  cvssToState,
  selectAssessment,
  type Assessment,
  type SeverityState,
  STATE_META,
} from "./severityMap";

export interface SeverityEmblemProps {
  projectName?: string;
  cveId?: string;
  cvssScore?: number | null;
  scoreVersion?: string;
  scoreSource?: string;
  /** When multiple assessments exist */
  assessments?: Assessment[];
  /** Base URL for gif/png assets (trailing slash optional) */
  assetBase?: string;
  className?: string;
  /** Demo-only: cycle states. Must be labeled in UI. */
  demoCycle?: boolean;
}

function assetUrl(base: string, state: SeverityState, ext: "gif" | "png"): string {
  const root = base.replace(/\/$/, "");
  return `${root}/${state}.${ext}`;
}

export function SeverityEmblem({
  projectName = "sentinelwatch",
  cveId = "—",
  cvssScore = null,
  scoreVersion = "CVSS:3.1",
  scoreSource = "nvd",
  assessments,
  assetBase = "/severity",
  className = "",
  demoCycle = false,
}: SeverityEmblemProps) {
  const reactId = useId();
  const [prefersReduced, setPrefersReduced] = useState(false);
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    const apply = () => setPrefersReduced(mq.matches);
    apply();
    mq.addEventListener("change", apply);
    return () => mq.removeEventListener("change", apply);
  }, []);

  const active = useMemo(() => {
    if (assessments && assessments.length > 0) {
      return selectAssessment(assessments);
    }
    return {
      score: cvssScore,
      version: scoreVersion,
      source: scoreSource,
    };
  }, [assessments, cvssScore, scoreVersion, scoreSource]);

  const state = cvssToState(active?.score ?? null);
  const meta = STATE_META[state];
  const showStatic = prefersReduced || paused;
  const src = assetUrl(assetBase, state, showStatic ? "png" : "gif");

  const label = `Severity ${meta.label} for ${cveId}, ${scoreVersion} score ${
    active?.score == null || Number.isNaN(Number(active.score))
      ? "unrated"
      : Number(active.score).toFixed(1)
  } from ${active?.source ?? scoreSource}`;

  const togglePause = useCallback(() => setPaused((p) => !p), []);

  return (
    <figure
      className={`sw-emblem ${className}`}
      aria-labelledby={`${reactId}-label`}
      data-severity={state}
      data-demo-cycle={demoCycle ? "true" : "false"}
    >
      <div className="sw-emblem__visual">
        <img
          key={src}
          src={src}
          width={512}
          height={512}
          alt=""
          role="presentation"
          className="sw-emblem__img"
        />
        {/* Watermark is burned into the GIF/PNG as giant background type */}
      </div>
      <figcaption className="sw-emblem__meta" id={`${reactId}-label`}>
        <p className="sw-emblem__cve">
          <strong>{cveId}</strong>
        </p>
        <p className="sw-emblem__score">
          <span className="sw-emblem__badge" data-sev={state}>
            {meta.label}
          </span>{" "}
          {active?.score == null || Number.isNaN(Number(active.score))
            ? "—"
            : Number(active.score).toFixed(1)}{" "}
          <span className="sw-emblem__src">
            {active?.version ?? scoreVersion} · {active?.source ?? scoreSource}
          </span>
        </p>
        <p className="sw-emblem__sr-only">{label}</p>
        <div className="sw-emblem__controls">
          <button
            type="button"
            className="sw-emblem__btn"
            onClick={togglePause}
            aria-pressed={paused}
            disabled={prefersReduced}
          >
            {prefersReduced
              ? "Reduced motion (static)"
              : paused
                ? "Play animation"
                : "Pause animation"}
          </button>
        </div>
        {demoCycle ? (
          <p className="sw-emblem__demo-note">Demo mode — severity controls below.</p>
        ) : null}
      </figcaption>
    </figure>
  );
}

export default SeverityEmblem;
