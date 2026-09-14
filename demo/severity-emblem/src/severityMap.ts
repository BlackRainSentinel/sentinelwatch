/** Centralized CVSS → severity mapping (mirrors Python sentinelwatch.severity_emblem). */

export type SeverityState =
  | "none"
  | "low"
  | "medium"
  | "high"
  | "critical"
  | "unknown";

export interface Assessment {
  score: number | string | null | undefined;
  version?: string;
  source?: string;
}

export const STATE_META: Record<
  SeverityState,
  { label: string; band: string; color: string }
> = {
  none: { label: "NONE", band: "0.0", color: "#5ac8be" },
  low: { label: "LOW", band: "0.1–3.9", color: "#4696ff" },
  medium: { label: "MEDIUM", band: "4.0–6.9", color: "#f0b428" },
  high: { label: "HIGH", band: "7.0–8.9", color: "#ff8228" },
  critical: { label: "CRITICAL", band: "9.0–10.0", color: "#ff3746" },
  unknown: { label: "UNRATED", band: "missing / invalid", color: "#8c96a5" },
};

export function cvssToState(cvss: number | string | null | undefined): SeverityState {
  if (cvss === null || cvss === undefined || cvss === "") return "unknown";
  const score = typeof cvss === "number" ? cvss : Number(cvss);
  if (!Number.isFinite(score) || score < 0 || score > 10) return "unknown";
  if (score === 0) return "none";
  if (score <= 3.9) return "low";
  if (score <= 6.9) return "medium";
  if (score <= 8.9) return "high";
  return "critical";
}

/** Prefer NVD/official, then highest valid score. */
export function selectAssessment(assessments: Assessment[]): Assessment | null {
  if (!assessments.length) return null;
  const ranked = [...assessments].sort((a, b) => {
    const scoreKey = (x: Assessment) => {
      const s = Number(x.score);
      const valid = Number.isFinite(s) && s >= 0 && s <= 10 ? 0 : 1;
      const src = (x.source || "").toLowerCase();
      const official = ["nvd", "official", "first", "cna"].includes(src) ? 0 : 1;
      const scoreSort = valid === 0 ? -s : 0;
      return [valid, official, scoreSort] as const;
    };
    const ka = scoreKey(a);
    const kb = scoreKey(b);
    for (let i = 0; i < 3; i++) {
      if (ka[i] !== kb[i]) return ka[i] - kb[i];
    }
    return 0;
  });
  return ranked[0];
}
