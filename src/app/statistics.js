import { computeQualityReport, gradeMeta, scoreColor } from '../lib/index.js';

/* Statistics tab: an SBOM quality score with a category breakdown and
   actionable "worst offender" insights, computed over the already-parsed
   model (see src/lib/quality.js — no extra parsing pass). */

export const statisticsMixin = {
  get qualityReport() {
    return computeQualityReport(this);
  },
  qualityGradeMeta(grade) {
    return gradeMeta(grade);
  },
  qualityScoreColor(score) {
    return scoreColor(score);
  },
  // Conic-gradient ring for the overall-score gauge; a plain CSS circle so the
  // gauge needs no charting dependency.
  qualityRingStyle(score, color) {
    return `background: conic-gradient(${color} ${score * 3.6}deg, #334155 0deg)`;
  }
};
