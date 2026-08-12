const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });

export function scoreCausalChain(input = {}) {
  const severity = normalizedSeverity(input.severity);
  const stages = Array.isArray(input.stages) ? input.stages : [];
  const satisfied = stages.filter((stage) => stage?.satisfied);
  const direct = satisfied.filter((stage) => stage?.direct);
  const threatImpact = SEVERITY_RANK[severity] / 4;
  const stageCompletion = stages.length ? satisfied.length / stages.length : 0;
  const confidenceFloor = satisfied.length ? Math.min(...satisfied.map((stage) => clamp01(Number(stage.confidence ?? 0)))) : 0;
  const directness = satisfied.length ? direct.length / satisfied.length : 0;
  const coverageRatio = clamp01(Number(input.coverage?.ratio ?? input.coverageRatio ?? 0));
  const coverageFactor = 0.7 + (0.3 * coverageRatio);
  const contradictionFactor = input.state === 'CONTRADICTED' ? 0.55 : input.state === 'BLOCKED' ? 0.3 : 1;
  const base = (0.35 * threatImpact)
    + (0.25 * stageCompletion)
    + (0.2 * confidenceFloor)
    + (0.1 * directness)
    + (0.1 * coverageFactor);
  const rank = round6(1000 * base * contradictionFactor);
  return {
    rank,
    breakdown: {
      threatImpact: round6(threatImpact),
      stageCompletion: round6(stageCompletion),
      confidenceFloor: round6(confidenceFloor),
      directness: round6(directness),
      coverageFactor: round6(coverageFactor),
      contradictionFactor: round6(contradictionFactor)
    },
    interpretation: 'evidence-strength-and-impact-not-safety-probability'
  };
}

export function severityRank(value) {
  return SEVERITY_RANK[normalizedSeverity(value)];
}

function normalizedSeverity(value) {
  const severity = String(value ?? 'info').toLowerCase();
  return severity in SEVERITY_RANK ? severity : 'info';
}

function clamp01(value) {
  return Number.isFinite(value) ? Math.min(1, Math.max(0, value)) : 0;
}

function round6(value) {
  return Math.round(value * 1_000_000) / 1_000_000;
}
