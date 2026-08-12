const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });
const ACTIVE_STATES = new Set(['PROVEN', 'SUPPORTED']);

export function normalizeCausalThreshold(value, flag = 'causal gate') {
  const normalized = String(value ?? '').trim().toLowerCase();
  if (!(normalized in SEVERITY_RANK)) {
    throw new Error(`Invalid causal threshold for ${flag}: ${value}. Expected info, low, medium, high, or critical.`);
  }
  return normalized;
}

export function causalMeetsSeverity(causal, threshold) {
  if (!causal) return false;
  const rank = severityRank(normalizeCausalThreshold(threshold));
  return (causal.reasoning?.chains ?? []).some((item) =>
    ACTIVE_STATES.has(item?.state) && severityRank(item?.severity) >= rank);
}

export function causalDifferentialMeetsSeverity(causal, threshold) {
  if (!causal) return false;
  const rank = severityRank(normalizeCausalThreshold(threshold));
  if ((causal.newActive ?? []).some((item) => severityRank(item?.severity) >= rank)) return true;
  return (causal.regressed ?? []).some((item) =>
    ACTIVE_STATES.has(item?.to) && severityRank(item?.severity) >= rank);
}

export function severityRank(value) {
  return SEVERITY_RANK[String(value ?? '').toLowerCase()] ?? -1;
}
