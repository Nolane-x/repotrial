const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });

export function normalizeReasoningThreshold(value, flag = 'reasoning gate') {
  const normalized = String(value ?? '').trim().toLowerCase();
  if (!(normalized in SEVERITY_RANK)) {
    throw new Error(`Invalid reasoning threshold for ${flag}: ${value}. Expected info, low, medium, high, or critical.`);
  }
  return normalized;
}

export function reasoningMeetsSeverity(reasoning, threshold) {
  if (!reasoning) return false;
  const rank = severityRank(normalizeReasoningThreshold(threshold));
  return (reasoning.hypotheses ?? []).some((item) =>
    ['PROVEN', 'SUPPORTED'].includes(item?.state) && severityRank(item?.severity) >= rank)
    || (reasoning.invariants?.results ?? []).some((item) =>
      item?.state === 'VIOLATED' && severityRank(item?.severity) >= rank);
}

export function reasoningDifferentialMeetsSeverity(reasoning, threshold) {
  if (!reasoning) return false;
  const rank = severityRank(normalizeReasoningThreshold(threshold));
  if ((reasoning.attackPaths?.new ?? []).some((item) => severityRank(item?.severity) >= rank)) return true;
  if ((reasoning.invariants?.newViolations ?? []).some((item) => severityRank(item?.severity) >= rank)) return true;
  return (reasoning.hypotheses?.regressed ?? []).some((item) =>
    ['PROVEN', 'SUPPORTED'].includes(item?.to) && severityRank(item?.severity) >= rank);
}

export function severityRank(value) {
  return SEVERITY_RANK[String(value ?? '').toLowerCase()] ?? -1;
}
