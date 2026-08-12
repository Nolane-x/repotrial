const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });
const ACTIVE_STATES = new Set(['PROVEN', 'SUPPORTED']);

export function normalizeCausalThreshold(value, flag = 'causal gate') {
  const normalized = String(value ?? '').trim().toLowerCase();
  if (!(normalized in SEVERITY_RANK)) {
    throw new Error(`Invalid causal threshold for ${flag}: ${value}. Expected info, low, medium, high, or critical.`);
  }
  return normalized;
}

export function normalizeCausalRealmScope(value, flag = 'causal realm scope') {
  const normalized = String(value ?? 'all').trim().toLowerCase();
  if (!['all', 'production'].includes(normalized)) throw new Error(`Invalid ${flag}: ${value}. Expected all or production.`);
  return normalized;
}

export function causalMeetsSeverity(causal, threshold, options = {}) {
  if (!causal) return false;
  const rank = severityRank(normalizeCausalThreshold(threshold));
  const scope = normalizeCausalRealmScope(options.realmScope ?? causal.realmScope ?? 'all');
  return (causal.reasoning?.chains ?? []).some((item) =>
    ACTIVE_STATES.has(item?.state)
    && (scope !== 'production' || item?.realmAssessment?.productionRelevant === true)
    && severityRank(item?.severity) >= rank);
}

export function causalDifferentialMeetsSeverity(causal, threshold, options = {}) {
  if (!causal) return false;
  const rank = severityRank(normalizeCausalThreshold(threshold));
  const scope = normalizeCausalRealmScope(options.realmScope ?? causal.realmScope ?? 'all');
  const relevant = (item) => scope !== 'production' || item?.realmAssessment?.productionRelevant === true || item?.productionRelevant === true;
  if ((causal.newActive ?? []).some((item) => relevant(item) && severityRank(item?.severity) >= rank)) return true;
  return (causal.regressed ?? []).some((item) =>
    relevant(item) && ACTIVE_STATES.has(item?.to) && severityRank(item?.severity) >= rank);
}

export function severityRank(value) {
  return SEVERITY_RANK[String(value ?? '').toLowerCase()] ?? -1;
}
