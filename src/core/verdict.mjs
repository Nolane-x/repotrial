const WEIGHTS = Object.freeze({ critical: 45, high: 24, medium: 11, low: 4, info: 0 });
const LABEL_RANK = Object.freeze({ UNPROVEN: 0, TRUSTED: 1, CAUTIOUS: 2, RECKLESS: 3, DANGEROUS: 4 });

export function calculateVerdict(charges, coverage = { ratio: 0, complete: false }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let score = 0;
  for (const charge of charges) {
    const severity = WEIGHTS[charge.severity] === undefined ? 'medium' : charge.severity;
    if (charge.status === 'proven') {
      counts[severity] += 1;
      score += WEIGHTS[severity];
    } else if (charge.status === 'mitigated') {
      score += Math.max(0, Math.floor(WEIGHTS[severity] * 0.2));
    }
  }
  if (!coverage.complete) score += Math.round((1 - (coverage.ratio ?? 0)) * 15);
  score = Math.min(100, Math.max(0, score));

  let label;
  if ((coverage.ratio ?? 0) === 0) label = 'UNPROVEN';
  else if (counts.critical > 0 || score >= 80) label = 'DANGEROUS';
  else if (counts.high >= 2 || score >= 45) label = 'RECKLESS';
  else if (score > 0 || !coverage.complete) label = 'CAUTIOUS';
  else label = 'TRUSTED';

  return {
    label,
    rank: LABEL_RANK[label],
    score,
    severityCounts: counts,
    coverage: coverage.ratio ?? 0,
    rationale: verdictRationale(label, counts, coverage)
  };
}

function verdictRationale(label, counts, coverage) {
  if (label === 'UNPROVEN') return 'No inspectable evidence was available.';
  if (label === 'DANGEROUS') return `Critical evidence or an accumulated risk score crossed the dangerous threshold.`;
  if (label === 'RECKLESS') return `${counts.high} high-severity and ${counts.critical} critical proven charges require remediation.`;
  if (label === 'CAUTIOUS') return coverage.complete
    ? 'Risk signals were found, but none crossed the dangerous threshold.'
    : 'The visible evidence is limited by incomplete scan coverage.';
  return 'No proven risk signal was found in the inspected scope; this is not a security guarantee.';
}

export function verdictMeetsThreshold(label, threshold) {
  const normalized = String(threshold ?? '').toUpperCase();
  if (!(normalized in LABEL_RANK)) return false;
  return LABEL_RANK[label] >= LABEL_RANK[normalized];
}
