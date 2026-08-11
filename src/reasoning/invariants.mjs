import { normalizeNegativeEvidence, explicitAbsenceForCapability } from './negative-evidence.mjs';

const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });

export const BUILTIN_INVARIANTS = Object.freeze([
  Object.freeze({
    id: 'no-secret-network-composition',
    title: 'Secret access and network egress must not compose',
    severity: 'critical',
    kind: 'forbid-all',
    capabilities: Object.freeze(['secret-access', 'network-egress'])
  }),
  Object.freeze({
    id: 'destructive-requires-human-approval',
    title: 'Destructive capability requires explicit human approval',
    severity: 'critical',
    kind: 'require-safeguard',
    whenAll: Object.freeze(['destructive-action']),
    safeguards: Object.freeze(['human-approval'])
  }),
  Object.freeze({
    id: 'instruction-control-requires-least-privilege',
    title: 'Instruction-control capability requires least-privilege safeguards',
    severity: 'high',
    kind: 'require-safeguard',
    whenAll: Object.freeze(['instruction-control']),
    safeguards: Object.freeze(['least-privilege'])
  }),
  Object.freeze({
    id: 'dependency-execution-no-network-egress',
    title: 'Dependency execution and network egress must not compose',
    severity: 'critical',
    kind: 'forbid-all',
    capabilities: Object.freeze(['dependency-execution', 'network-egress'])
  })
]);

export function evaluateSecurityInvariants(input = {}) {
  const observed = new Set(normalizeStrings(input.observedCapabilities));
  const safeguards = new Set(normalizeSafeguards(input.safeguards));
  const negativeEvidence = normalizeNegativeEvidence(input.negativeEvidence);
  const definitions = normalizeDefinitions(input.definitions);
  const results = definitions.map((definition) => evaluateOne(definition, observed, safeguards, negativeEvidence));
  const stateCounts = Object.fromEntries(['VIOLATED', 'SATISFIED', 'UNKNOWN', 'NOT_APPLICABLE'].map((state) => [state, 0]));
  for (const result of results) stateCounts[result.state] += 1;
  const maximumViolationSeverity = results
    .filter((item) => item.state === 'VIOLATED')
    .map((item) => item.severity)
    .sort((a, b) => SEVERITY_RANK[b] - SEVERITY_RANK[a])[0] ?? 'info';

  return {
    schemaVersion: 'repotrial.invariants.v1',
    results,
    summary: {
      stateCounts,
      maximumViolationSeverity,
      violationCount: stateCounts.VIOLATED
    }
  };
}

function evaluateOne(definition, observed, safeguards, negativeEvidence) {
  if (definition.kind === 'forbid-all') return evaluateForbidAll(definition, observed, negativeEvidence);
  return evaluateRequireSafeguard(definition, observed, safeguards, negativeEvidence);
}

function evaluateForbidAll(definition, observed, negativeEvidence) {
  const present = definition.capabilities.filter((capability) => observed.has(capability));
  const missing = definition.capabilities.filter((capability) => !observed.has(capability));
  const refuting = missing.flatMap((capability) => explicitAbsenceForCapability(negativeEvidence, capability));
  const state = missing.length === 0
    ? 'VIOLATED'
    : refuting.length > 0
      ? 'SATISFIED'
      : 'UNKNOWN';

  return resultShape(definition, {
    state,
    observedCapabilities: present,
    missingCapabilities: missing,
    safeguardIds: [],
    missingSafeguards: [],
    negativeEvidenceIds: uniqueSorted(refuting.map((item) => item.id)),
    rationale: state === 'VIOLATED'
      ? `All forbidden capabilities are explicitly observed: ${definition.capabilities.join(', ')}.`
      : state === 'SATISFIED'
        ? 'At least one required member of the forbidden composition is explicitly proven absent.'
        : 'The forbidden composition is not fully observed, but missing capability evidence is not proof of absence.'
  });
}

function evaluateRequireSafeguard(definition, observed, safeguards, negativeEvidence) {
  const present = definition.whenAll.filter((capability) => observed.has(capability));
  const missing = definition.whenAll.filter((capability) => !observed.has(capability));
  const refutingAntecedent = missing.flatMap((capability) => explicitAbsenceForCapability(negativeEvidence, capability));
  const presentSafeguards = definition.safeguards.filter((id) => safeguards.has(id));
  const missingSafeguards = definition.safeguards.filter((id) => !safeguards.has(id));

  let state;
  let rationale;
  if (missing.length === 0) {
    if (missingSafeguards.length === 0) {
      state = 'SATISFIED';
      rationale = 'The triggering capability is observed and every required safeguard is explicitly present.';
    } else {
      state = 'VIOLATED';
      rationale = `The triggering capability is observed without required safeguard(s): ${missingSafeguards.join(', ')}.`;
    }
  } else if (refutingAntecedent.length > 0) {
    state = 'NOT_APPLICABLE';
    rationale = 'Explicit negative evidence refutes at least one required triggering capability.';
  } else {
    state = 'UNKNOWN';
    rationale = 'The triggering capability is not fully observed and its absence has not been proven.';
  }

  return resultShape(definition, {
    state,
    observedCapabilities: present,
    missingCapabilities: missing,
    safeguardIds: presentSafeguards,
    missingSafeguards,
    negativeEvidenceIds: uniqueSorted(refutingAntecedent.map((item) => item.id)),
    rationale
  });
}

function resultShape(definition, detail) {
  return {
    id: definition.id,
    title: definition.title,
    severity: definition.severity,
    kind: definition.kind,
    state: detail.state,
    observedCapabilities: uniqueSorted(detail.observedCapabilities),
    missingCapabilities: uniqueSorted(detail.missingCapabilities),
    safeguardIds: uniqueSorted(detail.safeguardIds),
    missingSafeguards: uniqueSorted(detail.missingSafeguards),
    negativeEvidenceIds: uniqueSorted(detail.negativeEvidenceIds),
    rationale: detail.rationale
  };
}

function normalizeDefinitions(custom) {
  const byId = new Map();
  for (const definition of [...BUILTIN_INVARIANTS, ...(Array.isArray(custom) ? custom : [])]) {
    const normalized = normalizeDefinition(definition);
    if (!normalized || byId.has(normalized.id)) continue;
    byId.set(normalized.id, normalized);
  }
  return [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
}

function normalizeDefinition(definition) {
  if (!definition || typeof definition !== 'object' || Array.isArray(definition)) return null;
  const id = clean(definition.id);
  const title = clean(definition.title, id);
  const severity = normalizeSeverity(definition.severity);
  if (!id) return null;

  if (definition.kind === 'forbid-all') {
    const capabilities = normalizeStrings(definition.capabilities);
    if (!capabilities.length) return null;
    return { id, title, severity, kind: 'forbid-all', capabilities };
  }
  if (definition.kind === 'require-safeguard') {
    const whenAll = normalizeStrings(definition.whenAll);
    const safeguards = normalizeStrings(definition.safeguards);
    if (!whenAll.length || !safeguards.length) return null;
    return { id, title, severity, kind: 'require-safeguard', whenAll, safeguards };
  }
  return null;
}

function normalizeSafeguards(items) {
  if (!Array.isArray(items)) return [];
  return uniqueSorted(items.map((item) => typeof item === 'string' ? item : item?.id).filter((item) => typeof item === 'string' && item.trim()).map((item) => item.trim()));
}

function normalizeStrings(items) {
  if (!Array.isArray(items)) return [];
  return uniqueSorted(items.filter((item) => typeof item === 'string' && item.trim()).map((item) => item.trim()));
}

function uniqueSorted(items) {
  return [...new Set(items)].sort();
}

function normalizeSeverity(value) {
  const severity = clean(value, 'medium').toLowerCase();
  return severity in SEVERITY_RANK ? severity : 'medium';
}

function clean(value, fallback = '') {
  if (typeof value !== 'string') return fallback;
  const normalized = value.trim();
  return normalized || fallback;
}
