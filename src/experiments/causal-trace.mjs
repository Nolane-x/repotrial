import { sha256, stableStringify } from '../core/hash.mjs';

const PHASE_ORDER = Object.freeze({ PREPARE: 0, PRIME: 1, TRIGGER: 2, OBSERVE: 3, FOLLOW_UP: 4, VERIFY: 5 });
const CANARY_PATTERN = /rtx_[A-Za-z0-9_-]+/g;

export function buildCausalTrace(input = {}) {
  const phaseResults = Array.isArray(input.phaseResults) ? input.phaseResults : [];
  const ordered = phaseResults.map((item, index) => ({ item, index })).sort((a, b) =>
    (PHASE_ORDER[String(a.item?.phase)] ?? 99) - (PHASE_ORDER[String(b.item?.phase)] ?? 99)
    || a.index - b.index
    || String(a.item?.id ?? '').localeCompare(String(b.item?.id ?? '')));
  const steps = [];
  let parentStepId = null;
  for (const { item } of ordered) {
    const sanitizedObservations = sanitize(Array.isArray(item?.observations) ? item.observations : []);
    const identity = {
      episodeId: stringValue(input.episodeId, ''),
      sourcePhaseId: stringValue(item?.id, ''),
      phase: stringValue(item?.phase, 'UNKNOWN'),
      parentStepId
    };
    const step = {
      id: `trace-step:${digest(stableStringify(identity))}`,
      phase: identity.phase,
      status: normalizedState(item?.status),
      parentStepId,
      observations: sanitizedObservations,
      emittedEvidenceIds: uniqueSorted(item?.emittedEvidenceIds)
    };
    steps.push(step);
    parentStepId = step.id;
  }
  const emittedEvidenceIds = uniqueSorted(steps.flatMap((step) => step.emittedEvidenceIds));
  const body = {
    schemaVersion: 'repotrial.causal-trace.v1',
    episodeId: stringValue(input.episodeId, ''),
    chainId: stringValue(input.chainId, ''),
    threatId: stringValue(input.threatId, ''),
    targetCapabilities: uniqueSorted(input.targetCapabilities),
    scope: 'single-bounded-episode',
    outcome: overallOutcome(steps),
    steps,
    emittedEvidenceIds,
    redaction: {
      syntheticCanaries: 'redacted-before-serialization',
      rawCanaryPersistenceAllowed: false
    }
  };
  return { ...body, receipt: sha256(stableStringify(body)) };
}

function sanitize(value) {
  if (typeof value === 'string') return value.replace(CANARY_PATTERN, '[synthetic-canary-redacted]');
  if (Array.isArray(value)) return value.map(sanitize);
  if (value && typeof value === 'object') {
    const result = {};
    for (const [key, item] of Object.entries(value).sort(([a], [b]) => a.localeCompare(b))) {
      if (/^(rawCanary|canaryValue|secretValue)$/i.test(key)) {
        result[key] = '[synthetic-canary-redacted]';
      } else {
        result[key] = sanitize(item);
      }
    }
    return result;
  }
  return value;
}

function overallOutcome(steps) {
  const states = new Set(steps.map((step) => step.status));
  if (states.has('INCONCLUSIVE') || states.has('UNSUPPORTED')) return 'INCONCLUSIVE';
  if (states.has('OBSERVED')) return 'OBSERVED';
  if (states.has('NOT_OBSERVED')) return 'NOT_OBSERVED';
  if (states.has('TRIGGERED')) return 'TRIGGERED';
  return 'INCONCLUSIVE';
}

function normalizedState(value) {
  const state = String(value ?? 'INCONCLUSIVE').toUpperCase();
  return ['OBSERVED', 'TRIGGERED', 'NOT_OBSERVED', 'INCONCLUSIVE', 'UNSUPPORTED'].includes(state) ? state : 'INCONCLUSIVE';
}

function uniqueSorted(value) {
  return [...new Set((Array.isArray(value) ? value : []).map(String))].sort();
}

function stringValue(value, fallback) {
  return typeof value === 'string' ? value : fallback;
}

function digest(value) {
  return sha256(String(value)).slice(0, 24);
}
