import { sha256, stableStringify } from '../core/hash.mjs';
import { semanticsForCapability } from './capability-semantics.mjs';
import { validateThreatDefinitions } from './threat-registry.mjs';

const DEFAULT_MIN_NOVELTY = 0.35;
const CORROBORATED = new Set(['SHARED_EVIDENCE', 'SAME_FILE', 'EXPLICIT_CROSSING', 'RUNTIME_CAUSAL_TRACE']);

export function promoteDiscoveredHypothesis(candidate, options = {}) {
  if (!candidate || typeof candidate !== 'object') throw new TypeError('Discovered hypothesis candidate must be an object.');
  if (candidate.state !== 'PROMOTABLE') throw new TypeError('Only PROMOTABLE discovered hypotheses can be promoted.');
  if (candidate?.realmAssessment?.productionRelevant !== true) throw new TypeError('Promotion requires production-relevant evidence.');

  const minNovelty = boundedNumber(options.minNovelty, DEFAULT_MIN_NOVELTY, 0, 1);
  const noveltyScore = Number(candidate.noveltyScore ?? 0);
  if (!Number.isFinite(noveltyScore) || noveltyScore < minNovelty) throw new TypeError(`Promotion requires novelty >= ${minNovelty}.`);
  if (!CORROBORATED.has(String(candidate.corroboration ?? ''))) throw new TypeError('Promotion requires corroborated evidence composition.');

  const capabilities = Array.isArray(candidate.capabilities) ? candidate.capabilities.map(String) : [];
  if (capabilities.length < 2 || capabilities.length > 4) throw new TypeError('Promotion requires 2-4 bounded capabilities.');
  if (new Set(capabilities).size !== capabilities.length) throw new TypeError('Promotion requires distinct capabilities.');
  for (const capability of capabilities) {
    if (!semanticsForCapability(capability)) throw new TypeError(`Promotion rejected unknown capability: ${capability}`);
  }

  const identity = stableStringify({ capabilities, category: 'autonomous-discovery' });
  const raw = {
    id: `auto-discovered-${sha256(identity).slice(0, 24)}`,
    title: boundedTitle(candidate.title, capabilities),
    severity: normalizedSeverity(candidate.severity),
    category: 'autonomous-discovery',
    stages: capabilities.map((capability, order) => ({
      id: `stage-${order + 1}`,
      label: `Observed capability: ${capability}`,
      anyOf: [capability],
      order
    })),
    mitigatedBy: [],
    experimentHints: []
  };

  const validated = validateThreatDefinitions([raw]);
  return validated.definitions[0];
}

function boundedTitle(value, capabilities) {
  const text = typeof value === 'string' ? value.trim() : '';
  const fallback = `Discovered composition: ${capabilities.join(' -> ')}`;
  return (text || fallback).slice(0, 240);
}

function normalizedSeverity(value) {
  const severity = String(value ?? 'medium').toLowerCase();
  return new Set(['info', 'low', 'medium', 'high', 'critical']).has(severity) ? severity : 'medium';
}

function boundedNumber(value, fallback, min, max) {
  const number = Number(value ?? fallback);
  return Number.isFinite(number) ? Math.max(min, Math.min(max, number)) : fallback;
}
