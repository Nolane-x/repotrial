import { sha256, stableStringify } from '../core/hash.mjs';

const CONFIDENCE_WEIGHT = Object.freeze({
  high: 0.96,
  'external-evidence-anchored': 0.9,
  'external-evidence': 0.76,
  medium: 0.65,
  low: 0.45
});

export function normalizeNegativeEvidence(items = []) {
  if (!Array.isArray(items)) return [];
  const byId = new Map();

  for (const input of items) {
    const normalized = normalizeOne(input);
    if (!normalized) continue;
    const existing = byId.get(normalized.id);
    if (!existing || stronger(normalized, existing)) byId.set(normalized.id, normalized);
  }

  return [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
}

export function explicitAbsenceForCapability(items, capability, minimumConfidence = 0.75) {
  return normalizeNegativeEvidence(items)
    .filter((item) => item.capability === capability && item.confidence >= minimumConfidence)
    .sort((a, b) => b.confidence - a.confidence || a.id.localeCompare(b.id));
}

function normalizeOne(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  const capability = clean(input.capability);
  const source = clean(input.source);
  const method = clean(input.method);
  const scope = clean(input.scope, 'repository');
  const state = clean(input.state, 'absent').toLowerCase();
  if (!capability || !source || !method || state !== 'absent') return null;

  const confidenceLabel = confidenceName(input.confidence);
  const confidence = confidenceScore(input.confidence);
  const identity = stableStringify({ capability, source, method, scope, state: 'ABSENT' });

  return {
    id: `neg:${sha256(identity).slice(0, 24)}`,
    state: 'ABSENT',
    capability,
    source,
    method,
    scope,
    confidenceLabel,
    confidence
  };
}

function confidenceName(value) {
  if (typeof value === 'string' && value in CONFIDENCE_WEIGHT) return value;
  if (typeof value === 'number' && Number.isFinite(value)) return 'numeric';
  return 'low';
}

function confidenceScore(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return round3(clamp01(value));
  return CONFIDENCE_WEIGHT[value] ?? CONFIDENCE_WEIGHT.low;
}

function stronger(a, b) {
  if (a.confidence !== b.confidence) return a.confidence > b.confidence;
  return stableStringify(a).localeCompare(stableStringify(b)) < 0;
}

function clean(value, fallback = '') {
  if (typeof value !== 'string') return fallback;
  const normalized = value.trim();
  return normalized || fallback;
}

function clamp01(value) {
  return Math.min(1, Math.max(0, value));
}

function round3(value) {
  return Math.round(value * 1000) / 1000;
}
