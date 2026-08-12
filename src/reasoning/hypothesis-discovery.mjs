import { sha256, stableStringify } from '../core/hash.mjs';
import { getCapabilitySemantics } from './capability-semantics.mjs';
import { validateThreatDefinitions } from './threat-registry.mjs';

const DEFAULT_MAX_CANDIDATES = 32;
const HARD_MAX_CANDIDATES = 128;
const DEFAULT_MIN_NOVELTY = 0.35;
const HARD_MAX_PATTERN_PRODUCTS = 256;
const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });
const STATE_RANK = Object.freeze({ PROMOTABLE: 4, CORROBORATED: 3, STRUCTURAL: 2, DISMISSED: 1 });

const PATTERNS = Object.freeze([
  { id: 'source-control-sink', roles: [['SOURCE'], ['CONTROL', 'EXECUTION', 'TOOL'], ['SINK']] },
  { id: 'control-effect', roles: [['CONTROL'], ['TOOL', 'EXECUTION'], ['SINK']] },
  { id: 'authority-effect', roles: [['AUTHORITY'], ['CONTROL', 'EXECUTION', 'TOOL'], ['SINK']] },
  { id: 'persistence-effect', roles: [['PERSISTENCE'], ['CONTROL'], ['TOOL', 'EXECUTION', 'SINK']] },
  { id: 'sensitive-source-sink', roles: [['SOURCE'], ['SINK']], requireFirstProperty: 'sensitive', requireLastAnyProperty: ['external', 'persistent'] },
  { id: 'control-authority-sink', roles: [['CONTROL'], ['AUTHORITY'], ['SINK']], requireLastAnyProperty: ['privileged', 'destructive'] },
  { id: 'control-impact', roles: [['CONTROL'], ['SINK']], requireLastAnyProperty: ['external', 'destructive', 'privileged', 'persistent'] },
  { id: 'persistence-impact', roles: [['PERSISTENCE'], ['SINK']], requireLastAnyProperty: ['external', 'destructive', 'privileged', 'persistent'] }
]);

export function discoverThreatHypotheses(input = {}) {
  const graph = normalizeGraph(input.causalGraph);
  const registry = normalizeRegistry(input.registry);
  const realmIndex = input.realmIndex && typeof input.realmIndex === 'object' ? input.realmIndex : { byEvidenceId: {} };
  const maxCandidates = boundedInteger(input.maxCandidates, DEFAULT_MAX_CANDIDATES, 1, HARD_MAX_CANDIDATES);
  const minNovelty = boundedNumber(input.minNovelty, DEFAULT_MIN_NOVELTY, 0, 1);
  const semantics = getCapabilitySemantics();
  const index = indexObservedCapabilities(graph, realmIndex, semantics);

  const accepted = new Map();
  let registryCoveredCount = 0;
  let crossRealmDismissedCount = 0;
  let nonImpactfulDismissedCount = 0;
  let generatedBeforePruning = 0;

  for (const pattern of PATTERNS) {
    const optionSets = pattern.roles.map((roles) => capabilityOptions(index, roles));
    if (optionSets.some((options) => options.length === 0)) continue;
    for (const capabilities of boundedProduct(optionSets, HARD_MAX_PATTERN_PRODUCTS)) {
      if (new Set(capabilities).size !== capabilities.length) continue;
      if (!patternAllows(pattern, capabilities, semantics)) continue;
      generatedBeforePruning += 1;

      const candidateRealm = candidateRealmAssessment(capabilities, index);
      if (candidateRealm.state === 'CROSS_REALM_UNPROVEN') {
        crossRealmDismissedCount += 1;
        continue;
      }
      if (!impactBearing(capabilities, semantics)) {
        nonImpactfulDismissedCount += 1;
        continue;
      }

      const nearest = nearestRegisteredThreat(capabilities, registry);
      const noveltyScore = round3(1 - nearest.similarity);
      if (noveltyScore < minNovelty) {
        registryCoveredCount += 1;
        continue;
      }

      const evidence = evidenceCoherence(capabilities, index);
      const state = candidateState(candidateRealm, evidence, noveltyScore, minNovelty);
      const severity = severityBound(capabilities, semantics);
      const semantic = { patternId: pattern.id, capabilities };
      const candidate = {
        id: `hyp:auto:${digest(stableStringify(semantic))}`,
        title: `Discovered composition: ${capabilities.join(' → ')}`,
        category: 'autonomous-discovery',
        patternId: pattern.id,
        state,
        severity,
        capabilities: [...capabilities],
        stages: capabilities.map((capability, order) => ({ id: `stage-${order + 1}`, order, capability })),
        supportingEvidenceIds: evidence.supportingEvidenceIds,
        corroboration: evidence.corroboration,
        corroborationScore: evidence.score,
        sharedEvidenceIds: evidence.sharedEvidenceIds,
        sharedPaths: evidence.sharedPaths,
        realmAssessment: candidateRealm,
        nearestThreatId: nearest.threatId,
        knownThreatSimilarity: round3(nearest.similarity),
        noveltyScore,
        promotable: state === 'PROMOTABLE',
        caveat: 'Autonomous hypotheses are deterministic candidates for verification; they are not vulnerability proof.'
      };
      const key = stableStringify({ capabilities, realm: candidateRealm.realms, state });
      const existing = accepted.get(key);
      if (!existing || compareCandidates(candidate, existing) < 0) accepted.set(key, candidate);
    }
  }

  const all = [...accepted.values()].sort(compareCandidates);
  const candidates = all.slice(0, maxCandidates);
  const body = {
    schemaVersion: 'repotrial.hypothesis-discovery.v1',
    limits: { maxCandidates, hardMaxCandidates: HARD_MAX_CANDIDATES, minNovelty },
    candidates,
    summary: {
      candidateCount: candidates.length,
      promotableCount: candidates.filter((item) => item.state === 'PROMOTABLE').length,
      corroboratedCount: candidates.filter((item) => item.state === 'CORROBORATED').length,
      structuralCount: candidates.filter((item) => item.state === 'STRUCTURAL').length,
      productionCandidateCount: candidates.filter((item) => item.realmAssessment.productionRelevant).length,
      registryCoveredCount,
      crossRealmDismissedCount,
      nonImpactfulDismissedCount,
      generatedBeforePruning,
      truncated: all.length > candidates.length
    }
  };
  return { ...body, receipt: sha256(stableStringify(body)) };
}

function normalizeGraph(value) {
  return value && typeof value === 'object'
    ? { nodes: Array.isArray(value.nodes) ? value.nodes : [], edges: Array.isArray(value.edges) ? value.edges : [] }
    : { nodes: [], edges: [] };
}

function normalizeRegistry(value) {
  if (value?.schemaVersion === 'repotrial.threat-registry.v1' && Array.isArray(value.definitions)) return validateThreatDefinitions(value.definitions);
  if (Array.isArray(value)) return validateThreatDefinitions(value);
  return validateThreatDefinitions([]);
}

function indexObservedCapabilities(graph, realmIndex, semantics) {
  const capabilityNodes = new Map();
  const evidenceNodes = new Map();
  for (const node of graph.nodes) {
    if (node?.type === 'CAPABILITY' && node.observed === true && typeof node.capability === 'string' && semantics[node.capability]) capabilityNodes.set(node.id, node.capability);
    if (node?.type === 'EVIDENCE' && typeof node.id === 'string') evidenceNodes.set(node.id, node);
  }
  const supportsByCapability = new Map();
  for (const edge of graph.edges) {
    if (edge?.relation !== 'SUPPORTS') continue;
    const capability = capabilityNodes.get(edge.to);
    if (!capability || !evidenceNodes.has(edge.from)) continue;
    pushMap(supportsByCapability, capability, edge.from);
  }
  for (const ids of supportsByCapability.values()) ids.sort();

  const realmsByCapability = new Map();
  const pathsByEvidenceId = new Map();
  for (const [capability, ids] of supportsByCapability) {
    const realms = new Set();
    for (const id of ids) {
      const entry = realmIndex?.byEvidenceId?.[id];
      for (const realm of entry?.realms ?? (entry?.realm ? [entry.realm] : ['unknown'])) realms.add(realm);
      pathsByEvidenceId.set(id, (entry?.anchors ?? []).map((anchor) => anchor.path).filter(Boolean).sort());
    }
    realmsByCapability.set(capability, [...realms].sort());
  }
  return {
    capabilities: [...supportsByCapability.keys()].sort(),
    supportsByCapability,
    realmsByCapability,
    pathsByEvidenceId
  };
}

function capabilityOptions(index, roles) {
  const semantics = getCapabilitySemantics();
  return index.capabilities.filter((capability) => roles.some((role) => semantics[capability]?.roles.includes(role))).sort();
}

function patternAllows(pattern, capabilities, semantics) {
  const first = semantics[capabilities[0]];
  const last = semantics[capabilities[capabilities.length - 1]];
  if (pattern.requireFirstProperty && !first?.properties.includes(pattern.requireFirstProperty)) return false;
  if (pattern.requireLastAnyProperty && !pattern.requireLastAnyProperty.some((property) => last?.properties.includes(property))) return false;
  return true;
}

function candidateRealmAssessment(capabilities, index) {
  const realmSets = capabilities.map((capability) => new Set(index.realmsByCapability.get(capability) ?? ['unknown']));
  let common = realmSets.length ? new Set(realmSets[0]) : new Set();
  for (const set of realmSets.slice(1)) common = new Set([...common].filter((realm) => set.has(realm)));
  const all = [...new Set(realmSets.flatMap((set) => [...set]))].sort();
  if (!common.size) return { state: 'CROSS_REALM_UNPROVEN', productionRelevant: false, realms: all, commonRealms: [] };
  const commonRealms = [...common].sort();
  if (common.has('production')) return { state: 'PRODUCTION_RELEVANT', productionRelevant: true, realms: all, commonRealms };
  if (common.size === 1 && common.has('unknown')) return { state: 'UNKNOWN_REALM', productionRelevant: false, realms: all, commonRealms };
  return { state: 'NON_PRODUCTION_ONLY', productionRelevant: false, realms: all, commonRealms };
}

function evidenceCoherence(capabilities, index) {
  const evidenceSets = capabilities.map((capability) => new Set(index.supportsByCapability.get(capability) ?? []));
  let shared = evidenceSets.length ? new Set(evidenceSets[0]) : new Set();
  for (const set of evidenceSets.slice(1)) shared = new Set([...shared].filter((id) => set.has(id)));
  const supportingEvidenceIds = [...new Set(evidenceSets.flatMap((set) => [...set]))].sort();
  const pathSets = evidenceSets.map((set) => new Set([...set].flatMap((id) => index.pathsByEvidenceId.get(id) ?? [])));
  let sharedPaths = pathSets.length ? new Set(pathSets[0]) : new Set();
  for (const set of pathSets.slice(1)) sharedPaths = new Set([...sharedPaths].filter((path) => set.has(path)));
  if (shared.size) return { corroboration: 'SHARED_EVIDENCE', score: 1, sharedEvidenceIds: [...shared].sort(), sharedPaths: [...sharedPaths].sort(), supportingEvidenceIds };
  if (sharedPaths.size) return { corroboration: 'SAME_FILE', score: 0.8, sharedEvidenceIds: [], sharedPaths: [...sharedPaths].sort(), supportingEvidenceIds };
  return { corroboration: 'SAME_REALM', score: 0.45, sharedEvidenceIds: [], sharedPaths: [], supportingEvidenceIds };
}

function candidateState(realm, evidence, noveltyScore, minNovelty) {
  if (realm.state === 'CROSS_REALM_UNPROVEN') return 'DISMISSED';
  if (realm.productionRelevant && evidence.score >= 0.8 && noveltyScore >= minNovelty) return 'PROMOTABLE';
  if (evidence.score >= 0.8) return 'CORROBORATED';
  return 'STRUCTURAL';
}

function impactBearing(capabilities, semantics) {
  return capabilities.some((capability) => semantics[capability]?.roles.includes('SINK')
    || semantics[capability]?.roles.includes('AUTHORITY')
    || semantics[capability]?.roles.includes('PERSISTENCE'));
}

function severityBound(capabilities, semantics) {
  const props = new Set(capabilities.flatMap((capability) => semantics[capability]?.properties ?? []));
  const roles = new Set(capabilities.flatMap((capability) => semantics[capability]?.roles ?? []));
  if (props.has('destructive') || props.has('privileged')) return 'critical';
  if (props.has('sensitive') && props.has('external')) return 'critical';
  if (roles.has('EXECUTION') || props.has('external') || roles.has('PERSISTENCE')) return 'high';
  if (props.has('persistent') || props.has('stateful')) return 'medium';
  return 'low';
}

function nearestRegisteredThreat(capabilities, registry) {
  let best = { threatId: null, similarity: 0 };
  for (const definition of registry.definitions) {
    for (const sequence of boundedProduct(definition.stages
      .slice().sort((a, b) => a.order - b.order || a.id.localeCompare(b.id))
      .map((stage) => [...stage.anyOf].sort()), 64)) {
      const similarity = sequenceSimilarity(capabilities, sequence);
      if (similarity > best.similarity || (similarity === best.similarity && String(definition.id).localeCompare(String(best.threatId ?? '~')) < 0)) {
        best = { threatId: definition.id, similarity };
      }
    }
  }
  return best;
}

function sequenceSimilarity(a, b) {
  const aSet = new Set(a);
  const bSet = new Set(b);
  const intersection = [...aSet].filter((item) => bSet.has(item)).length;
  const union = new Set([...aSet, ...bSet]).size || 1;
  const jaccard = intersection / union;
  const maxLen = Math.max(a.length, b.length, 1);
  let positional = 0;
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) if (a[i] === b[i]) positional += 1;
  const ordered = positional / maxLen;
  return clamp01(0.7 * jaccard + 0.3 * ordered);
}

function compareCandidates(a, b) {
  return (STATE_RANK[b.state] ?? 0) - (STATE_RANK[a.state] ?? 0)
    || (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0)
    || b.noveltyScore - a.noveltyScore
    || b.corroborationScore - a.corroborationScore
    || a.id.localeCompare(b.id);
}

function boundedProduct(optionSets, hardMax) {
  let items = [[]];
  for (const options of optionSets) {
    const next = [];
    for (const prefix of items) {
      for (const option of options) {
        if (next.length >= hardMax) break;
        next.push([...prefix, option]);
      }
      if (next.length >= hardMax) break;
    }
    items = next;
    if (!items.length) break;
  }
  return items;
}

function pushMap(map, key, value) {
  const values = map.get(key) ?? [];
  values.push(value);
  map.set(key, values);
}

function boundedInteger(value, fallback, min, max) {
  const number = Number(value ?? fallback);
  return Number.isInteger(number) ? Math.max(min, Math.min(max, number)) : fallback;
}

function boundedNumber(value, fallback, min, max) {
  const number = Number(value ?? fallback);
  return Number.isFinite(number) ? Math.max(min, Math.min(max, number)) : fallback;
}

function clamp01(value) {
  return Number.isFinite(value) ? Math.max(0, Math.min(1, value)) : 0;
}

function round3(value) {
  return Math.round(value * 1000) / 1000;
}

function digest(value) {
  return sha256(String(value)).slice(0, 24);
}
