import { sha256, stableStringify } from '../core/hash.mjs';
import { reasonAboutEvidence } from './engine.mjs';
import { getThreatRegistry } from './threat-registry.mjs';
import { buildCausalSecurityGraph } from './causal-graph.mjs';
import { synthesizeCausalAttackChains } from './attack-synthesis.mjs';
import { buildEvidenceRealmIndex, assessChainRealm } from './evidence-realms.mjs';
import { discoverThreatHypotheses } from './hypothesis-discovery.mjs';
import { planActiveExperiments } from '../experiments/active-planner.mjs';

const MODES = new Set(['analyze', 'discover', 'active']);
const REALM_SCOPES = new Set(['all', 'production']);
const ACTIVE_STATES = new Set(['PROVEN', 'SUPPORTED']);

export function analyzeCausalEvidence(input = {}) {
  const mode = String(input.mode ?? 'analyze').toLowerCase();
  if (!MODES.has(mode)) throw new Error('Causal analysis mode must be analyze, discover, or active.');
  const realmScope = normalizeRealmScope(input.realmScope);
  const charges = Array.isArray(input.charges) ? input.charges : [];
  const safeguards = Array.isArray(input.safeguards) ? input.safeguards : [];
  const coverage = normalizeCoverage(input.coverage);
  const reasoning = input.reasoning ?? reasonAboutEvidence({
    charges,
    safeguards,
    coverage,
    providers: input.providers,
    negativeEvidence: input.negativeEvidence,
    invariants: input.invariants
  });
  const registry = input.registry ?? getThreatRegistry();
  const graph = buildCausalSecurityGraph({ reasoning, charges });
  const realms = buildEvidenceRealmIndex({ charges, reasoning });
  const baseCausalReasoning = synthesizeCausalAttackChains({
    registry,
    causalGraph: graph,
    coverage,
    maxDepth: input.maxDepth,
    maxChains: input.maxChains
  });
  const causalReasoning = withRealmAssessments(baseCausalReasoning, realms, graph);
  const discovery = mode === 'discover' || mode === 'active'
    ? discoverThreatHypotheses({
      causalGraph: graph,
      causalReasoning,
      registry,
      realmIndex: realms,
      maxCandidates: input.maxDiscoveredHypotheses,
      minNovelty: input.minDiscoveryNovelty
    })
    : null;
  const activePlan = mode === 'active'
    ? planActiveExperiments({
      causalReasoning,
      registry,
      candidates: input.candidates,
      maxExperiments: input.maxExperiments,
      maxPerCandidate: input.maxPerCandidate,
      observations: input.observations
    })
    : null;
  const body = {
    schemaVersion: 'repotrial.causal.v2',
    mode,
    realmScope,
    registry: {
      schemaVersion: registry.schemaVersion,
      receipt: registry.receipt,
      definitionCount: registry.definitions.length
    },
    realms,
    graph,
    reasoning: causalReasoning,
    ...(discovery ? { discovery } : {}),
    ...(activePlan ? { activePlan } : {}),
    summary: buildSummary(causalReasoning, activePlan, registry.definitions.length, discovery)
  };
  return { ...body, receipt: sha256(stableStringify(body)) };
}

export function buildCausalEpistemicDelta(before, after) {
  const beforeMap = chainMap(before?.reasoning?.chains);
  const afterMap = chainMap(after?.reasoning?.chains);
  const transitions = [];
  const newlyActive = [];
  const resolvedActive = [];
  for (const id of [...new Set([...beforeMap.keys(), ...afterMap.keys()])].sort()) {
    const a = beforeMap.get(id);
    const b = afterMap.get(id);
    if (!a || !b) continue;
    if (a.state === b.state) continue;
    const transition = { id, threatId: b.threatId ?? a.threatId, severity: b.severity ?? a.severity, from: a.state, to: b.state };
    transitions.push(transition);
    if (!ACTIVE_STATES.has(a.state) && ACTIVE_STATES.has(b.state)) newlyActive.push(transition);
    if (ACTIVE_STATES.has(a.state) && !ACTIVE_STATES.has(b.state)) resolvedActive.push(transition);
  }
  const body = {
    schemaVersion: 'repotrial.causal-epistemic-delta.v1',
    interpretation: 'knowledge-change-not-trust-change',
    transitions,
    newlyActive,
    resolvedActive,
    summary: {
      transitionCount: transitions.length,
      newlyActiveCount: newlyActive.length,
      resolvedActiveCount: resolvedActive.length
    }
  };
  return { ...body, receipt: sha256(stableStringify(body)) };
}

function withRealmAssessments(reasoning, realmIndex, graph) {
  const { receipt: _oldReceipt, ...base } = reasoning;
  const chains = (reasoning.chains ?? []).map((chain) => ({
    ...chain,
    realmAssessment: assessChainRealm(chain, realmIndex, graph)
  }));
  const active = chains.filter((chain) => ACTIVE_STATES.has(chain.state));
  const summary = {
    ...reasoning.summary,
    productionActiveChainCount: active.filter((chain) => chain.realmAssessment?.productionRelevant === true).length,
    nonProductionActiveChainCount: active.filter((chain) => chain.realmAssessment?.state === 'NON_PRODUCTION_ONLY').length,
    crossRealmUnprovenActiveChainCount: active.filter((chain) => chain.realmAssessment?.state === 'CROSS_REALM_UNPROVEN').length,
    unknownRealmActiveChainCount: active.filter((chain) => chain.realmAssessment?.state === 'UNKNOWN_REALM').length
  };
  const body = { ...base, chains, summary };
  return { ...body, receipt: sha256(stableStringify(body)) };
}

function buildSummary(reasoning, activePlan, registryThreatCount, discovery) {
  const chains = reasoning.chains ?? [];
  const active = chains.filter((item) => ACTIVE_STATES.has(item.state));
  const partial = chains.filter((item) => item.state === 'PARTIAL');
  const productionActive = active.filter((item) => item.realmAssessment?.productionRelevant === true);
  const maximumActiveSeverity = active
    .map((item) => item.severity)
    .sort((a, b) => severityRank(b) - severityRank(a))[0] ?? 'info';
  const maximumProductionActiveSeverity = productionActive
    .map((item) => item.severity)
    .sort((a, b) => severityRank(b) - severityRank(a))[0] ?? 'info';
  return {
    chainCount: chains.length,
    activeChainCount: active.length,
    productionActiveChainCount: productionActive.length,
    nonProductionActiveChainCount: active.filter((item) => item.realmAssessment?.state === 'NON_PRODUCTION_ONLY').length,
    crossRealmUnprovenActiveChainCount: active.filter((item) => item.realmAssessment?.state === 'CROSS_REALM_UNPROVEN').length,
    highImpactActiveChainCount: active.filter((item) => ['high', 'critical'].includes(item.severity)).length,
    highImpactProductionActiveChainCount: productionActive.filter((item) => ['high', 'critical'].includes(item.severity)).length,
    partialChainCount: partial.length,
    maximumActiveSeverity,
    maximumProductionActiveSeverity,
    plannedActiveExperimentCount: activePlan?.experiments?.length ?? 0,
    registryThreatCount,
    discoveredHypothesisCount: discovery?.candidates?.length ?? 0,
    promotableHypothesisCount: discovery?.candidates?.filter((item) => item.state === 'PROMOTABLE').length ?? 0
  };
}

function chainMap(chains) {
  return new Map((Array.isArray(chains) ? chains : []).filter((item) => typeof item?.id === 'string').map((item) => [item.id, item]));
}

function normalizeCoverage(value) {
  return value && typeof value === 'object'
    ? { ratio: clamp01(Number(value.ratio ?? 0)), complete: Boolean(value.complete) }
    : { ratio: 0, complete: false };
}

function normalizeRealmScope(value) {
  const scope = String(value ?? 'all').toLowerCase();
  if (!REALM_SCOPES.has(scope)) throw new Error('Causal realm scope must be all or production.');
  return scope;
}

function clamp01(value) {
  return Number.isFinite(value) ? Math.max(0, Math.min(1, value)) : 0;
}

function severityRank(value) {
  return ({ info: 0, low: 1, medium: 2, high: 3, critical: 4 })[String(value ?? '').toLowerCase()] ?? -1;
}
