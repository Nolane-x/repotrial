import { sha256, stableStringify } from '../core/hash.mjs';
import { scoreCausalChain, severityRank } from './causal-score.mjs';
import { validateThreatDefinitions } from './threat-registry.mjs';

const DEFAULT_MAX_DEPTH = 8;
const HARD_MAX_DEPTH = 16;
const DEFAULT_MAX_CHAINS = 64;
const HARD_MAX_CHAINS = 256;
const HARD_MAX_VARIANTS_PER_THREAT = 64;
const CONFIDENCE_WEIGHT = Object.freeze({ high: 0.96, 'external-evidence-anchored': 0.9, 'external-evidence': 0.76, medium: 0.65, low: 0.45 });

export function synthesizeCausalAttackChains(input = {}) {
  const registry = normalizeRegistry(input.registry);
  const graph = input.causalGraph && typeof input.causalGraph === 'object' ? input.causalGraph : { nodes: [], edges: [] };
  const maxDepth = boundedInteger(input.maxDepth, DEFAULT_MAX_DEPTH, 1, HARD_MAX_DEPTH);
  const maxChains = boundedInteger(input.maxChains, DEFAULT_MAX_CHAINS, 1, HARD_MAX_CHAINS);
  const coverage = normalizeCoverage(input.coverage);
  const index = indexGraph(graph);
  const safeguardIds = new Set(index.safeguards.map((item) => item.safeguardId).filter(Boolean));
  const chains = [];
  let depthTruncatedThreatCount = 0;
  let variantTruncatedThreatCount = 0;

  for (const definition of registry.definitions) {
    const orderedStages = [...definition.stages].sort((a, b) => a.order - b.order || a.id.localeCompare(b.id));
    if (orderedStages.length > maxDepth) {
      depthTruncatedThreatCount += 1;
      continue;
    }
    const stageOptions = orderedStages.map((stage) => stageVariants(stage, index));
    const combinations = boundedProduct(stageOptions, HARD_MAX_VARIANTS_PER_THREAT);
    if (combinations.truncated) variantTruncatedThreatCount += 1;

    for (const selection of combinations.items) {
      const stages = selection.map((variant, stageIndex) => buildStageResult(orderedStages[stageIndex], variant, index));
      const missingStages = stages.filter((stage) => !stage.satisfied && !stage.refuted).map((stage) => stage.id);
      const refutedStages = stages.filter((stage) => !stage.satisfied && stage.refuted).map((stage) => stage.id);
      const supportingEvidenceIds = uniqueSorted(stages.flatMap((stage) => stage.evidenceIds));
      const refutingEvidenceIds = uniqueSorted(stages.flatMap((stage) => stage.refutingEvidenceIds));
      const selectedContradictions = uniqueSorted(stages.flatMap((stage) => stage.contradictionEvidenceIds));
      const safeguardContradictions = definition.mitigatedBy.filter((id) => safeguardIds.has(id)).map((id) => `safeguard:${id}`);
      const contradictions = uniqueSorted([...selectedContradictions, ...safeguardContradictions]);
      const allSatisfied = stages.every((stage) => stage.satisfied);
      let state;
      if (allSatisfied) {
        state = stages.every((stage) => stage.direct) ? 'PROVEN' : 'SUPPORTED';
        if (contradictions.length) state = 'CONTRADICTED';
      } else if (refutedStages.length) {
        state = 'BLOCKED';
      } else {
        state = 'PARTIAL';
      }
      const semanticIdentity = {
        threatId: definition.id,
        stages: stages.map((stage) => ({ id: stage.id, selectedCapability: stage.selectedCapability }))
      };
      const chain = {
        id: `chain:${digest(stableStringify(semanticIdentity))}`,
        threatId: definition.id,
        title: definition.title,
        category: definition.category,
        severity: definition.severity,
        state,
        stages,
        missingStages,
        refutedStages,
        supportingEvidenceIds,
        refutingEvidenceIds,
        contradictions
      };
      chain.score = scoreCausalChain({ ...chain, coverage });
      chains.push(chain);
    }
  }

  const pruned = pruneDominated(chains);
  pruned.sort(compareChains);
  const selected = pruned.slice(0, maxChains);
  const body = {
    schemaVersion: 'repotrial.causal-reasoning.v1',
    registryReceipt: registry.receipt,
    graphReceipt: typeof graph.receipt === 'string' ? graph.receipt : sha256(stableStringify(graph)),
    limits: {
      maxDepth,
      hardMaxDepth: HARD_MAX_DEPTH,
      maxChains,
      hardMaxChains: HARD_MAX_CHAINS,
      hardMaxVariantsPerThreat: HARD_MAX_VARIANTS_PER_THREAT
    },
    chains: selected,
    summary: buildSummary(selected, {
      synthesizedBeforePruning: chains.length,
      synthesizedAfterPruning: pruned.length,
      truncatedByTopK: pruned.length > selected.length,
      depthTruncatedThreatCount,
      variantTruncatedThreatCount
    })
  };
  return { ...body, receipt: sha256(stableStringify(body)) };
}

function normalizeRegistry(value) {
  if (value?.schemaVersion === 'repotrial.threat-registry.v1' && Array.isArray(value.definitions)) {
    return validateThreatDefinitions(value.definitions);
  }
  if (Array.isArray(value)) return validateThreatDefinitions(value);
  return validateThreatDefinitions([]);
}

function indexGraph(graph) {
  const nodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  const edges = Array.isArray(graph.edges) ? graph.edges : [];
  const nodeById = new Map(nodes.filter((node) => node?.id).map((node) => [node.id, node]));
  const capabilityByName = new Map();
  const evidenceById = new Map();
  const safeguards = [];
  for (const node of nodes) {
    if (node?.type === 'CAPABILITY' && typeof node.capability === 'string') capabilityByName.set(node.capability, node);
    if (node?.type === 'EVIDENCE' && node.id) evidenceById.set(node.id, node);
    if (node?.type === 'SAFEGUARD') safeguards.push(node);
  }
  const supports = new Map();
  const refutes = new Map();
  for (const edge of edges) {
    const target = nodeById.get(edge?.to);
    if (!target || target.type !== 'CAPABILITY') continue;
    if (edge.relation === 'SUPPORTS') pushMap(supports, target.capability, edge.from);
    if (edge.relation === 'REFUTES') pushMap(refutes, target.capability, edge.from);
  }
  for (const values of supports.values()) values.sort();
  for (const values of refutes.values()) values.sort();
  return { nodeById, capabilityByName, evidenceById, supports, refutes, safeguards };
}

function stageVariants(stage, index) {
  const observed = stage.anyOf.filter((capability) => index.capabilityByName.get(capability)?.observed === true);
  if (!observed.length) return [{ selectedCapability: null }];
  return observed.sort().map((selectedCapability) => ({ selectedCapability }));
}

function buildStageResult(stage, variant, index) {
  const selectedCapability = variant.selectedCapability;
  const evidenceIds = selectedCapability ? uniqueSorted(index.supports.get(selectedCapability) ?? []) : [];
  const refutingByCapability = stage.anyOf.map((capability) => ({ capability, ids: uniqueSorted(index.refutes.get(capability) ?? []) }));
  const refuted = !selectedCapability && stage.anyOf.length > 0 && refutingByCapability.every((item) => item.ids.length > 0);
  const selectedRefuting = selectedCapability ? uniqueSorted(index.refutes.get(selectedCapability) ?? []) : [];
  const refutingEvidenceIds = uniqueSorted(refutingByCapability.flatMap((item) => item.ids));
  const supportScores = evidenceIds.map((id) => evidenceConfidence(index.evidenceById.get(id)));
  const direct = evidenceIds.length > 0 && evidenceIds.some((id) => directEvidence(index.evidenceById.get(id)));
  return {
    id: stage.id,
    label: stage.label,
    order: stage.order,
    anyOf: [...stage.anyOf],
    selectedCapability,
    satisfied: Boolean(selectedCapability),
    refuted,
    confidence: supportScores.length ? Math.max(...supportScores) : refuted ? refutingConfidence(refutingEvidenceIds, index) : 0,
    direct,
    evidenceIds,
    refutingEvidenceIds,
    contradictionEvidenceIds: selectedRefuting
  };
}

function refutingConfidence(ids, index) {
  const scores = ids.map((id) => {
    const value = Number(index.evidenceById.get(id)?.confidence ?? 0);
    return Number.isFinite(value) ? clamp01(value) : 0;
  });
  return scores.length ? Math.min(...scores) : 0;
}

function evidenceConfidence(node) {
  if (!node) return 0;
  if (typeof node.confidence === 'number') return clamp01(node.confidence);
  return CONFIDENCE_WEIGHT[node.confidence] ?? 0.55;
}

function directEvidence(node) {
  return node?.polarity !== 'NEGATIVE' && node?.status === 'proven' && node?.confidence === 'high';
}

function boundedProduct(optionSets, hardMax) {
  let items = [[]];
  let truncated = false;
  for (const options of optionSets) {
    const next = [];
    for (const prefix of items) {
      for (const option of options) {
        if (next.length >= hardMax) {
          truncated = true;
          break;
        }
        next.push([...prefix, option]);
      }
      if (next.length >= hardMax) break;
    }
    items = next;
    if (!items.length) break;
  }
  return { items, truncated };
}

function pruneDominated(chains) {
  const byIdentity = new Map();
  for (const chain of chains) {
    const key = stableStringify({
      threatId: chain.threatId,
      selectedCapabilities: chain.stages.map((stage) => stage.selectedCapability),
      state: chain.state,
      missingStages: chain.missingStages,
      refutedStages: chain.refutedStages,
      contradictions: chain.contradictions
    });
    const existing = byIdentity.get(key);
    if (!existing || compareChains(chain, existing) < 0) byIdentity.set(key, chain);
  }
  return [...byIdentity.values()];
}

function compareChains(a, b) {
  return b.score.rank - a.score.rank
    || severityRank(b.severity) - severityRank(a.severity)
    || stateRank(b.state) - stateRank(a.state)
    || a.threatId.localeCompare(b.threatId)
    || a.id.localeCompare(b.id);
}

function stateRank(state) {
  return ({ PROVEN: 5, SUPPORTED: 4, CONTRADICTED: 3, PARTIAL: 2, BLOCKED: 1 })[state] ?? 0;
}

function buildSummary(chains, metadata) {
  const stateCounts = Object.fromEntries(['PROVEN', 'SUPPORTED', 'CONTRADICTED', 'PARTIAL', 'BLOCKED'].map((state) => [state, 0]));
  for (const chain of chains) stateCounts[chain.state] = (stateCounts[chain.state] ?? 0) + 1;
  const active = chains.filter((chain) => ['PROVEN', 'SUPPORTED', 'CONTRADICTED'].includes(chain.state));
  return {
    chainCount: chains.length,
    activeChainCount: active.length,
    highImpactActiveChainCount: active.filter((chain) => ['high', 'critical'].includes(chain.severity)).length,
    stateCounts,
    ...metadata
  };
}

function pushMap(map, key, value) {
  const values = map.get(key) ?? [];
  values.push(value);
  map.set(key, values);
}

function uniqueSorted(values) {
  return [...new Set((Array.isArray(values) ? values : []).map(String))].sort();
}

function normalizeCoverage(value) {
  return value && typeof value === 'object'
    ? { ratio: clamp01(Number(value.ratio ?? 0)), complete: Boolean(value.complete) }
    : { ratio: 0, complete: false };
}

function boundedInteger(value, fallback, min, max) {
  const number = Number(value ?? fallback);
  return Number.isInteger(number) ? Math.max(min, Math.min(max, number)) : fallback;
}

function clamp01(value) {
  return Number.isFinite(value) ? Math.min(1, Math.max(0, value)) : 0;
}

function digest(value) {
  return sha256(String(value)).slice(0, 24);
}
