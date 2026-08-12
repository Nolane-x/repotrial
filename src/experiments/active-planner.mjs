import { sha256, stableStringify } from '../core/hash.mjs';
import { getExperimentTemplate, validateExperimentScenario } from './templates.mjs';

const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });
const STRENGTH = Object.freeze({ contextual: 0.45, strong: 0.8, direct: 1 });
const EVIDENCE_STRENGTH = Object.freeze({ contextual: 0.5, strong: 0.82, direct: 0.96 });
const TEMPLATE_COST = Object.freeze({
  'ci-context-trigger-v1': 0.7,
  'filesystem-sentinel-v1': 0.9,
  'secret-egress-canary-v1': 1.2,
  'memory-persistence-v1': 1.5,
  'approval-boundary-contrast-v1': 1.25,
  'lifecycle-ci-episode-v1': 1.35
});
const DEFAULT_MAX_EXPERIMENTS = 6;
const DEFAULT_MAX_PER_CANDIDATE = 2;
const HARD_MAX_EXPERIMENTS = 32;
const HARD_MAX_PER_CANDIDATE = 8;

export function planActiveExperiments(input = {}) {
  const chains = Array.isArray(input.causalReasoning?.chains) ? input.causalReasoning.chains : [];
  const registry = normalizeRegistry(input.registry);
  const candidates = normalizeCandidates(input.candidates);
  const maxExperiments = boundedInteger(input.maxExperiments, DEFAULT_MAX_EXPERIMENTS, 0, HARD_MAX_EXPERIMENTS);
  const maxPerCandidate = boundedInteger(input.maxPerCandidate, DEFAULT_MAX_PER_CANDIDATE, 0, HARD_MAX_PER_CANDIDATE);
  const threatById = new Map(registry.definitions.map((item) => [item.id, item]));
  const partialChains = chains.filter((chain) => chain?.state === 'PARTIAL');
  const targets = [];

  for (const chain of partialChains) {
    const definition = threatById.get(String(chain.threatId));
    if (!definition) continue;
    const stageById = new Map((chain.stages ?? []).map((stage) => [String(stage.id), stage]));
    for (const missingStageId of uniqueSorted(chain.missingStages)) {
      const hint = selectHint(definition, missingStageId);
      const template = hint ? getExperimentTemplate(hint.templateId) : null;
      if (!hint || !template) continue;
      const stage = stageById.get(missingStageId) ?? definition.stages.find((item) => item.id === missingStageId);
      targets.push({
        chain,
        threat: definition,
        stageId: missingStageId,
        targetCapabilities: uniqueSorted(stage?.anyOf ?? template.targetCapabilities ?? []),
        hint,
        template
      });
    }
  }

  targets.sort(compareTargets);
  const addressableChainIds = new Set(targets.map((item) => String(item.chain.id)));
  const chainWeights = buildChainWeights(targets);
  const totalAddressableWeight = [...addressableChainIds].reduce((sum, id) => sum + (chainWeights.get(id) ?? 1), 0);
  const templateChains = new Map();
  for (const target of targets) {
    const key = target.template.id;
    const set = templateChains.get(key) ?? new Set();
    set.add(String(target.chain.id));
    templateChains.set(key, set);
  }

  const summaryBase = {
    partialChainCount: partialChains.length,
    addressableChainCount: addressableChainIds.size,
    candidateCount: candidates.length,
    plannedExperimentCount: 0,
    reason: candidates.length ? (targets.length ? 'planned' : 'no-addressable-causal-gaps') : 'no-runtime-candidates'
  };

  if (!candidates.length || !targets.length || maxExperiments === 0 || maxPerCandidate === 0) {
    return finalize([], summaryBase, maxExperiments, maxPerCandidate);
  }

  const proposals = [];
  for (const target of targets) {
    const coveredChains = templateChains.get(target.template.id) ?? new Set();
    const coveredWeight = [...coveredChains].reduce((sum, id) => sum + (chainWeights.get(id) ?? 1), 0);
    const centrality = totalAddressableWeight > 0 ? coveredWeight / totalAddressableWeight : 0;
    for (const candidate of candidates) {
      proposals.push(buildProposal(target, candidate, {
        centrality,
        coveredChainIds: [...coveredChains].sort()
      }));
    }
  }
  proposals.sort(compareProposals);

  const selected = [];
  const perCandidate = new Map();
  const redundancy = new Map();
  const usedIds = new Set();
  const usedProbeKeys = new Set();

  while (selected.length < maxExperiments) {
    let best = null;
    for (const proposal of proposals) {
      if (usedIds.has(proposal.baseId)) continue;
      const probeKey = `${proposal.candidate.id}\0${proposal.templateId}`;
      if (usedProbeKeys.has(probeKey)) continue;
      const used = perCandidate.get(proposal.candidate.id) ?? 0;
      if (used >= maxPerCandidate) continue;
      const redundancyKey = `${proposal.candidate.id}\0${proposal.templateId}`;
      const repeats = redundancy.get(redundancyKey) ?? 0;
      const redundancyPenalty = 1 / (1 + (0.5 * repeats));
      const score = scoreProposal(proposal.scoreInputs, redundancyPenalty);
      const candidate = { ...proposal, score };
      if (!best || compareProposals(candidate, best) < 0) best = candidate;
    }
    if (!best) break;
    selected.push(stripInternal(best));
    usedIds.add(best.baseId);
    usedProbeKeys.add(`${best.candidate.id}\0${best.templateId}`);
    perCandidate.set(best.candidate.id, (perCandidate.get(best.candidate.id) ?? 0) + 1);
    const redundancyKey = `${best.candidate.id}\0${best.templateId}`;
    redundancy.set(redundancyKey, (redundancy.get(redundancyKey) ?? 0) + 1);
  }

  const summary = {
    ...summaryBase,
    plannedExperimentCount: selected.length,
    truncatedByBudget: proposals.length > selected.length && selected.length >= maxExperiments
  };
  return finalize(selected, summary, maxExperiments, maxPerCandidate);
}

function buildChainWeights(targets) {
  const weights = new Map();
  for (const target of targets) {
    const id = String(target.chain.id);
    // Information that can close a critical chain should count more than the
    // same observation on a lower-impact chain, while still giving every
    // addressable chain a non-zero contribution.
    const weight = 1 + severityRank(target.chain.severity ?? target.threat.severity);
    weights.set(id, Math.max(weights.get(id) ?? 0, weight));
  }
  return weights;
}

function buildProposal(target, candidate, context) {
  const scenario = validateExperimentScenario({
    templateId: target.template.id,
    envKeys: target.template.envKeys,
    sentinelPaths: target.template.sentinelPaths
  });
  const confidenceFloor = clamp01(Number(target.chain.score?.breakdown?.confidenceFloor ?? target.chain.confidence ?? 0));
  const scoreInputs = {
    threatImpact: severityRank(target.chain.severity ?? target.threat.severity) / 4,
    uncertainty: 1 - confidenceFloor,
    chainCentrality: clamp01(context.centrality),
    discriminationPower: STRENGTH[target.hint.strength] ?? STRENGTH.contextual,
    expectedEvidenceStrength: EVIDENCE_STRENGTH[target.hint.strength] ?? EVIDENCE_STRENGTH.contextual,
    executionCost: TEMPLATE_COST[target.template.id] ?? 1
  };
  const identity = {
    chainId: String(target.chain.id), stageId: target.stageId, templateId: target.template.id, candidateId: candidate.id
  };
  return {
    id: `aexp:${digest(stableStringify(identity))}`,
    baseId: stableStringify(identity),
    templateId: target.template.id,
    title: target.template.title,
    chainId: String(target.chain.id),
    threatId: String(target.chain.threatId),
    severity: normalizedSeverity(target.chain.severity ?? target.threat.severity),
    targetStageIds: [target.stageId],
    targetCapabilities: target.targetCapabilities,
    coveredChainIds: context.coveredChainIds,
    rationale: `Resolve causal stage ${target.stageId} in ${target.chain.threatId} with ${target.template.id}.`,
    candidate,
    scenario,
    scoreInputs,
    score: scoreProposal(scoreInputs, 1)
  };
}

function scoreProposal(input, redundancyPenalty) {
  // Execution cost is intentionally a soft penalty. A cheap probe that only
  // resolves a narrow low-impact gap must not outrank a slightly more costly
  // probe that discriminates several critical causal chains.
  const benefit = (0.26 * input.threatImpact)
    + (0.2 * input.uncertainty)
    + (0.22 * input.chainCentrality)
    + (0.14 * input.discriminationPower)
    + (0.18 * input.expectedEvidenceStrength);
  const executionEfficiency = 1 / (1 + (0.25 * Math.max(0, Number(input.executionCost) - 0.7)));
  const rank = round6(1000 * benefit * executionEfficiency * redundancyPenalty);
  return {
    rank,
    breakdown: {
      threatImpact: round6(input.threatImpact),
      uncertainty: round6(input.uncertainty),
      chainCentrality: round6(input.chainCentrality),
      discriminationPower: round6(input.discriminationPower),
      expectedEvidenceStrength: round6(input.expectedEvidenceStrength),
      executionCost: round6(input.executionCost),
      executionEfficiency: round6(executionEfficiency),
      redundancyPenalty: round6(redundancyPenalty)
    },
    interpretation: 'expected-epistemic-value-not-safety-probability'
  };
}

function finalize(experiments, summary, maxExperiments, maxPerCandidate) {
  const body = {
    schemaVersion: 'repotrial.active-experiment-plan.v1',
    plannerVersion: 'active-epistemic-v2',
    budget: { maxExperiments, maxPerCandidate, hardMaxExperiments: HARD_MAX_EXPERIMENTS, hardMaxPerCandidate: HARD_MAX_PER_CANDIDATE },
    experiments,
    summary
  };
  return { ...body, receipt: sha256(stableStringify(body)) };
}

function normalizeRegistry(value) {
  if (value?.schemaVersion === 'repotrial.threat-registry.v1' && Array.isArray(value.definitions)) return value;
  return { schemaVersion: 'repotrial.threat-registry.v1', definitions: [], receipt: sha256('[]') };
}

function normalizeCandidates(value) {
  if (!Array.isArray(value)) return [];
  const map = new Map();
  for (const item of value) {
    if (!item || typeof item !== 'object') continue;
    const identity = {
      kind: stringValue(item.kind, 'unknown'), packagePath: stringValue(item.packagePath, ''), name: stringValue(item.name, ''),
      command: stringValue(item.command, ''), workingDirectory: stringValue(item.workingDirectory, '.'), event: item.event ? String(item.event) : null
    };
    const candidate = {
      id: `candidate:${digest(stableStringify(identity))}`,
      kind: identity.kind, packagePath: identity.packagePath, name: identity.name, command: identity.command, workingDirectory: identity.workingDirectory,
      ...(identity.event ? { event: identity.event } : {})
    };
    map.set(candidate.id, candidate);
  }
  return [...map.values()].sort((a, b) => a.packagePath.localeCompare(b.packagePath) || a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
}

function selectHint(definition, stageId) {
  return (definition.experimentHints ?? [])
    .filter((hint) => hint.stageId === stageId)
    .sort((a, b) => (STRENGTH[b.strength] ?? 0) - (STRENGTH[a.strength] ?? 0) || a.templateId.localeCompare(b.templateId))[0] ?? null;
}

function compareTargets(a, b) {
  return severityRank(b.chain.severity ?? b.threat.severity) - severityRank(a.chain.severity ?? a.threat.severity)
    || String(a.chain.id).localeCompare(String(b.chain.id)) || a.stageId.localeCompare(b.stageId) || a.template.id.localeCompare(b.template.id);
}

function compareProposals(a, b) {
  return (b.score?.rank ?? 0) - (a.score?.rank ?? 0)
    || severityRank(b.severity) - severityRank(a.severity)
    || String(a.chainId).localeCompare(String(b.chainId))
    || String(a.templateId).localeCompare(String(b.templateId))
    || String(a.candidate?.id).localeCompare(String(b.candidate?.id));
}

function stripInternal(value) {
  const { baseId: _baseId, scoreInputs: _scoreInputs, ...publicValue } = value;
  return publicValue;
}

function severityRank(value) {
  return SEVERITY_RANK[normalizedSeverity(value)];
}

function normalizedSeverity(value) {
  const severity = String(value ?? 'info').toLowerCase();
  return severity in SEVERITY_RANK ? severity : 'info';
}

function uniqueSorted(values) {
  return [...new Set((Array.isArray(values) ? values : []).map(String))].sort();
}

function boundedInteger(value, fallback, min, max) {
  const number = Number(value ?? fallback);
  return Number.isInteger(number) ? Math.max(min, Math.min(max, number)) : fallback;
}

function clamp01(value) {
  return Number.isFinite(value) ? Math.min(1, Math.max(0, value)) : 0;
}

function round6(value) {
  return Math.round(value * 1_000_000) / 1_000_000;
}

function stringValue(value, fallback) {
  return value == null ? fallback : String(value);
}

function digest(value) {
  return sha256(String(value)).slice(0, 24);
}
