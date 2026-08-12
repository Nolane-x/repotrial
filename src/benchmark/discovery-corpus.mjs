import { sha256, stableStringify } from '../core/hash.mjs';
import { discoverThreatHypotheses } from '../reasoning/hypothesis-discovery.mjs';
import { getThreatRegistry } from '../reasoning/threat-registry.mjs';

const CASES = Object.freeze([
  positive('prompt-egress', ['instruction-control', 'network-egress']),
  positive('approval-persistent-write', ['approval-bypass', 'filesystem-write']),
  positive('memory-egress', ['memory-write', 'network-egress']),
  positive('secret-persistent-write', ['secret-access', 'filesystem-write']),
  positive('delegation-egress', ['agent-delegation', 'network-egress']),
  benign('single-control', ['instruction-control']),
  benign('single-execution', ['shell-exec']),
  benign('single-sink', ['network-egress']),
  realmCase('mixed-production-benchmark', [
    { capability: 'instruction-control', realm: 'production', evidenceId: 'evidence:prod-control', path: 'src/agent.mjs' },
    { capability: 'network-egress', realm: 'benchmark', evidenceId: 'evidence:bench-egress', path: 'tests/adversarial-corpus/egress/package.json' }
  ], 'mixed'),
  realmCase('benchmark-only', [
    { capability: 'instruction-control', realm: 'benchmark', evidenceId: 'evidence:bench-shared', path: 'tests/adversarial-corpus/prompt/AGENTS.md' },
    { capability: 'network-egress', realm: 'benchmark', evidenceId: 'evidence:bench-shared', path: 'tests/adversarial-corpus/prompt/AGENTS.md' }
  ], 'non-production')
]);

export function runDiscoveryBenchmark(options = {}) {
  const registry = options.registry ?? getThreatRegistry();
  const details = CASES.map((entry) => evaluateCase(entry, registry));
  const positives = details.filter((entry) => entry.kind === 'positive');
  const benignCases = details.filter((entry) => entry.kind === 'benign');
  const realmCases = details.filter((entry) => entry.kind === 'realm');
  const allPromotable = details.flatMap((entry) => entry.promotable.map((candidate) => ({ entry, candidate })));
  const correctPromotable = allPromotable.filter(({ entry, candidate }) =>
    entry.kind === 'positive' && entry.expectedKey === capabilityKey(candidate.capabilities)).length;

  const metrics = {
    novelCandidateRecall: ratio(positives.filter((entry) => entry.expectedFound).length, positives.length),
    promotablePrecision: ratio(correctPromotable, allPromotable.length),
    benignProductionFalsePositiveRate: ratio(benignCases.filter((entry) => entry.promotable.length > 0).length, benignCases.length),
    realmIsolationAccuracy: ratio(realmCases.filter((entry) => entry.realmIsolated).length, realmCases.length),
    deterministicReplayRatio: ratio(details.filter((entry) => entry.deterministicReplay).length, details.length)
  };
  const body = {
    schemaVersion: 'repotrial.discovery-benchmark.v1',
    caseCount: details.length,
    metrics,
    cases: details.map(({ result: _result, replay: _replay, ...entry }) => entry),
    thresholds: {
      novelCandidateRecall: 0.95,
      promotablePrecision: 0.95,
      benignProductionFalsePositiveRate: 0.05,
      realmIsolationAccuracy: 1,
      deterministicReplayRatio: 1
    }
  };
  return { ...body, receipt: sha256(stableStringify(body)) };
}

export function getDiscoveryBenchmarkCases() {
  return structuredClone(CASES);
}

function evaluateCase(entry, registry) {
  const input = buildInput(entry.observations, registry);
  const result = discoverThreatHypotheses(input);
  const replay = discoverThreatHypotheses({
    ...input,
    causalGraph: { nodes: [...input.causalGraph.nodes].reverse(), edges: [...input.causalGraph.edges].reverse() }
  });
  const promotable = result.candidates.filter((candidate) => candidate.state === 'PROMOTABLE');
  const expectedKey = entry.expectedCapabilities ? capabilityKey(entry.expectedCapabilities) : null;
  const expectedFound = expectedKey ? result.candidates.some((candidate) => capabilityKey(candidate.capabilities) === expectedKey) : true;
  const realmIsolated = entry.kind !== 'realm' ? true : entry.realmExpectation === 'mixed'
    ? result.candidates.every((candidate) => candidate.realmAssessment?.productionRelevant === false)
    : result.candidates.every((candidate) => candidate.realmAssessment?.productionRelevant === false && candidate.state !== 'PROMOTABLE');
  return {
    id: entry.id,
    kind: entry.kind,
    expectedKey,
    expectedFound,
    candidateCount: result.candidates.length,
    promotableCount: promotable.length,
    promotable,
    realmIsolated,
    deterministicReplay: result.receipt === replay.receipt,
    result,
    replay
  };
}

function buildInput(observations, registry) {
  const nodes = [];
  const edges = [];
  const seenEvidence = new Set();
  const byEvidenceId = {};
  for (const observation of observations) {
    if (!seenEvidence.has(observation.evidenceId)) {
      seenEvidence.add(observation.evidenceId);
      nodes.push({ id: observation.evidenceId, type: 'EVIDENCE' });
      byEvidenceId[observation.evidenceId] = {
        realms: [observation.realm],
        anchors: [{ path: observation.path }]
      };
    }
    const capabilityNodeId = `capability:${observation.capability}`;
    if (!nodes.some((node) => node.id === capabilityNodeId)) {
      nodes.push({ id: capabilityNodeId, type: 'CAPABILITY', capability: observation.capability, observed: true });
    }
    edges.push({ from: observation.evidenceId, to: capabilityNodeId, relation: 'SUPPORTS' });
  }
  return { causalGraph: { nodes, edges }, registry, realmIndex: { byEvidenceId } };
}

function positive(id, capabilities) {
  return Object.freeze({
    id,
    kind: 'positive',
    expectedCapabilities: capabilities,
    observations: capabilities.map((capability) => ({
      capability,
      realm: 'production',
      evidenceId: `evidence:${id}:shared`,
      path: `src/${id}.mjs`
    }))
  });
}

function benign(id, capabilities) {
  return Object.freeze({
    id,
    kind: 'benign',
    expectedCapabilities: null,
    observations: capabilities.map((capability, index) => ({
      capability,
      realm: 'production',
      evidenceId: `evidence:${id}:${index}`,
      path: `src/${id}-${index}.mjs`
    }))
  });
}

function realmCase(id, observations, realmExpectation) {
  return Object.freeze({ id, kind: 'realm', expectedCapabilities: null, observations, realmExpectation });
}

function capabilityKey(capabilities) {
  return (Array.isArray(capabilities) ? capabilities : []).join('>');
}

function ratio(numerator, denominator) {
  if (!denominator) return 1;
  return Math.round((numerator / denominator) * 1_000_000) / 1_000_000;
}
