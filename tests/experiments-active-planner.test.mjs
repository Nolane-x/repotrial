import test from 'node:test';
import assert from 'node:assert/strict';
import { planActiveExperiments } from '../src/experiments/active-planner.mjs';
import { getThreatRegistry } from '../src/reasoning/threat-registry.mjs';

function chain(id, overrides = {}) {
  return {
    id,
    threatId: overrides.threatId ?? 'credential-exfiltration',
    severity: overrides.severity ?? 'critical',
    state: overrides.state ?? 'PARTIAL',
    missingStages: overrides.missingStages ?? ['network-egress'],
    stages: overrides.stages ?? [
      { id: 'secret-source', satisfied: true, confidence: 0.96, direct: true, anyOf: ['secret-access'], selectedCapability: 'secret-access' },
      { id: 'execution-control', satisfied: true, confidence: 0.96, direct: true, anyOf: ['shell-exec'], selectedCapability: 'shell-exec' },
      { id: 'network-egress', satisfied: false, confidence: 0, direct: false, anyOf: ['network-egress'], selectedCapability: null }
    ],
    score: overrides.score ?? { rank: 700, breakdown: { confidenceFloor: 0.4 } }
  };
}

const candidates = [
  { kind: 'package-script', packagePath: 'package.json', name: 'postinstall', command: 'node setup.mjs', workingDirectory: '.' },
  { kind: 'package-script', packagePath: 'tools/package.json', name: 'prepare', command: 'node prepare.mjs', workingDirectory: 'tools' }
];

test('planner favors a stage shared by multiple critical chains over a redundant narrow probe', () => {
  const causalReasoning = {
    chains: [
      chain('c1'),
      chain('c2', { threatId: 'lifecycle-ci-credential-abuse', missingStages: ['credential-or-sink'], stages: [
        { id: 'lifecycle-execution', satisfied: true, confidence: 0.96, direct: true, anyOf: ['dependency-execution'], selectedCapability: 'dependency-execution' },
        { id: 'ci-context', satisfied: true, confidence: 0.65, direct: false, anyOf: ['ci-context-control'], selectedCapability: 'ci-context-control' },
        { id: 'credential-or-sink', satisfied: false, confidence: 0, direct: false, anyOf: ['network-egress', 'secret-access'], selectedCapability: null }
      ] }),
      chain('c3', { threatId: 'unapproved-destructive-action', severity: 'high', missingStages: ['destructive-capability'], stages: [
        { id: 'destructive-capability', satisfied: false, confidence: 0, direct: false, anyOf: ['destructive-action'], selectedCapability: null },
        { id: 'execution-control', satisfied: true, confidence: 0.96, direct: true, anyOf: ['shell-exec'], selectedCapability: 'shell-exec' }
      ] })
    ]
  };
  const plan = planActiveExperiments({ causalReasoning, registry: getThreatRegistry(), candidates, maxExperiments: 3, maxPerCandidate: 2 });
  assert.ok(plan.experiments.length > 0);
  assert.equal(plan.experiments[0].templateId, 'secret-egress-canary-v1');
  assert.equal(plan.experiments[0].score.breakdown.chainCentrality > 0.5, true);
});

test('planner exposes a complete auditable score breakdown and stable receipt', () => {
  const input = { causalReasoning: { chains: [chain('c1')] }, registry: getThreatRegistry(), candidates, maxExperiments: 2 };
  const a = planActiveExperiments(input);
  const b = planActiveExperiments({ ...input, candidates: [...candidates].reverse() });
  assert.deepEqual(a, b);
  assert.match(a.receipt, /^[a-f0-9]{64}$/);
  const breakdown = a.experiments[0].score.breakdown;
  for (const key of ['threatImpact', 'uncertainty', 'chainCentrality', 'discriminationPower', 'expectedEvidenceStrength', 'executionCost', 'redundancyPenalty']) {
    assert.equal(typeof breakdown[key], 'number', key);
  }
});

test('global and per-candidate budgets are bounded', () => {
  const chains = Array.from({ length: 20 }, (_, index) => chain(`c${index}`));
  const plan = planActiveExperiments({ causalReasoning: { chains }, registry: getThreatRegistry(), candidates, maxExperiments: 2, maxPerCandidate: 1 });
  assert.equal(plan.experiments.length <= 2, true);
  const counts = new Map();
  for (const experiment of plan.experiments) counts.set(experiment.candidate.id, (counts.get(experiment.candidate.id) ?? 0) + 1);
  assert.equal([...counts.values()].every((count) => count <= 1), true);
});

test('no runtime candidates produces an explicit non-executing plan reason', () => {
  const plan = planActiveExperiments({ causalReasoning: { chains: [chain('c1')] }, registry: getThreatRegistry(), candidates: [] });
  assert.deepEqual(plan.experiments, []);
  assert.equal(plan.summary.reason, 'no-runtime-candidates');
});

test('planner only targets PARTIAL chains and never turns NOT_OBSERVED into negative evidence', () => {
  const plan = planActiveExperiments({
    causalReasoning: { chains: [chain('proven', { state: 'PROVEN' }), chain('partial')] },
    registry: getThreatRegistry(), candidates,
    observations: [{ state: 'NOT_OBSERVED', targetCapability: 'network-egress' }]
  });
  assert.equal(plan.summary.addressableChainCount, 1);
  assert.equal(Object.hasOwn(plan, 'negativeEvidence'), false);
});
