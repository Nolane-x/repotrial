import test from 'node:test';
import assert from 'node:assert/strict';
import { planAdaptiveExperiments } from '../src/experiments/planner.mjs';
import { getExperimentTemplate, validateExperimentScenario } from '../src/experiments/templates.mjs';

function candidate(name = 'postinstall', packagePath = 'package.json') {
  return {
    kind: 'package-script',
    packagePath,
    name,
    command: `node ${name}.mjs`,
    workingDirectory: '.'
  };
}

function partialReasoning(overrides = {}) {
  const hypothesis = {
    id: 'credential-exfiltration',
    state: 'UNKNOWN',
    severity: 'critical',
    confidence: 0.32,
    missingStages: ['secret-source', 'network-egress'],
    ...overrides.hypothesis
  };
  const attackPath = {
    id: 'path:credential',
    hypothesisId: hypothesis.id,
    severity: hypothesis.severity,
    viability: 'PARTIAL',
    confidence: hypothesis.confidence,
    missingStages: [...hypothesis.missingStages],
    stages: [
      { id: 'secret-source', label: 'Secret access', capabilities: ['secret-access'], satisfied: false, evidenceIds: [] },
      { id: 'execution-control', label: 'Execution', capabilities: ['shell-exec'], satisfied: true, evidenceIds: ['ev:exec'] },
      { id: 'network-egress', label: 'Network egress', capabilities: ['network-egress'], satisfied: false, evidenceIds: [] }
    ],
    ...overrides.attackPath
  };
  return {
    schemaVersion: 'repotrial.reasoning.v1',
    hypotheses: [hypothesis],
    attackPaths: [attackPath]
  };
}

test('planner deterministically targets a critical partial credential path', () => {
  const input = { reasoning: partialReasoning(), candidates: [candidate()] };
  const first = planAdaptiveExperiments(input);
  const second = planAdaptiveExperiments(input);
  assert.deepEqual(first, second);
  assert.equal(first.schemaVersion, 'repotrial.experiment-plan.v1');
  assert.equal(first.experiments.length, 1);
  assert.equal(first.experiments[0].templateId, 'secret-egress-canary-v1');
  assert.equal(first.experiments[0].hypothesisId, 'credential-exfiltration');
  assert.equal(first.experiments[0].attackPathId, 'path:credential');
  assert.deepEqual(first.experiments[0].targetStageIds, ['network-egress', 'secret-source']);
  assert.ok(first.experiments[0].id.startsWith('exp:'));
});

test('planner does not target viable or blocked paths', () => {
  const base = partialReasoning();
  const reasoning = {
    ...base,
    hypotheses: [
      base.hypotheses[0],
      { ...base.hypotheses[0], id: 'already-viable', state: 'PROVEN', missingStages: [] },
      { ...base.hypotheses[0], id: 'already-blocked', state: 'REFUTED', missingStages: ['network-egress'] }
    ],
    attackPaths: [
      base.attackPaths[0],
      { ...base.attackPaths[0], id: 'path:viable', hypothesisId: 'already-viable', viability: 'VIABLE', missingStages: [] },
      { ...base.attackPaths[0], id: 'path:blocked', hypothesisId: 'already-blocked', viability: 'BLOCKED', missingStages: ['network-egress'] }
    ]
  };
  const plan = planAdaptiveExperiments({ reasoning, candidates: [candidate()] });
  assert.deepEqual(plan.experiments.map((item) => item.hypothesisId), ['credential-exfiltration']);
});

test('planner prioritizes higher severity and smaller epistemic gaps while enforcing budgets', () => {
  const critical = partialReasoning();
  const highHypothesis = {
    id: 'unapproved-destructive-action',
    state: 'UNKNOWN',
    severity: 'high',
    confidence: 0.1,
    missingStages: ['destructive-capability']
  };
  const highPath = {
    id: 'path:destructive',
    hypothesisId: highHypothesis.id,
    severity: 'high',
    viability: 'PARTIAL',
    confidence: 0.1,
    missingStages: ['destructive-capability'],
    stages: [{ id: 'destructive-capability', capabilities: ['destructive-action'], satisfied: false, evidenceIds: [] }]
  };
  const reasoning = {
    schemaVersion: 'repotrial.reasoning.v1',
    hypotheses: [...critical.hypotheses, highHypothesis],
    attackPaths: [...critical.attackPaths, highPath]
  };
  const plan = planAdaptiveExperiments({
    reasoning,
    candidates: [candidate('postinstall'), candidate('prepare')],
    maxExperiments: 2,
    maxPerCandidate: 1
  });
  assert.equal(plan.experiments.length, 2);
  assert.equal(plan.budget.maxExperiments, 2);
  assert.equal(plan.budget.maxPerCandidate, 1);
  assert.equal(new Set(plan.experiments.map((item) => item.candidate.id)).size, 2);
  assert.equal(plan.experiments[0].severity, 'critical');
});

test('planner returns no execution work when no runtime candidate exists', () => {
  const plan = planAdaptiveExperiments({ reasoning: partialReasoning(), candidates: [] });
  assert.deepEqual(plan.experiments, []);
  assert.equal(plan.summary.addressablePathCount, 0);
});

test('experiment templates are internal, bounded, and contain no canary values', () => {
  const template = getExperimentTemplate('secret-egress-canary-v1');
  assert.equal(template.id, 'secret-egress-canary-v1');
  assert.ok(template.envKeys.includes('OPENAI_API_KEY'));
  assert.ok(template.envKeys.length <= 8);
  assert.equal('envValues' in template, false);
  assert.equal(JSON.stringify(template).includes('sk-'), false);
});

test('scenario validation rejects arbitrary env values and sentinel traversal', () => {
  assert.throws(() => validateExperimentScenario({
    templateId: 'secret-egress-canary-v1',
    envKeys: ['OPENAI_API_KEY'],
    env: { OPENAI_API_KEY: 'real-value-must-not-be-accepted' },
    sentinelPaths: []
  }), /arbitrary environment values/i);

  assert.throws(() => validateExperimentScenario({
    templateId: 'filesystem-sentinel-v1',
    envKeys: [],
    sentinelPaths: ['../host-target']
  }), /sentinel/i);
});
