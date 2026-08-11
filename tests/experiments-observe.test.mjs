import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { classifyExperimentObservation } from '../src/experiments/observe.mjs';
import { experimentObservationsToCharges } from '../src/experiments/evidence.mjs';
import { buildEpistemicDelta } from '../src/experiments/delta.mjs';
import { reasonAboutEvidence } from '../src/reasoning/engine.mjs';

const CANARY = 'rtx_super_secret_synthetic_value';
const CANARY_FP = createHash('sha256').update(CANARY).digest('hex');

function experiment(templateId = 'secret-egress-canary-v1') {
  return {
    id: `exp:${templateId}`,
    templateId,
    title: 'Synthetic experiment',
    hypothesisId: templateId === 'filesystem-sentinel-v1' ? 'unapproved-destructive-action' : 'credential-exfiltration',
    attackPathId: 'path:test',
    severity: 'critical',
    targetStageIds: ['secret-source', 'network-egress'],
    candidate: {
      id: 'candidate:test',
      kind: 'package-script',
      packagePath: 'package.json',
      name: 'postinstall',
      command: 'node install.mjs',
      workingDirectory: '.'
    }
  };
}

function run(overrides = {}) {
  return {
    status: 'completed',
    exitCode: 0,
    timedOut: false,
    outputTruncated: false,
    events: [],
    filesystemChanges: [],
    stdout: '',
    stderr: '',
    ...overrides
  };
}

function snapshot() {
  const content = '{\n  "scripts": {\n    "postinstall": "node install.mjs"\n  }\n}\n';
  return {
    files: [{ path: 'package.json', content, sha256: createHash('sha256').update(content).digest('hex') }]
  };
}

test('canary propagation into a network event is OBSERVED without persisting the raw canary', () => {
  const observation = classifyExperimentObservation({
    experiment: experiment(),
    baselineRun: run(),
    scenarioRun: run({
      events: [{ kind: 'network', api: 'request', target: `https://sink.invalid/?key=${CANARY}` }]
    }),
    canaries: [{ key: 'OPENAI_API_KEY', value: CANARY, fingerprint: CANARY_FP }],
    sentinelPaths: []
  });

  assert.equal(observation.state, 'OBSERVED');
  assert.equal(observation.signals.canaryNetworkPropagation, true);
  assert.equal(observation.signals.networkDeltaCount, 1);
  assert.deepEqual(observation.canaryFingerprints, [{ key: 'OPENAI_API_KEY', fingerprint: CANARY_FP }]);
  assert.equal(JSON.stringify(observation).includes(CANARY), false);
  assert.match(JSON.stringify(observation), /EXPERIMENT_CANARY/);
});

test('new network behavior without canary propagation is still direct positive network evidence', () => {
  const observation = classifyExperimentObservation({
    experiment: experiment('ci-context-trigger-v1'),
    baselineRun: run({ events: [{ kind: 'process', api: 'spawn', target: 'node baseline.mjs' }] }),
    scenarioRun: run({ events: [
      { kind: 'process', api: 'spawn', target: 'node baseline.mjs' },
      { kind: 'dns', api: 'lookup', target: 'telemetry.invalid' }
    ] }),
    canaries: [],
    sentinelPaths: []
  });
  assert.equal(observation.state, 'OBSERVED');
  assert.equal(observation.signals.networkDeltaCount, 1);
  assert.equal(observation.signals.canaryNetworkPropagation, false);
});

test('context-only process delta is TRIGGERED but does not invent a dangerous capability', () => {
  const observation = classifyExperimentObservation({
    experiment: experiment('ci-context-trigger-v1'),
    baselineRun: run(),
    scenarioRun: run({ events: [{ kind: 'process', api: 'spawn', target: 'node ci-only.mjs' }] }),
    canaries: [],
    sentinelPaths: []
  });
  assert.equal(observation.state, 'TRIGGERED');
  assert.equal(observation.signals.processDeltaCount, 1);

  const charges = experimentObservationsToCharges({ observations: [observation], snapshot: snapshot() });
  assert.equal(charges.length, 1);
  assert.equal(charges[0].ruleId, 'adaptive-ci-triggered-behavior');

  const reasoning = reasonAboutEvidence({ charges, safeguards: [], coverage: { ratio: 1, complete: true } });
  assert.equal(reasoning.summary.capabilityCount, 0);
});

test('NOT_OBSERVED creates neither a charge nor global negative evidence', () => {
  const observation = classifyExperimentObservation({
    experiment: experiment(),
    baselineRun: run(),
    scenarioRun: run(),
    canaries: [{ key: 'OPENAI_API_KEY', value: CANARY, fingerprint: CANARY_FP }],
    sentinelPaths: []
  });
  assert.equal(observation.state, 'NOT_OBSERVED');
  assert.equal('negativeEvidence' in observation, false);
  assert.deepEqual(experimentObservationsToCharges({ observations: [observation], snapshot: snapshot() }), []);
});

test('timeout without a positive signal is INCONCLUSIVE rather than NOT_OBSERVED', () => {
  const observation = classifyExperimentObservation({
    experiment: experiment(),
    baselineRun: run(),
    scenarioRun: run({ status: 'timeout', timedOut: true, exitCode: null }),
    canaries: [],
    sentinelPaths: []
  });
  assert.equal(observation.state, 'INCONCLUSIVE');
});

test('sentinel deletion becomes destructive positive evidence', () => {
  const sentinel = '.repotrial-experiment/sentinel-a.txt';
  const observation = classifyExperimentObservation({
    experiment: experiment('filesystem-sentinel-v1'),
    baselineRun: run(),
    scenarioRun: run({ filesystemChanges: [{ path: sentinel, change: 'deleted', before: { type: 'file' } }] }),
    canaries: [],
    sentinelPaths: [sentinel]
  });
  assert.equal(observation.state, 'OBSERVED');
  assert.equal(observation.signals.sentinelMutationCount, 1);

  const charges = experimentObservationsToCharges({ observations: [observation], snapshot: snapshot() });
  assert.equal(charges.some((charge) => charge.ruleId === 'adaptive-sentinel-destruction-observed'), true);
});

test('experiment secret-egress evidence closes the missing reasoning stages when execution is already proven', () => {
  const observation = classifyExperimentObservation({
    experiment: experiment(),
    baselineRun: run(),
    scenarioRun: run({ events: [{ kind: 'network', api: 'request', target: `https://sink.invalid/${CANARY}` }] }),
    canaries: [{ key: 'OPENAI_API_KEY', value: CANARY, fingerprint: CANARY_FP }],
    sentinelPaths: []
  });
  const experimentCharges = experimentObservationsToCharges({ observations: [observation], snapshot: snapshot() });
  const executionCharge = {
    ruleId: 'unrestricted-shell-capability',
    title: 'Unrestricted shell',
    severity: 'critical',
    status: 'proven',
    confidence: 'high',
    source: 'test',
    rationale: 'test',
    remediation: 'test',
    evidence: [{
      path: 'package.json', startLine: 3, endLine: 3, snippet: 'postinstall', fileSha256: 'sha',
      fingerprint: 'fp:exec', stableFingerprint: 'fp:exec', severity: 'critical'
    }]
  };
  const reasoning = reasonAboutEvidence({
    charges: [executionCharge, ...experimentCharges],
    safeguards: [],
    coverage: { ratio: 1, complete: true }
  });
  const hypothesis = reasoning.hypotheses.find((item) => item.id === 'credential-exfiltration');
  assert.equal(hypothesis.state, 'PROVEN');
  assert.deepEqual(hypothesis.missingStages, []);
});

test('epistemic delta records UNKNOWN to PROVEN and PARTIAL to VIABLE without calling it trust gain', () => {
  const initial = reasonAboutEvidence({
    charges: [{
      ruleId: 'unrestricted-shell-capability', title: 'Shell', severity: 'critical', status: 'proven', confidence: 'high', source: 'test',
      evidence: [{ path: 'package.json', startLine: 1, endLine: 1, snippet: 'shell', fileSha256: 'sha', fingerprint: 'a', stableFingerprint: 'a', severity: 'critical' }]
    }],
    safeguards: [], coverage: { ratio: 1, complete: true }
  });
  const final = reasonAboutEvidence({
    charges: [
      {
        ruleId: 'unrestricted-shell-capability', title: 'Shell', severity: 'critical', status: 'proven', confidence: 'high', source: 'test',
        evidence: [{ path: 'package.json', startLine: 1, endLine: 1, snippet: 'shell', fileSha256: 'sha', fingerprint: 'a', stableFingerprint: 'a', severity: 'critical' }]
      },
      {
        ruleId: 'adaptive-secret-egress-observed', title: 'Observed', severity: 'critical', status: 'proven', confidence: 'high', source: 'repotrial-experiment',
        evidence: [{ path: 'package.json', startLine: 1, endLine: 1, snippet: 'experiment', fileSha256: 'sha', fingerprint: 'b', stableFingerprint: 'b', severity: 'critical' }]
      }
    ],
    safeguards: [], coverage: { ratio: 1, complete: true }
  });
  const delta = buildEpistemicDelta(initial, final);
  const transition = delta.hypothesisTransitions.find((item) => item.id === 'credential-exfiltration');
  assert.equal(transition.from, 'UNKNOWN');
  assert.equal(transition.to, 'PROVEN');
  assert.equal(delta.attackPathTransitions.some((item) => item.hypothesisId === 'credential-exfiltration' && item.from === 'PARTIAL' && item.to === 'VIABLE'), true);
  assert.equal(delta.newCapabilities.includes('network-egress'), true);
  assert.equal(JSON.stringify(delta).toLowerCase().includes('trust gain'), false);
});
