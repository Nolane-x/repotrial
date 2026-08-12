import test from 'node:test';
import assert from 'node:assert/strict';
import { reasonAboutEvidence } from '../src/reasoning/engine.mjs';
import { runAdaptiveExperiments } from '../src/experiments/run.mjs';

function charge(ruleId, severity = 'critical') {
  return {
    ruleId,
    title: ruleId,
    severity,
    status: 'proven',
    confidence: 'high',
    source: 'test',
    rationale: 'test',
    remediation: 'test',
    evidence: [{
      path: 'package.json', startLine: 1, endLine: 1, snippet: ruleId,
      fileSha256: 'sha', fingerprint: `fp:${ruleId}`, stableFingerprint: `fp:${ruleId}`, severity
    }]
  };
}

const candidate = {
  kind: 'package-script', packagePath: 'package.json', name: 'postinstall',
  command: 'node install.mjs', workingDirectory: '.'
};

const snapshot = {
  files: [{ path: 'package.json', content: '{"scripts":{"postinstall":"node install.mjs"}}', sha256: 'sha' }]
};

function partialReasoning() {
  return reasonAboutEvidence({
    charges: [charge('unrestricted-shell-capability')],
    safeguards: [], coverage: { ratio: 1, complete: true }
  });
}

test('off mode performs no planning or execution and returns no charges', async () => {
  let executions = 0;
  const result = await runAdaptiveExperiments({
    mode: 'off', reasoning: partialReasoning(), candidates: [candidate], snapshot,
    executeBaseline: async () => { executions += 1; throw new Error('must not execute'); },
    executeScenario: async () => { executions += 1; throw new Error('must not execute'); }
  });
  assert.equal(result.status, 'disabled');
  assert.equal(executions, 0);
  assert.deepEqual(result.charges, []);
  assert.equal(result.plan.experiments.length, 0);
});

test('plan mode produces a deterministic bounded plan and executes nothing', async () => {
  let executions = 0;
  const input = {
    mode: 'plan', reasoning: partialReasoning(), candidates: [candidate], snapshot, scanId: 'scan:plan', maxExperiments: 1,
    executeBaseline: async () => { executions += 1; }, executeScenario: async () => { executions += 1; }
  };
  const first = await runAdaptiveExperiments(input);
  const second = await runAdaptiveExperiments(input);
  assert.deepEqual(first, second);
  assert.equal(first.status, 'planned');
  assert.equal(first.plan.experiments.length, 1);
  assert.equal(first.runs.length, 0);
  assert.equal(first.observations.length, 0);
  assert.equal(executions, 0);
});

test('sandbox unavailable is inconclusive and creates no positive charge', async () => {
  const result = await runAdaptiveExperiments({
    mode: 'sandbox', reasoning: partialReasoning(), candidates: [candidate], snapshot, scanId: 'scan:unavailable', maxExperiments: 1,
    executeBaseline: async () => ({ status: 'unavailable', run: null, canaries: [] }),
    executeScenario: async () => ({ status: 'unavailable', reason: 'userns-disabled', run: null, canaries: [] })
  });
  assert.equal(result.status, 'inconclusive');
  assert.equal(result.observations.every((item) => item.state === 'INCONCLUSIVE'), true);
  assert.deepEqual(result.charges, []);
});

test('positive synthetic canary observation produces experiment evidence that closes the reasoning loop', async () => {
  const canary = 'rtx_internal_test_value';
  const initial = partialReasoning();
  const experiments = await runAdaptiveExperiments({
    mode: 'sandbox', reasoning: initial, candidates: [candidate], snapshot, scanId: 'scan:positive', maxExperiments: 1,
    executeBaseline: async () => ({
      status: 'completed', run: { status: 'completed', exitCode: 0, timedOut: false, outputTruncated: false, events: [], filesystemChanges: [], stdout: '', stderr: '' }, canaries: []
    }),
    executeScenario: async () => ({
      status: 'completed',
      canaries: [{ key: 'OPENAI_API_KEY', value: canary, fingerprint: 'f'.repeat(64) }],
      run: {
        status: 'completed', exitCode: 0, timedOut: false, outputTruncated: false,
        events: [{ kind: 'network', api: 'request', target: `https://sink.invalid/?k=${canary}` }],
        filesystemChanges: [], stdout: '', stderr: ''
      }
    })
  });
  assert.equal(experiments.status, 'completed');
  assert.equal(experiments.summary.positiveObservationCount, 1);
  assert.equal(experiments.charges.some((item) => item.ruleId === 'adaptive-secret-egress-observed'), true);
  assert.equal(JSON.stringify(experiments).includes(canary), false);

  const final = reasonAboutEvidence({
    charges: [charge('unrestricted-shell-capability'), ...experiments.charges],
    safeguards: [], coverage: { ratio: 1, complete: true }
  });
  const hypothesis = final.hypotheses.find((item) => item.id === 'credential-exfiltration');
  assert.equal(hypothesis.state, 'PROVEN');
});

test('NOT_OBSERVED experiment stays unresolved and creates no global absence', async () => {
  const initial = partialReasoning();
  const result = await runAdaptiveExperiments({
    mode: 'sandbox', reasoning: initial, candidates: [candidate], snapshot, scanId: 'scan:not-observed', maxExperiments: 1,
    executeBaseline: async () => ({ status: 'completed', run: { status: 'completed', events: [], filesystemChanges: [], stdout: '', stderr: '' }, canaries: [] }),
    executeScenario: async () => ({ status: 'completed', canaries: [], run: { status: 'completed', events: [], filesystemChanges: [], stdout: '', stderr: '' } })
  });
  assert.equal(result.observations[0].state, 'NOT_OBSERVED');
  assert.deepEqual(result.charges, []);
  assert.equal('negativeEvidence' in result, false);
});
