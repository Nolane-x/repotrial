import test from 'node:test';
import assert from 'node:assert/strict';
import { runCausalActiveExperiments } from '../src/experiments/causal-run.mjs';

const candidate = { id: 'candidate:test', kind: 'package-script', packagePath: 'package.json', name: 'postinstall', command: 'node x.mjs', workingDirectory: '.' };

function causalPlan() {
  return { activePlan: { receipt: 'a'.repeat(64), experiments: [{
    id: 'aexp:test', templateId: 'secret-egress-canary-v1', chainId: 'chain:test', threatId: 'credential-exfiltration',
    candidate, targetCapabilities: ['network-egress', 'secret-access']
  }] } };
}

test('active causal runner assimilates only canonical positive episode observations', async () => {
  const result = await runCausalActiveExperiments({
    causal: causalPlan(), snapshot: { files: [] },
    episodeExecutor: async ({ episode }) => ({
      schemaVersion: 'repotrial.adversarial-episode-result.v1', episodeId: episode.id, templateId: episode.templateId,
      chainId: episode.chainId, threatId: episode.threatId, status: 'OBSERVED', reason: 'test', scope: 'single-bounded-episode',
      phaseResults: [{ id: 'p', phase: 'TRIGGER', status: 'OBSERVED', emittedEvidenceIds: [], observations: [{
        schemaVersion: 'repotrial.experiment-observation.v1', id: 'obs:test', experimentId: 'exp:test', templateId: 'secret-egress-canary-v1',
        hypothesisId: 'credential-exfiltration', attackPathId: 'chain:test', candidate, state: 'OBSERVED',
        signals: { canaryNetworkPropagation: true, networkDeltaCount: 1, sentinelMutationCount: 0 }, canaryFingerprints: [],
        evidence: { networkDelta: [], processDelta: [], filesystemDelta: [], sentinelMutations: [], propagatedCanaryFingerprints: [] }
      }] }]
    })
  });
  assert.equal(result.summary.emittedChargeCount, 1);
  assert.equal(result.charges[0].ruleId, 'adaptive-secret-egress-observed');
  assert.equal(JSON.stringify(result).includes('"charges"'), false);
  assert.equal(result.traces[0].outcome, 'OBSERVED');
});

test('NOT_OBSERVED causal episode emits no global negative evidence or charge', async () => {
  const result = await runCausalActiveExperiments({
    causal: causalPlan(), snapshot: { files: [] },
    episodeExecutor: async ({ episode }) => ({
      schemaVersion: 'repotrial.adversarial-episode-result.v1', episodeId: episode.id, templateId: episode.templateId,
      chainId: episode.chainId, threatId: episode.threatId, status: 'NOT_OBSERVED', reason: 'bounded-miss', scope: 'single-bounded-episode',
      phaseResults: [{ id: 'p', phase: 'TRIGGER', status: 'NOT_OBSERVED', emittedEvidenceIds: [], observations: [] }]
    })
  });
  assert.deepEqual(result.charges, []);
  assert.equal(Object.hasOwn(result, 'negativeEvidence'), false);
  assert.equal(result.traces[0].outcome, 'NOT_OBSERVED');
});
