import test from 'node:test';
import assert from 'node:assert/strict';
import { buildCausalTrace } from '../src/experiments/causal-trace.mjs';

test('causal trace preserves ordered phase ancestry and emitted evidence IDs', () => {
  const trace = buildCausalTrace({
    episodeId: 'episode:a', chainId: 'chain:a', threatId: 'credential-exfiltration', targetCapabilities: ['network-egress'],
    phaseResults: [
      { id: 'phase:prepare', phase: 'PREPARE', status: 'TRIGGERED', observations: [{ kind: 'synthetic-source', fingerprint: 'a'.repeat(64) }] },
      { id: 'phase:trigger', phase: 'TRIGGER', status: 'OBSERVED', observations: [{ kind: 'network', target: 'example.invalid' }], emittedEvidenceIds: ['ev:one'] }
    ]
  });
  assert.equal(trace.schemaVersion, 'repotrial.causal-trace.v1');
  assert.deepEqual(trace.steps.map((step) => step.phase), ['PREPARE', 'TRIGGER']);
  assert.equal(trace.steps[1].parentStepId, trace.steps[0].id);
  assert.deepEqual(trace.emittedEvidenceIds, ['ev:one']);
  assert.match(trace.receipt, /^[a-f0-9]{64}$/);
});

test('trace serialization redacts raw synthetic canaries recursively', () => {
  const raw = 'rtx_super_secret_canary_123';
  const trace = buildCausalTrace({
    episodeId: 'episode:a', chainId: 'chain:a', threatId: 'credential-exfiltration', targetCapabilities: ['secret-access'],
    phaseResults: [{ id: 'phase:trigger', phase: 'TRIGGER', status: 'OBSERVED', observations: [{ stdout: raw, nested: { value: `prefix-${raw}-suffix` } }] }]
  });
  const serialized = JSON.stringify(trace);
  assert.equal(serialized.includes(raw), false);
  assert.equal(serialized.includes('rtx_'), false);
  assert.equal(serialized.includes('[synthetic-canary-redacted]'), true);
});

test('NOT_OBSERVED trace stays local and never manufactures negative evidence', () => {
  const trace = buildCausalTrace({
    episodeId: 'episode:a', chainId: 'chain:a', threatId: 'credential-exfiltration', targetCapabilities: ['network-egress'],
    phaseResults: [{ id: 'phase:verify', phase: 'VERIFY', status: 'NOT_OBSERVED', observations: [] }]
  });
  assert.equal(trace.outcome, 'NOT_OBSERVED');
  assert.equal(trace.scope, 'single-bounded-episode');
  assert.equal(Object.hasOwn(trace, 'negativeEvidence'), false);
});
