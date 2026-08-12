import test from 'node:test';
import assert from 'node:assert/strict';
import { causalMeetsSeverity, causalDifferentialMeetsSeverity, normalizeCausalThreshold } from '../src/reasoning/causal-gates.mjs';

test('causal gate only blocks active causal chains at or above threshold', () => {
  const causal = { reasoning: { chains: [
    { id: 'a', severity: 'critical', state: 'PARTIAL' },
    { id: 'b', severity: 'high', state: 'PROVEN' }
  ] } };
  assert.equal(causalMeetsSeverity(causal, 'high'), true);
  assert.equal(causalMeetsSeverity(causal, 'critical'), false);
  assert.equal(normalizeCausalThreshold('CRITICAL'), 'critical');
});

test('causal differential gate recognizes new and regressed active chains', () => {
  const differential = { newActive: [{ id: 'x', severity: 'critical', state: 'PROVEN' }], regressed: [] };
  assert.equal(causalDifferentialMeetsSeverity(differential, 'critical'), true);
  assert.equal(causalDifferentialMeetsSeverity({ newActive: [], regressed: [{ id: 'y', severity: 'high', to: 'SUPPORTED' }] }, 'high'), true);
});
