import test from 'node:test';
import assert from 'node:assert/strict';
import { compareReports } from '../src/core/diff.mjs';

function report(causal) {
  return { charges: [], receipt: { sha256: 'a'.repeat(64) }, causal };
}
function causal(chains) {
  return { schemaVersion: 'repotrial.causal.v1', reasoning: { chains } };
}

test('causal differential detects new active chains and threat-level epistemic regression across identity changes', () => {
  const baseline = report(causal([{ id: 'chain:partial', threatId: 'credential-exfiltration', severity: 'critical', state: 'PARTIAL', score: { rank: 400 } }]));
  const current = report(causal([{ id: 'chain:proven', threatId: 'credential-exfiltration', severity: 'critical', state: 'PROVEN', score: { rank: 900 } }]));
  const diff = compareReports(baseline, current);
  assert.equal(diff.causal.schemaVersion, 'repotrial.causal-differential.v1');
  assert.equal(diff.causal.newActive.length, 1);
  assert.equal(diff.causal.regressed.length, 1);
  assert.deepEqual(diff.causal.regressed[0], { threatId: 'credential-exfiltration', severity: 'critical', from: 'PARTIAL', to: 'PROVEN' });
  assert.equal(diff.causal.summary.newActiveChainCount, 1);
  assert.match(diff.causal.receipt.sha256, /^[a-f0-9]{64}$/);
});

test('causal differential reports resolved active chains without inventing regression', () => {
  const baseline = report(causal([{ id: 'chain:a', threatId: 'unauthorized-tool-use', severity: 'high', state: 'SUPPORTED', score: { rank: 700 } }]));
  const current = report(causal([{ id: 'chain:b', threatId: 'unauthorized-tool-use', severity: 'high', state: 'BLOCKED', score: { rank: 50 } }]));
  const diff = compareReports(baseline, current);
  assert.equal(diff.causal.resolvedActive.length, 1);
  assert.equal(diff.causal.regressed.length, 0);
  assert.equal(diff.causal.improved.length, 1);
});
