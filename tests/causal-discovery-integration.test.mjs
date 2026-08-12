import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeCausalEvidence } from '../src/reasoning/causal-engine.mjs';
import { causalMeetsSeverity } from '../src/reasoning/causal-gates.mjs';

function charge(ruleId, path, fp, overrides = {}) {
  return {
    ruleId,
    title: ruleId,
    severity: 'critical',
    status: 'proven',
    confidence: 'high',
    source: 'repotrial',
    evidence: [{ path, startLine: 1, endLine: 1, stableFingerprint: fp }],
    ...overrides
  };
}

const coverage = { ratio: 1, complete: true };

test('analyze mode annotates benchmark-only proven chains without hiding them', () => {
  const causal = analyzeCausalEvidence({
    mode: 'analyze',
    charges: [charge('dangerous-lifecycle-script', 'tests/adversarial-corpus/cases/x/package.json', 'bench')],
    safeguards: [],
    coverage
  });
  const proven = causal.reasoning.chains.find((item) => item.threatId === 'arbitrary-code-execution' && item.state === 'PROVEN');
  assert.ok(proven);
  assert.equal(proven.realmAssessment.state, 'NON_PRODUCTION_ONLY');
  assert.equal(proven.realmAssessment.productionRelevant, false);
  assert.ok(causal.summary.activeChainCount >= 1);
  assert.equal(causal.summary.productionActiveChainCount, 0);
  assert.equal(causal.discovery, undefined);
});

test('discover mode synthesizes novel hypotheses without active execution planning', () => {
  const causal = analyzeCausalEvidence({
    mode: 'discover',
    charges: [
      charge('prompt-boundary-override', 'src/agent.mjs', 'control', { severity: 'high' }),
      charge('adaptive-network-trigger-observed', 'src/agent.mjs', 'network', { severity: 'high', source: 'repotrial-experiment' })
    ],
    safeguards: [],
    coverage
  });
  assert.equal(causal.mode, 'discover');
  assert.equal(causal.activePlan, undefined);
  assert.ok(causal.discovery);
  const candidate = causal.discovery.candidates.find((item) => item.capabilities.join(',') === 'instruction-control,network-egress');
  assert.ok(candidate, JSON.stringify(causal.discovery, null, 2));
  assert.equal(candidate.state, 'PROMOTABLE');
  assert.ok(causal.summary.discoveredHypothesisCount >= 1);
});

test('production causal gate ignores non-production-only active chains when requested', () => {
  const causal = analyzeCausalEvidence({
    mode: 'analyze',
    realmScope: 'production',
    charges: [charge('dangerous-lifecycle-script', 'tests/adversarial-corpus/cases/x/package.json', 'bench')],
    safeguards: [],
    coverage
  });
  assert.equal(causalMeetsSeverity(causal, 'critical'), false);
  assert.equal(causalMeetsSeverity({ ...causal, realmScope: 'all' }, 'critical'), true);
});
