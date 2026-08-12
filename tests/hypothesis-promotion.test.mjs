import test from 'node:test';
import assert from 'node:assert/strict';
import { getThreatRegistry } from '../src/reasoning/threat-registry.mjs';
import { promoteDiscoveredHypothesis } from '../src/reasoning/hypothesis-promotion.mjs';

function candidate(overrides = {}) {
  return {
    id: 'hyp:auto:abcdef',
    title: 'Discovered composition: instruction-control → network-egress',
    category: 'autonomous-discovery',
    state: 'PROMOTABLE',
    severity: 'high',
    capabilities: ['instruction-control', 'network-egress'],
    noveltyScore: 0.5,
    corroboration: 'SHARED_EVIDENCE',
    realmAssessment: { state: 'PRODUCTION_RELEVANT', productionRelevant: true, realms: ['production'] },
    ...overrides
  };
}

test('promotes a production-relevant corroborated novel candidate into a validated transient threat definition', () => {
  const promoted = promoteDiscoveredHypothesis(candidate());
  assert.match(promoted.id, /^auto-discovered-[a-f0-9]{24}$/);
  assert.equal(promoted.category, 'autonomous-discovery');
  assert.equal(promoted.stages.length, 2);
  assert.deepEqual(promoted.stages.map((stage) => stage.anyOf), [['instruction-control'], ['network-egress']]);
});

test('promotion fails closed for structural, non-production, low-novelty, or unknown-capability candidates', () => {
  assert.throws(() => promoteDiscoveredHypothesis(candidate({ state: 'STRUCTURAL' })), /PROMOTABLE/);
  assert.throws(() => promoteDiscoveredHypothesis(candidate({ realmAssessment: { state: 'NON_PRODUCTION_ONLY', productionRelevant: false, realms: ['benchmark'] } })), /production/);
  assert.throws(() => promoteDiscoveredHypothesis(candidate({ noveltyScore: 0.1 })), /novelty/);
  assert.throws(() => promoteDiscoveredHypothesis(candidate({ capabilities: ['instruction-control', 'invented-capability'] })), /unknown capability/);
});

test('promotion never mutates the built-in registry', () => {
  const before = getThreatRegistry();
  promoteDiscoveredHypothesis(candidate());
  const after = getThreatRegistry();
  assert.deepEqual(after, before);
});
