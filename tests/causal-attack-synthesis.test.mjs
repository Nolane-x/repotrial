import test from 'node:test';
import assert from 'node:assert/strict';
import { reasonAboutEvidence } from '../src/reasoning/engine.mjs';
import { buildCausalSecurityGraph } from '../src/reasoning/causal-graph.mjs';
import { getThreatRegistry } from '../src/reasoning/threat-registry.mjs';
import { synthesizeCausalAttackChains } from '../src/reasoning/attack-synthesis.mjs';

function charge(ruleId, options = {}) {
  return {
    ruleId,
    title: options.title ?? ruleId,
    severity: options.severity ?? 'critical',
    status: options.status ?? 'proven',
    confidence: options.confidence ?? 'high',
    source: options.source ?? 'test',
    evidence: options.evidence ?? [{ path: `${ruleId}.txt`, startLine: 1, endLine: 1, stableFingerprint: `${ruleId}-fp` }]
  };
}

function synthesize(charges, options = {}) {
  const negativeEvidence = options.negativeEvidence ?? [];
  const safeguards = options.safeguards ?? [];
  const coverage = options.coverage ?? { ratio: 1, complete: true };
  const reasoning = reasonAboutEvidence({ charges, safeguards, coverage, negativeEvidence });
  const graph = buildCausalSecurityGraph({ reasoning, charges, negativeEvidence });
  return synthesizeCausalAttackChains({
    registry: getThreatRegistry(), causalGraph: graph, reasoning, coverage,
    maxDepth: options.maxDepth, maxChains: options.maxChains
  });
}

test('synthesizes a proven credential-exfiltration chain in causal order with evidence provenance', () => {
  const result = synthesize([
    charge('secret-to-egress-path'),
    charge('unrestricted-shell-capability')
  ]);
  const chain = result.chains.find((item) => item.threatId === 'credential-exfiltration' && item.state === 'PROVEN');
  assert.ok(chain);
  assert.deepEqual(chain.stages.map((stage) => stage.id), ['secret-source', 'execution-control', 'network-egress']);
  assert.equal(chain.stages.every((stage) => stage.satisfied), true);
  assert.equal(chain.supportingEvidenceIds.length >= 2, true);
  assert.match(chain.id, /^chain:/);
  assert.match(result.receipt, /^[a-f0-9]{64}$/);
});

test('partial chain preserves exact unresolved stages rather than treating them as absent', () => {
  const result = synthesize([charge('unrestricted-shell-capability')]);
  const chain = result.chains.find((item) => item.threatId === 'credential-exfiltration');
  assert.ok(chain);
  assert.equal(chain.state, 'PARTIAL');
  assert.deepEqual(chain.missingStages.sort(), ['network-egress', 'secret-source']);
  assert.deepEqual(chain.refutedStages, []);
});

test('explicit negative evidence blocks a required unresolved stage', () => {
  const negativeEvidence = [{
    capability: 'network-egress', state: 'ABSENT', source: 'complete-provider', method: 'complete-callgraph', scope: 'repository', confidence: 0.99
  }];
  const result = synthesize([charge('unrestricted-shell-capability')], { negativeEvidence });
  const chain = result.chains.find((item) => item.threatId === 'credential-exfiltration');
  assert.ok(chain);
  assert.equal(chain.state, 'BLOCKED');
  assert.equal(chain.refutedStages.includes('network-egress'), true);
  assert.equal(chain.refutingEvidenceIds.length > 0, true);
});

test('positive and negative support for the same required capability produces CONTRADICTED rather than silently choosing a side', () => {
  const negativeEvidence = [{
    capability: 'network-egress', state: 'ABSENT', source: 'complete-provider', method: 'complete-callgraph', scope: 'repository', confidence: 0.99
  }];
  const result = synthesize([
    charge('secret-to-egress-path'),
    charge('unrestricted-shell-capability')
  ], { negativeEvidence });
  const chain = result.chains.find((item) => item.threatId === 'credential-exfiltration');
  assert.ok(chain);
  assert.equal(chain.state, 'CONTRADICTED');
  assert.equal(chain.contradictions.length > 0, true);
});

test('effective safeguard contradiction is retained in an otherwise active chain', () => {
  const result = synthesize([
    charge('secret-to-egress-path'),
    charge('unrestricted-shell-capability')
  ], { safeguards: [{ id: 'secret-protection', detail: 'synthetic protection', path: 'policy.yml' }] });
  const chain = result.chains.find((item) => item.threatId === 'credential-exfiltration');
  assert.ok(chain);
  assert.equal(chain.state, 'CONTRADICTED');
  assert.equal(chain.contradictions.some((item) => item.includes('secret-protection')), true);
});

test('hard caps bound depth and top-K output', () => {
  const result = synthesize([
    charge('secret-to-egress-path'),
    charge('unrestricted-shell-capability'),
    charge('destructive-without-approval'),
    charge('prompt-boundary-override')
  ], { maxDepth: 2, maxChains: 3 });
  assert.equal(result.chains.length <= 3, true);
  assert.equal(result.chains.every((chain) => chain.stages.length <= 2), true);
  assert.equal(result.limits.maxDepth, 2);
  assert.equal(result.limits.maxChains, 3);
});

test('equivalent evidence ordering produces identical chain IDs, ranking and receipt', () => {
  const charges = [
    charge('secret-to-egress-path'), charge('unrestricted-shell-capability'), charge('prompt-boundary-override')
  ];
  const a = synthesize(charges);
  const b = synthesize([...charges].reverse().map((item) => structuredClone(item)));
  assert.deepEqual(a, b);
});

test('chain score exposes auditable evidence-strength components', () => {
  const result = synthesize([charge('secret-to-egress-path'), charge('unrestricted-shell-capability')]);
  const chain = result.chains.find((item) => item.threatId === 'credential-exfiltration');
  assert.ok(chain.score);
  assert.equal(typeof chain.score.rank, 'number');
  assert.equal(typeof chain.score.breakdown.threatImpact, 'number');
  assert.equal(typeof chain.score.breakdown.stageCompletion, 'number');
  assert.equal(typeof chain.score.breakdown.confidenceFloor, 'number');
  assert.equal(typeof chain.score.breakdown.coverageFactor, 'number');
  assert.equal(typeof chain.score.breakdown.contradictionFactor, 'number');
});
