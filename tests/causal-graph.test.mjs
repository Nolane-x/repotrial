import test from 'node:test';
import assert from 'node:assert/strict';
import { reasonAboutEvidence } from '../src/reasoning/engine.mjs';
import { buildCausalSecurityGraph } from '../src/reasoning/causal-graph.mjs';

function charge(ruleId, options = {}) {
  return {
    ruleId,
    title: options.title ?? ruleId,
    severity: options.severity ?? 'high',
    status: options.status ?? 'proven',
    confidence: options.confidence ?? 'high',
    source: options.source ?? 'test',
    evidence: options.evidence ?? [{ path: 'fixture.txt', startLine: 1, endLine: 1, stableFingerprint: `${ruleId}-fp` }]
  };
}

function graphFor(charges, extra = {}) {
  const reasoning = reasonAboutEvidence({ charges, safeguards: extra.safeguards ?? [], coverage: { ratio: 1, complete: true }, negativeEvidence: extra.negativeEvidence ?? [] });
  return buildCausalSecurityGraph({ reasoning, charges, negativeEvidence: extra.negativeEvidence ?? [] });
}

test('causal graph is byte-deterministic under equivalent evidence reordering', () => {
  const charges = [
    charge('secret-to-egress-path'),
    charge('unrestricted-shell-capability'),
    charge('runtime-network-attempt')
  ];
  const a = graphFor(charges);
  const b = graphFor([...charges].reverse().map((item) => structuredClone(item)));
  assert.deepEqual(a, b);
  assert.equal(a.schemaVersion, 'repotrial.causal-graph.v1');
  assert.match(a.receipt, /^[a-f0-9]{64}$/);
});

test('causal graph materializes typed roles only from observed capabilities', () => {
  const graph = graphFor([
    charge('secret-to-egress-path'),
    charge('unrestricted-shell-capability'),
    charge('destructive-without-approval')
  ]);
  const types = new Set(graph.nodes.map((node) => node.type));
  assert.equal(types.has('SECRET'), true);
  assert.equal(types.has('EXECUTION_SURFACE'), true);
  assert.equal(types.has('TOOL'), true);
  assert.equal(types.has('SINK'), true);
  assert.equal(graph.nodes.some((node) => node.type === 'CAPABILITY' && node.capability === 'secret-access'), true);
});

test('unknown rule remains evidence and never invents a capability or causal role', () => {
  const graph = graphFor([charge('totally-unknown-rule')]);
  assert.equal(graph.nodes.some((node) => node.type === 'EVIDENCE'), true);
  assert.equal(graph.nodes.some((node) => node.type === 'CAPABILITY'), false);
  assert.equal(graph.nodes.some((node) => ['SECRET', 'TOOL', 'EXECUTION_SURFACE', 'SINK'].includes(node.type)), false);
});

test('explicit negative evidence remains a REFUTES relationship rather than an inferred absence', () => {
  const negativeEvidence = [{
    capability: 'network-egress', state: 'ABSENT', source: 'test-provider', method: 'complete-callgraph', scope: 'repository', confidence: 0.97
  }];
  const graph = graphFor([], { negativeEvidence });
  assert.equal(graph.edges.some((edge) => edge.relation === 'REFUTES'), true);
  const without = graphFor([]);
  assert.equal(without.edges.some((edge) => edge.relation === 'REFUTES'), false);
});

test('duplicate semantic evidence collapses by stable graph identity', () => {
  const item = charge('runtime-network-attempt');
  const graph = graphFor([item, structuredClone(item)]);
  const evidence = graph.nodes.filter((node) => node.type === 'EVIDENCE' && node.polarity !== 'NEGATIVE');
  assert.equal(evidence.length, 1);
});

test('trust-boundary edges require explicit source and target anchors', () => {
  const anchored = charge('runtime-network-attempt', {
    evidence: [{
      path: 'agent.mjs', startLine: 4, endLine: 4, stableFingerprint: 'anchored-fp',
      sourceTrustDomain: 'repository-content', targetTrustDomain: 'external-network'
    }]
  });
  const graph = graphFor([anchored]);
  const crossings = graph.edges.filter((edge) => edge.relation === 'CROSSES_TRUST_BOUNDARY');
  assert.equal(crossings.length, 1);
  assert.equal(graph.nodes.filter((node) => node.type === 'TRUST_DOMAIN').length, 2);

  const unanchored = graphFor([charge('runtime-network-attempt')]);
  assert.equal(unanchored.edges.some((edge) => edge.relation === 'CROSSES_TRUST_BOUNDARY'), false);
});
