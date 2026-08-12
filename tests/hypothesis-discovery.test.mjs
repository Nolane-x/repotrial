import test from 'node:test';
import assert from 'node:assert/strict';
import { getThreatRegistry } from '../src/reasoning/threat-registry.mjs';
import { getCapabilitySemantics } from '../src/reasoning/capability-semantics.mjs';
import { discoverThreatHypotheses } from '../src/reasoning/hypothesis-discovery.mjs';

function graph(capabilities, supports = {}) {
  const nodes = [];
  const edges = [];
  for (const [id, meta] of Object.entries(supports)) {
    nodes.push({ id, type: 'EVIDENCE', polarity: 'POSITIVE', status: 'proven', confidence: 'high', ...meta });
  }
  for (const capability of capabilities) {
    const id = `cap:${capability}`;
    nodes.push({ id, type: 'CAPABILITY', capability, observed: true });
    for (const evidenceId of Object.keys(supports).filter((ev) => supports[ev].capabilities?.includes(capability))) {
      edges.push({ id: `edge:${evidenceId}:${capability}`, from: evidenceId, to: id, relation: 'SUPPORTS' });
    }
  }
  return { schemaVersion: 'repotrial.causal-graph.v1', nodes, edges, receipt: 'graph' };
}

function realmIndex(entries) {
  return {
    schemaVersion: 'repotrial.evidence-realms.v1',
    byEvidenceId: Object.fromEntries(Object.entries(entries).map(([id, value]) => [id, {
      evidenceId: id,
      realm: value.realm,
      realms: [value.realm],
      anchors: [{ path: value.path, realm: value.realm, fingerprint: `${id}:fp` }],
      fingerprints: [`${id}:fp`]
    }]))
  };
}

test('capability semantics cover every normalized capability family used by causal discovery', () => {
  const semantics = getCapabilitySemantics();
  for (const capability of ['secret-access','shell-exec','dependency-execution','broad-tool-access','network-egress','destructive-action','filesystem-write','instruction-control','supply-chain-exposure','verification-bypass','persistent-state','memory-write','ci-identity-access','identity-access','privileged-action']) {
    assert.ok(semantics[capability], capability);
    assert.ok(semantics[capability].roles.length > 0, capability);
  }
});

test('discovers a novel production composition without inventing capabilities', () => {
  const supports = {
    'ev:shared': { capabilities: ['instruction-control', 'network-egress'] }
  };
  const result = discoverThreatHypotheses({
    causalGraph: graph(['instruction-control', 'network-egress'], supports),
    registry: getThreatRegistry(),
    realmIndex: realmIndex({ 'ev:shared': { realm: 'production', path: 'src/agent.mjs' } })
  });
  const candidate = result.candidates.find((item) => item.capabilities.join(',') === 'instruction-control,network-egress');
  assert.ok(candidate, JSON.stringify(result, null, 2));
  assert.equal(candidate.realmAssessment.state, 'PRODUCTION_RELEVANT');
  assert.equal(candidate.state, 'PROMOTABLE');
  assert.ok(candidate.noveltyScore >= 0.35);
  assert.deepEqual(candidate.supportingEvidenceIds, ['ev:shared']);
  assert.ok(candidate.capabilities.every((capability) => ['instruction-control', 'network-egress'].includes(capability)));
});

test('does not rediscover a registry-covered credential exfiltration chain as novel', () => {
  const supports = {
    'ev:secret': { capabilities: ['secret-access'] },
    'ev:shell': { capabilities: ['shell-exec'] },
    'ev:net': { capabilities: ['network-egress'] }
  };
  const result = discoverThreatHypotheses({
    causalGraph: graph(['secret-access', 'shell-exec', 'network-egress'], supports),
    registry: getThreatRegistry(),
    realmIndex: realmIndex({
      'ev:secret': { realm: 'production', path: 'src/a.mjs' },
      'ev:shell': { realm: 'production', path: 'src/b.mjs' },
      'ev:net': { realm: 'production', path: 'src/c.mjs' }
    })
  });
  assert.equal(result.candidates.some((item) => item.capabilities.join(',') === 'secret-access,shell-exec,network-egress'), false);
  assert.ok(result.summary.registryCoveredCount >= 1);
});

test('mixed isolated realms cannot create a promotable production hypothesis', () => {
  const supports = {
    'ev:control': { capabilities: ['instruction-control'] },
    'ev:net': { capabilities: ['network-egress'] }
  };
  const result = discoverThreatHypotheses({
    causalGraph: graph(['instruction-control', 'network-egress'], supports),
    registry: getThreatRegistry(),
    realmIndex: realmIndex({
      'ev:control': { realm: 'production', path: 'src/agent.mjs' },
      'ev:net': { realm: 'fixture', path: 'tests/fixtures/agent/.mcp.json' }
    })
  });
  assert.equal(result.candidates.some((item) => item.state === 'PROMOTABLE'), false);
  assert.ok(result.summary.crossRealmDismissedCount >= 1);
});

test('discovery is deterministic under graph and evidence ordering', () => {
  const supports = {
    'ev:a': { capabilities: ['instruction-control', 'network-egress'] },
    'ev:b': { capabilities: ['verification-bypass', 'destructive-action'] }
  };
  const g = graph(['instruction-control','network-egress','verification-bypass','destructive-action'], supports);
  const index = realmIndex({
    'ev:a': { realm: 'production', path: 'src/a.mjs' },
    'ev:b': { realm: 'production', path: 'src/b.mjs' }
  });
  const one = discoverThreatHypotheses({ causalGraph: g, registry: getThreatRegistry(), realmIndex: index });
  const two = discoverThreatHypotheses({
    causalGraph: { ...g, nodes: [...g.nodes].reverse(), edges: [...g.edges].reverse() },
    registry: getThreatRegistry(),
    realmIndex: { ...index, byEvidenceId: Object.fromEntries(Object.entries(index.byEvidenceId).reverse()) }
  });
  assert.equal(one.receipt, two.receipt);
  assert.deepEqual(one.candidates, two.candidates);
});

test('maxCandidates bounds candidate output', () => {
  const supports = {
    'ev:a': { capabilities: ['instruction-control','network-egress','destructive-action','filesystem-write','broad-tool-access','shell-exec','verification-bypass'] }
  };
  const result = discoverThreatHypotheses({
    causalGraph: graph(supports['ev:a'].capabilities, supports),
    registry: getThreatRegistry(),
    realmIndex: realmIndex({ 'ev:a': { realm: 'production', path: 'src/a.mjs' } }),
    maxCandidates: 2,
    minNovelty: 0.1
  });
  assert.ok(result.candidates.length <= 2);
  assert.equal(result.limits.maxCandidates, 2);
});
