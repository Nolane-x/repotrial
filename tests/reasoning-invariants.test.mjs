import test from 'node:test';
import assert from 'node:assert/strict';
import { reasonAboutEvidence } from '../src/reasoning/engine.mjs';
import { evaluateSecurityInvariants } from '../src/reasoning/invariants.mjs';
import { normalizeNegativeEvidence } from '../src/reasoning/negative-evidence.mjs';

const coverage = { ratio: 1, complete: true };

function charge(ruleId, overrides = {}) {
  return {
    ruleId,
    title: overrides.title ?? ruleId,
    severity: overrides.severity ?? 'high',
    status: 'proven',
    confidence: overrides.confidence ?? 'high',
    source: overrides.source ?? 'repotrial',
    rationale: overrides.rationale ?? ruleId,
    remediation: overrides.remediation ?? `remediate ${ruleId}`,
    evidence: [{
      path: overrides.path ?? 'AGENTS.md',
      startLine: 1,
      endLine: 1,
      stableFingerprint: overrides.fingerprint ?? `fp:${ruleId}`
    }]
  };
}

function absent(capability, overrides = {}) {
  return {
    capability,
    state: 'absent',
    source: overrides.source ?? 'test-provider',
    method: overrides.method ?? 'explicit-capability-check',
    scope: overrides.scope ?? 'repository',
    confidence: overrides.confidence ?? 'high'
  };
}

function invariant(result, id) {
  return result.invariants.results.find((item) => item.id === id);
}

test('negative evidence normalization is deterministic and stable', () => {
  const input = [absent('network-egress'), absent('shell-exec')];
  const forward = normalizeNegativeEvidence(input);
  const reverse = normalizeNegativeEvidence([...input].reverse());

  assert.deepEqual(forward, reverse);
  assert.equal(forward.length, 2);
  assert.match(forward[0].id, /^neg:[a-f0-9]{24}$/);
  assert.ok(forward.every((item) => item.confidence > 0 && item.confidence <= 1));
});

test('forbidden composition stays UNKNOWN when a capability is merely unobserved', () => {
  const result = reasonAboutEvidence({
    charges: [charge('secret-to-egress-path')].map((item) => ({ ...item, ruleId: 'secret-source-only' })),
    safeguards: [],
    coverage,
    providers: {}
  });

  const direct = evaluateSecurityInvariants({
    observedCapabilities: ['secret-access'],
    safeguards: [],
    negativeEvidence: []
  });
  assert.equal(direct.results.find((item) => item.id === 'no-secret-network-composition').state, 'UNKNOWN');
  assert.equal(result.negativeEvidence.length, 0);
});

test('explicit absence can satisfy a forbidden-composition invariant', () => {
  const direct = evaluateSecurityInvariants({
    observedCapabilities: ['secret-access'],
    safeguards: [],
    negativeEvidence: normalizeNegativeEvidence([absent('network-egress')])
  });
  const item = direct.results.find((entry) => entry.id === 'no-secret-network-composition');

  assert.equal(item.state, 'SATISFIED');
  assert.equal(item.negativeEvidenceIds.length, 1);
});

test('secret access plus network egress violates the composition invariant', () => {
  const direct = evaluateSecurityInvariants({
    observedCapabilities: ['secret-access', 'network-egress'],
    safeguards: [],
    negativeEvidence: []
  });
  assert.equal(direct.results.find((item) => item.id === 'no-secret-network-composition').state, 'VIOLATED');
});

test('destructive capability requires explicit human approval', () => {
  const withoutApproval = evaluateSecurityInvariants({
    observedCapabilities: ['destructive-action'], safeguards: [], negativeEvidence: []
  });
  const withApproval = evaluateSecurityInvariants({
    observedCapabilities: ['destructive-action'], safeguards: ['human-approval'], negativeEvidence: []
  });

  assert.equal(withoutApproval.results.find((item) => item.id === 'destructive-requires-human-approval').state, 'VIOLATED');
  assert.equal(withApproval.results.find((item) => item.id === 'destructive-requires-human-approval').state, 'SATISFIED');
});

test('explicit negative evidence refutes a hypothesis only when every alternative for a required stage is absent', () => {
  const negativeEvidence = [
    absent('shell-exec'),
    absent('broad-tool-access'),
    absent('instruction-control'),
    absent('dependency-execution')
  ];
  const result = reasonAboutEvidence({
    charges: [charge('secret-to-egress-path')],
    safeguards: [],
    coverage,
    providers: {},
    negativeEvidence
  });
  const hypothesis = result.hypotheses.find((item) => item.id === 'credential-exfiltration');
  const path = result.attackPaths.find((item) => item.hypothesisId === 'credential-exfiltration');

  assert.equal(hypothesis.state, 'REFUTED');
  assert.equal(path.viability, 'BLOCKED');
  assert.equal(result.negativeEvidence.length, 4);
  assert.ok(result.graph.edges.some((edge) => edge.relation === 'REFUTES'));
});

test('provider absence never manufactures negative evidence or a satisfied invariant', () => {
  const result = reasonAboutEvidence({
    charges: [],
    safeguards: [],
    coverage,
    providers: {
      runtime: { status: 'disabled' },
      supplyChain: { status: 'disabled' },
      forgeos: { status: 'disabled' }
    }
  });

  assert.deepEqual(result.negativeEvidence, []);
  assert.equal(invariant(result, 'no-secret-network-composition').state, 'UNKNOWN');
  assert.notEqual(result.hypotheses.find((item) => item.id === 'credential-exfiltration').state, 'REFUTED');
});

test('caller-supplied invariants are evaluated deterministically', () => {
  const definitions = [{
    id: 'custom-no-shell-network',
    title: 'Shell and network must not compose',
    severity: 'critical',
    kind: 'forbid-all',
    capabilities: ['shell-exec', 'network-egress']
  }];
  const a = evaluateSecurityInvariants({
    observedCapabilities: ['network-egress', 'shell-exec'], safeguards: [], negativeEvidence: [], definitions
  });
  const b = evaluateSecurityInvariants({
    observedCapabilities: ['shell-exec', 'network-egress'], safeguards: [], negativeEvidence: [], definitions
  });

  assert.deepEqual(a, b);
  assert.equal(a.results.find((item) => item.id === 'custom-no-shell-network').state, 'VIOLATED');
});
