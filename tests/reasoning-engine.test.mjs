import test from 'node:test';
import assert from 'node:assert/strict';
import { reasonAboutEvidence } from '../src/reasoning/engine.mjs';

function charge(ruleId, overrides = {}) {
  return {
    ruleId,
    title: overrides.title ?? ruleId,
    severity: overrides.severity ?? 'high',
    status: overrides.status ?? 'proven',
    confidence: overrides.confidence ?? 'high',
    evidence: overrides.evidence ?? [{
      path: overrides.path ?? 'AGENTS.md',
      startLine: 1,
      endLine: 1,
      stableFingerprint: overrides.fingerprint ?? `fp:${ruleId}`
    }],
    rationale: overrides.rationale ?? ruleId,
    remediation: overrides.remediation ?? `remediate ${ruleId}`,
    source: overrides.source ?? 'repotrial'
  };
}

const completeCoverage = { ratio: 1, complete: true };

function reason(charges, safeguards = []) {
  return reasonAboutEvidence({ charges, safeguards, coverage: completeCoverage, providers: {} });
}

test('reasoning output is deterministic and invariant to charge ordering', () => {
  const charges = [
    charge('unrestricted-shell-capability'),
    charge('secret-to-egress-path'),
    charge('unknown-enterprise-rule', { severity: 'medium' })
  ];

  const forward = reason(charges);
  const reverse = reason([...charges].reverse());

  assert.deepEqual(forward, reverse);
  assert.equal(forward.schemaVersion, 'repotrial.reasoning.v1');
});

test('unknown rules remain evidence without inventing capabilities', () => {
  const result = reason([charge('unknown-enterprise-rule')]);
  const evidence = result.graph.nodes.find((node) => node.type === 'EVIDENCE' && node.ruleId === 'unknown-enterprise-rule');

  assert.ok(evidence);
  assert.equal(result.graph.edges.some((edge) => edge.from === evidence.id && edge.relation === 'SUPPORTS'), false);
});

test('credential exfiltration becomes proven only when the complete capability chain exists', () => {
  const result = reason([
    charge('unrestricted-shell-capability'),
    charge('secret-to-egress-path')
  ]);
  const hypothesis = result.hypotheses.find((item) => item.id === 'credential-exfiltration');
  const path = result.attackPaths.find((item) => item.hypothesisId === 'credential-exfiltration');

  assert.equal(hypothesis.state, 'PROVEN');
  assert.deepEqual(hypothesis.missingStages, []);
  assert.ok(hypothesis.confidence >= 0.9);
  assert.equal(path.viability, 'VIABLE');
  assert.deepEqual(path.missingStages, []);
});

test('missing evidence remains unknown and produces a partial path', () => {
  const result = reason([charge('secret-to-egress-path')]);
  const hypothesis = result.hypotheses.find((item) => item.id === 'credential-exfiltration');
  const path = result.attackPaths.find((item) => item.hypothesisId === 'credential-exfiltration');

  assert.equal(hypothesis.state, 'UNKNOWN');
  assert.ok(hypothesis.missingStages.includes('execution-control'));
  assert.equal(path.viability, 'PARTIAL');
});

test('human approval contradicts an otherwise viable destructive-action hypothesis', () => {
  const result = reason([
    charge('destructive-without-approval', { severity: 'medium' }),
    charge('unrestricted-shell-capability')
  ], [{ id: 'human-approval', detail: 'Explicit human approval is mandatory.', path: 'AGENTS.md' }]);
  const hypothesis = result.hypotheses.find((item) => item.id === 'unapproved-destructive-action');
  const path = result.attackPaths.find((item) => item.hypothesisId === 'unapproved-destructive-action');

  assert.equal(hypothesis.state, 'CONTRADICTED');
  assert.equal(hypothesis.contradictions.length, 1);
  assert.equal(path.viability, 'BLOCKED');
});

test('counterfactual remediation ranks evidence that breaks attack paths above unrelated findings', () => {
  const result = reason([
    charge('unrestricted-shell-capability'),
    charge('secret-to-egress-path'),
    charge('known-vulnerable-dependency:OSV-UNRELATED', { severity: 'medium' })
  ]);
  const egress = result.remediation.candidates.find((item) => item.ruleId === 'secret-to-egress-path');
  const unrelated = result.remediation.candidates.find((item) => item.ruleId === 'known-vulnerable-dependency:OSV-UNRELATED');

  assert.ok(egress.attackPathsEliminated > unrelated.attackPathsEliminated);
  assert.ok(result.remediation.candidates.indexOf(egress) < result.remediation.candidates.indexOf(unrelated));
});

test('graph exposes evidence, capability, claim, and mitigation relationships', () => {
  const result = reason([
    charge('prompt-boundary-override'),
    charge('broad-mcp-permissions')
  ], [{ id: 'least-privilege', detail: 'Use least privilege.', path: 'AGENTS.md' }]);

  assert.ok(result.graph.nodes.some((node) => node.type === 'EVIDENCE'));
  assert.ok(result.graph.nodes.some((node) => node.type === 'CAPABILITY'));
  assert.ok(result.graph.nodes.some((node) => node.type === 'CLAIM'));
  assert.ok(result.graph.nodes.some((node) => node.type === 'SAFEGUARD'));
  assert.ok(result.graph.edges.some((edge) => edge.relation === 'SUPPORTS'));
  assert.ok(result.graph.edges.some((edge) => edge.relation === 'ENABLES'));
});
