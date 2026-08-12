import test from 'node:test';
import assert from 'node:assert/strict';
import { reasonAboutEvidence } from '../src/reasoning/engine.mjs';
import {
  classifyEvidencePath,
  buildEvidenceRealmIndex,
  assessChainRealm
} from '../src/reasoning/evidence-realms.mjs';

const charge = (ruleId, path, extra = {}) => ({
  ruleId,
  title: ruleId,
  severity: 'high',
  status: 'proven',
  confidence: 'high',
  source: 'repotrial',
  evidence: [{ path, startLine: 1, endLine: 1, stableFingerprint: `fp:${ruleId}:${path}` }],
  ...extra
});

test('classifyEvidencePath separates production and non-production realms deterministically', () => {
  const cases = [
    ['src/core/analyze.mjs', 'production'],
    ['tests/unit/foo.test.mjs', 'test'],
    ['tests/adversarial-corpus/cases/x/AGENTS.md', 'benchmark'],
    ['tests/fixtures/reckless-agent/.mcp.json', 'fixture'],
    ['docs/architecture.md', 'docs'],
    ['coverage/lcov.info', 'generated'],
    ['.repotrial-self-v07/forgeos-agent-surface.json', 'generated'],
    ['nested/.repotrial_ci/verdict.json', 'generated'],
    ['vendor/tool/index.js', 'vendor'],
    ['', 'unknown']
  ];
  for (const [path, realm] of cases) {
    assert.equal(classifyEvidencePath(path).realm, realm, path);
  }
});

test('buildEvidenceRealmIndex maps reasoning evidence ids back to anchor realms', () => {
  const charges = [
    charge('dangerous-lifecycle-script', 'tests/adversarial-corpus/cases/lifecycle/package.json'),
    charge('unrestricted-shell-capability', 'src/agent.mjs')
  ];
  const reasoning = reasonAboutEvidence({ charges, safeguards: [], coverage: { ratio: 1, complete: true } });
  const index = buildEvidenceRealmIndex({ charges, reasoning });
  const positiveNodes = reasoning.graph.nodes.filter((node) => node.type === 'EVIDENCE' && node.polarity === 'POSITIVE');
  assert.equal(positiveNodes.length, 2);
  const byRule = new Map(positiveNodes.map((node) => [node.ruleId, node.id]));
  assert.deepEqual(index.byEvidenceId[byRule.get('dangerous-lifecycle-script')].realms, ['benchmark']);
  assert.deepEqual(index.byEvidenceId[byRule.get('unrestricted-shell-capability')].realms, ['production']);
});

test('assessChainRealm keeps benchmark-only attack chains visible but non-production', () => {
  const charges = [charge('dangerous-lifecycle-script', 'tests/adversarial-corpus/cases/lifecycle/package.json')];
  const reasoning = reasonAboutEvidence({ charges, safeguards: [], coverage: { ratio: 1, complete: true } });
  const index = buildEvidenceRealmIndex({ charges, reasoning });
  const evidenceId = reasoning.graph.nodes.find((node) => node.type === 'EVIDENCE' && node.polarity === 'POSITIVE').id;
  const assessment = assessChainRealm({ supportingEvidenceIds: [evidenceId] }, index, { edges: [] });
  assert.equal(assessment.state, 'NON_PRODUCTION_ONLY');
  assert.equal(assessment.productionRelevant, false);
  assert.deepEqual(assessment.realms, ['benchmark']);
});

test('assessChainRealm rejects unproven cross-realm composition', () => {
  const charges = [
    charge('prompt-boundary-override', 'src/agent.mjs'),
    charge('unrestricted-shell-capability', 'tests/fixtures/agent/AGENTS.md')
  ];
  const reasoning = reasonAboutEvidence({ charges, safeguards: [], coverage: { ratio: 1, complete: true } });
  const index = buildEvidenceRealmIndex({ charges, reasoning });
  const ids = reasoning.graph.nodes.filter((node) => node.type === 'EVIDENCE' && node.polarity === 'POSITIVE').map((node) => node.id);
  const assessment = assessChainRealm({ supportingEvidenceIds: ids }, index, { edges: [] });
  assert.equal(assessment.state, 'CROSS_REALM_UNPROVEN');
  assert.equal(assessment.productionRelevant, false);
  assert.deepEqual(assessment.realms, ['fixture', 'production']);
});
