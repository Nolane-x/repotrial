import test from 'node:test';
import assert from 'node:assert/strict';
import { buildSarifReport } from '../src/core/sarif.mjs';

test('builds deterministic SARIF 2.1.0 with relative evidence locations', () => {
  const report = {
    scan: { target: '/private/home/alice/project', id: 'scan-1' },
    receipt: { sha256: 'a'.repeat(64) },
    verdict: { label: 'RECKLESS', score: 72 },
    forgeos: { status: 'ok', engine: { version: '0.6.1' } },
    charges: [
      {
        ruleId: 'unrestricted-shell-capability', title: 'Unrestricted shell capability', severity: 'high',
        status: 'proven', source: 'repotrial', confidence: 'high', rationale: 'Shell is unrestricted.',
        remediation: 'Allowlist commands.', evidence: [{ path: '.mcp.json', startLine: 4, endLine: 4, fingerprint: 'f'.repeat(64) }]
      },
      {
        ruleId: 'missing-verification-evidence', title: 'No credible verification command found', severity: 'medium',
        status: 'proven', source: 'repotrial', confidence: 'high', rationale: 'No command.',
        remediation: 'Add tests.', evidence: []
      }
    ]
  };

  const first = buildSarifReport(report, { version: '0.3.0' });
  const second = buildSarifReport(report, { version: '0.3.0' });
  assert.deepEqual(first, second);
  assert.equal(first.version, '2.1.0');
  assert.equal(first.runs[0].tool.driver.name, 'RepoTrial');
  assert.equal(first.runs[0].tool.driver.version, '0.3.0');
  assert.equal(first.runs[0].results.length, 2);
  assert.equal(first.runs[0].results[0].level, 'error');
  assert.equal(first.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, '.mcp.json');
  assert.equal(first.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uriBaseId, '%SRCROOT%');
  assert.equal(first.runs[0].results[1].locations, undefined);
  assert.doesNotMatch(JSON.stringify(first), /\/private\/home\/alice/);
});

test('maps critical and high charges to SARIF errors and low findings to notes', () => {
  const severities = ['critical', 'high', 'medium', 'low', 'info'];
  const sarif = buildSarifReport({
    scan: { id: 'x' }, receipt: { sha256: 'b'.repeat(64) }, verdict: { label: 'DANGEROUS', score: 100 },
    forgeos: { status: 'off' },
    charges: severities.map((severity, index) => ({
      ruleId: `r${index}`, title: severity, severity, status: 'proven', source: 'repotrial', confidence: 'high',
      rationale: severity, remediation: 'fix', evidence: []
    }))
  }, { version: '0.3.0' });
  assert.deepEqual(sarif.runs[0].results.map((result) => result.level), ['error', 'error', 'warning', 'note', 'note']);
});

test('marks differential findings with SARIF baselineState', () => {
  const shared = {
    ruleId: 'shared', title: 'Shared', severity: 'medium', status: 'proven', source: 'repotrial', confidence: 'high',
    rationale: 'Shared finding.', remediation: 'Fix it.', evidence: [{ path: 'a.json', startLine: 1, fingerprint: '1'.repeat(64) }]
  };
  const introduced = {
    ruleId: 'new', title: 'New', severity: 'high', status: 'proven', source: 'repotrial', confidence: 'high',
    rationale: 'New finding.', remediation: 'Fix it.', evidence: [{ path: 'b.json', startLine: 2, fingerprint: '2'.repeat(64) }]
  };
  const report = {
    scan: { id: 'diff' }, receipt: { sha256: 'd'.repeat(64) }, verdict: { label: 'RECKLESS', score: 70 }, forgeos: { status: 'off' },
    charges: [shared, introduced],
    differential: { new: [{ ...introduced }], existing: [{ ...shared }], resolved: [], summary: { new: 1, existing: 1, resolved: 0 } }
  };
  const sarif = buildSarifReport(report, { version: '0.4.0' });
  const states = Object.fromEntries(sarif.runs[0].results.map((result) => [result.ruleId, result.baselineState]));
  assert.deepEqual(states, { shared: 'unchanged', new: 'new' });
});
