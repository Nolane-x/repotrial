import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { reasonAboutEvidence } from '../src/reasoning/engine.mjs';

function charge(overrides = {}) {
  return {
    ruleId: 'unrestricted-shell-capability',
    title: overrides.title ?? 'Unrestricted shell capability',
    severity: overrides.severity ?? 'high',
    status: overrides.status ?? 'proven',
    confidence: overrides.confidence ?? 'high',
    source: overrides.source ?? 'repotrial',
    rationale: overrides.rationale ?? 'Shell is unrestricted.',
    remediation: overrides.remediation ?? 'Restrict shell execution.',
    evidence: [{
      path: 'AGENTS.md',
      startLine: overrides.startLine ?? 4,
      endLine: overrides.endLine ?? 4,
      stableFingerprint: 'stable:shell-capability'
    }]
  };
}

function evidenceId(result) {
  return result.graph.nodes.find((node) => node.type === 'EVIDENCE' && node.ruleId === 'unrestricted-shell-capability').id;
}

test('report.v2 keeps reasoning optional so pre-0.5 reports remain schema-compatible', async () => {
  const schema = JSON.parse(await readFile(new URL('../schemas/report.schema.json', import.meta.url), 'utf8'));
  assert.equal(schema.properties.reasoning.$ref, './reasoning.schema.json');
  assert.equal(schema.required.includes('reasoning'), false);
});

test('stable evidence identity ignores presentation and severity changes when the stable anchor is unchanged', () => {
  const coverage = { ratio: 1, complete: true };
  const before = reasonAboutEvidence({ charges: [charge()], safeguards: [], coverage });
  const after = reasonAboutEvidence({
    charges: [charge({
      title: 'Shell execution is unrestricted',
      severity: 'critical',
      rationale: 'Reworded explanation after rule tuning.',
      remediation: 'Use an explicit command allowlist.',
      startLine: 200,
      endLine: 200
    })],
    safeguards: [],
    coverage
  });

  assert.equal(evidenceId(before), evidenceId(after));
});
