import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { analyzeCausalEvidence } from '../src/reasoning/causal-engine.mjs';
import { reasonAboutEvidence } from '../src/reasoning/engine.mjs';
import { scanRepository } from '../src/core/analyze.mjs';

function charge(ruleId, severity = 'high') {
  return {
    ruleId, title: ruleId, severity, status: 'proven', confidence: 'high', source: 'test',
    rationale: ruleId, remediation: '',
    evidence: [{ path: 'AGENTS.md', startLine: 1, endLine: 1, stableFingerprint: `${ruleId}-anchor` }]
  };
}

test('causal engine is deterministic and synthesizes multi-stage chains from canonical reasoning evidence', () => {
  const charges = [charge('secret-to-egress-path'), charge('unrestricted-shell-capability')];
  const reasoning = reasonAboutEvidence({ charges, safeguards: [], coverage: { ratio: 1, complete: true } });
  const a = analyzeCausalEvidence({ charges, reasoning, coverage: { ratio: 1, complete: true }, mode: 'analyze' });
  const b = analyzeCausalEvidence({ charges: [...charges].reverse(), reasoning, coverage: { ratio: 1, complete: true }, mode: 'analyze' });
  assert.deepEqual(a, b);
  assert.equal(a.schemaVersion, 'repotrial.causal.v1');
  assert.equal(a.mode, 'analyze');
  assert.equal(a.reasoning.chains.some((item) => item.threatId === 'credential-exfiltration' && ['PROVEN', 'SUPPORTED'].includes(item.state)), true);
  assert.match(a.receipt, /^[a-f0-9]{64}$/);
});

test('causal off preserves 0.6 report shape while analyze writes a proof-bound causal artifact', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-causal-scan-'));
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ scripts: { test: 'node --test' } }));
  await writeFile(path.join(root, 'AGENTS.md'), 'Run tests before completion.');

  const offDir = path.join(root, '.out-off');
  const off = await scanRepository({ root, outputDir: offDir, forgeos: { mode: 'off' }, runtime: { mode: 'off' }, supplyChain: { mode: 'off' }, causal: { mode: 'off' }, scanId: 'causal-off', now: '2026-08-12T00:00:00.000Z' });
  assert.equal(Object.hasOwn(off.report, 'causal'), false);
  assert.equal(Object.hasOwn(off.artifacts, 'causal'), false);

  const analyzeDir = path.join(root, '.out-analyze');
  const analyzed = await scanRepository({ root, outputDir: analyzeDir, forgeos: { mode: 'off' }, runtime: { mode: 'off' }, supplyChain: { mode: 'off' }, causal: { mode: 'analyze' }, scanId: 'causal-analyze', now: '2026-08-12T00:00:00.000Z' });
  assert.equal(analyzed.report.causal.schemaVersion, 'repotrial.causal.v1');
  assert.ok(analyzed.artifacts.causal.endsWith('causal.json'));
  const causalArtifact = JSON.parse(await readFile(analyzed.artifacts.causal, 'utf8'));
  assert.equal(causalArtifact.receipt, analyzed.report.causal.receipt);
  const proof = JSON.parse(await readFile(analyzed.artifacts.proof, 'utf8'));
  assert.equal(proof.artifacts.some((item) => item.name === 'causal.json'), true);
});
