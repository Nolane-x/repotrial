import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import * as api from '../src/index.mjs';
import { calculateVerdict } from '../src/core/verdict.mjs';

async function withFixture(run) {
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-reasoning-fixture-'));
  const outputDir = path.join(root, '.case');
  try {
    await writeFile(path.join(root, 'package.json'), JSON.stringify({
      name: 'reasoning-fixture',
      scripts: { test: 'node --test' }
    }, null, 2));
    await writeFile(path.join(root, 'AGENTS.md'), [
      '# Agent policy',
      'shell: true',
      'network: *',
      'env: ${OPENAI_API_KEY}'
    ].join('\n'));
    return await run({ root, outputDir });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('scan report embeds deterministic reasoning without changing verdict semantics', async () => {
  await withFixture(async ({ root, outputDir }) => {
    const { report } = await api.scanRepository({
      root,
      outputDir,
      forgeos: { mode: 'off' },
      runtime: { mode: 'off' },
      supplyChain: { mode: 'off' },
      scanId: 'reasoning-integration',
      now: '2026-08-11T00:00:00.000Z'
    });

    assert.equal(report.reasoning.schemaVersion, 'repotrial.reasoning.v1');
    assert.equal(report.reasoning.hypotheses.find((item) => item.id === 'credential-exfiltration').state, 'PROVEN');
    assert.equal(report.reasoning.invariants.schemaVersion, 'repotrial.invariants.v1');
    assert.equal(report.reasoning.invariants.results.find((item) => item.id === 'no-secret-network-composition').state, 'VIOLATED');
    assert.deepEqual(report.reasoning.negativeEvidence, []);
    assert.deepEqual(report.verdict, calculateVerdict(report.charges, report.scan.coverage));
  });
});

test('package root exports the reasoning, invariant, and negative-evidence APIs', () => {
  assert.equal(typeof api.reasonAboutEvidence, 'function');
  assert.equal(typeof api.evaluateSecurityInvariants, 'function');
  assert.equal(typeof api.normalizeNegativeEvidence, 'function');
});

test('portable HTML report renders attack paths and invariant proof', async () => {
  await withFixture(async ({ root, outputDir }) => {
    const { artifacts } = await api.scanRepository({
      root,
      outputDir,
      forgeos: { mode: 'off' },
      runtime: { mode: 'off' },
      supplyChain: { mode: 'off' },
      scanId: 'reasoning-html',
      now: '2026-08-11T00:00:00.000Z'
    });

    const html = await readFile(artifacts.report, 'utf8');
    assert.match(html, /Evidence Reasoning/);
    assert.match(html, /credential-exfiltration/);
    assert.match(html, /VIABLE/);
    assert.match(html, /Invariant Proof/);
    assert.match(html, /no-secret-network-composition/);
    assert.match(html, /VIOLATED/);
    assert.match(html, /negative evidence/i);
  });
});
