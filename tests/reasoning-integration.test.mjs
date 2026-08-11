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
    assert.deepEqual(report.verdict, calculateVerdict(report.charges, report.scan.coverage));
  });
});

test('package root exports the pure evidence reasoning engine', () => {
  assert.equal(typeof api.reasonAboutEvidence, 'function');
});

test('portable HTML report renders the evidence reasoning summary', async () => {
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
  });
});
