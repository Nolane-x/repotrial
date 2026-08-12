import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanRepository } from '../src/core/analyze.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('RepoTrial dogfood keeps its malicious corpus chains visible without treating them as production-active', async () => {
  const outputDir = await mkdtemp(path.join(tmpdir(), 'repotrial-self-dogfood-realms-'));
  const result = await scanRepository({
    root,
    outputDir,
    forgeos: { mode: 'off' },
    runtime: { mode: 'off' },
    supplyChain: { mode: 'offline' },
    causal: { mode: 'analyze', realmScope: 'production' }
  });
  const activeCodeExecution = result.report.causal.reasoning.chains.filter((chain) =>
    chain.threatId === 'arbitrary-code-execution' && ['PROVEN', 'SUPPORTED'].includes(chain.state));
  assert.ok(activeCodeExecution.length >= 1, 'dogfood should keep adversarial/fixture code-execution evidence visible');
  assert.ok(activeCodeExecution.every((chain) => chain.realmAssessment?.productionRelevant === false));
  assert.equal(result.report.causal.summary.productionActiveChainCount, 0);
  assert.ok(result.report.causal.summary.nonProductionActiveChainCount + result.report.causal.summary.crossRealmUnprovenActiveChainCount >= 1);
});
