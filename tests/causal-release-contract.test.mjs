import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import * as api from '../src/index.mjs';

async function text(path) { return readFile(new URL(`../${path}`, import.meta.url), 'utf8'); }
async function json(path) { return JSON.parse(await text(path)); }

test('RepoTrial 0.8 publishes causal reasoning, active verification and benchmark capabilities', async () => {
  const pkg = await json('package.json');
  const lock = await json('package-lock.json');
  assert.equal(pkg.version, '0.8.0');
  assert.equal(lock.version, '0.8.0');
  assert.equal(lock.packages[''].version, '0.8.0');
  assert.equal(Object.keys(pkg.dependencies ?? {}).length, 0);
  assert.equal(pkg.scripts['benchmark:adversarial'], 'node scripts/benchmark-adversarial.mjs');
  for (const name of ['getThreatRegistry','buildCausalSecurityGraph','synthesizeCausalAttackChains','analyzeCausalEvidence','planActiveExperiments','runCausalActiveExperiments','causalMeetsSeverity']) {
    assert.equal(typeof api[name], 'function', `${name} must be exported`);
  }
});

test('0.8 keeps causal analysis opt-in and publishes proof-bound schemas and documentation', async () => {
  const report = await json('schemas/report.schema.json');
  const causal = await json('schemas/causal.schema.json');
  const threatRegistry = await json('schemas/threat-registry.schema.json');
  assert.equal(report.required.includes('causal'), false);
  assert.equal(report.properties.causal.$ref, './causal.schema.json');
  assert.equal(causal.properties.schemaVersion.const, 'repotrial.causal.v2');
  assert.equal(threatRegistry.properties.schemaVersion.const, 'repotrial.threat-registry.v1');
  const docs = await text('docs/causal-adversarial-reasoning.md');
  assert.match(docs, /NOT_OBSERVED.*ABSENT/is);
  assert.match(docs, /active.*episode/is);
  assert.match(docs, /deterministic/i);
});

test('CI requires the repository-native adversarial benchmark', async () => {
  const ci = await text('.github/workflows/ci.yml');
  assert.match(ci, /npm run benchmark:adversarial/);
});
