import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import * as api from '../src/index.mjs';

async function text(path) { return readFile(new URL(`../${path}`, import.meta.url), 'utf8'); }
async function json(path) { return JSON.parse(await text(path)); }

test('RepoTrial 0.8 publishes autonomous threat discovery and evidence-realm APIs', async () => {
  const pkg = await json('package.json');
  const lock = await json('package-lock.json');
  const manifest = await json('project-manifest.json');
  assert.equal(pkg.version, '0.8.0');
  assert.equal(lock.version, '0.8.0');
  assert.equal(lock.packages[''].version, '0.8.0');
  assert.equal(manifest.version, '0.8.0');
  assert.equal(Object.keys(pkg.dependencies ?? {}).length, 0);
  assert.equal(pkg.scripts['benchmark:discovery'], 'node scripts/benchmark-discovery.mjs');
  for (const name of [
    'classifyEvidencePath', 'buildEvidenceRealmIndex', 'assessChainRealm',
    'getCapabilitySemantics', 'discoverThreatHypotheses', 'promoteDiscoveredHypothesis',
    'runDiscoveryBenchmark'
  ]) assert.equal(typeof api[name], 'function', `${name} must be exported`);
});

test('0.8 publishes hypothesis schema, autonomous discovery docs, and bounded product controls', async () => {
  const pkg = await json('package.json');
  const hypotheses = await json('schemas/hypotheses.schema.json');
  const causal = await json('schemas/causal.schema.json');
  assert.equal(hypotheses.properties.schemaVersion.const, 'repotrial.hypothesis-discovery.v1');
  assert.equal(causal.properties.schemaVersion.const, 'repotrial.causal.v2');
  assert.ok(pkg.files.includes('docs/autonomous-threat-discovery.md'));
  const docs = await text('docs/autonomous-threat-discovery.md');
  assert.match(docs, /Evidence Realms/i);
  assert.match(docs, /candidate.*not proven/is);
  assert.match(docs, /production/i);
  const cli = await text('src/cli.mjs');
  assert.match(cli, /--causal-realm-scope/);
  assert.match(cli, /--causal-max-discovered/);
  assert.match(cli, /--causal-min-novelty/);
  const action = await text('action.yml');
  assert.match(action, /causal-realm-scope:/);
  assert.match(action, /hypotheses-path:/);
});

test('CI requires both adversarial and autonomous-discovery benchmarks', async () => {
  const ci = await text('.github/workflows/ci.yml');
  assert.match(ci, /npm run benchmark:adversarial/);
  assert.match(ci, /npm run benchmark:discovery/);
});
