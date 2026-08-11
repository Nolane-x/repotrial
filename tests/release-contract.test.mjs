import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

async function json(path) {
  return JSON.parse(await readFile(new URL(`../${path}`, import.meta.url), 'utf8'));
}

test('RepoTrial 0.5 package metadata points at the canonical Nolane-x repository', async () => {
  const pkg = await json('package.json');
  const lock = await json('package-lock.json');

  assert.equal(pkg.version, '0.5.0');
  assert.equal(lock.version, pkg.version);
  assert.equal(lock.packages[''].version, pkg.version);
  assert.equal(pkg.repository.url, 'git+https://github.com/Nolane-x/repotrial.git');
  assert.equal(pkg.homepage, 'https://github.com/Nolane-x/repotrial#readme');
  assert.equal(pkg.bugs.url, 'https://github.com/Nolane-x/repotrial/issues');
});

test('report schema requires and references the evidence reasoning contract', async () => {
  const reportSchema = await json('schemas/report.schema.json');
  const reasoningSchema = await json('schemas/reasoning.schema.json');

  assert.ok(reportSchema.required.includes('reasoning'));
  assert.equal(reportSchema.properties.reasoning.$ref, './reasoning.schema.json');
  assert.equal(reasoningSchema.properties.schemaVersion.const, 'repotrial.reasoning.v1');
  assert.equal(reasoningSchema.required.includes('graph'), true);
  assert.equal(reasoningSchema.required.includes('hypotheses'), true);
  assert.equal(reasoningSchema.required.includes('attackPaths'), true);
  assert.equal(reasoningSchema.required.includes('remediation'), true);
});

test('analysis does not carry an independent hard-coded package version', async () => {
  const source = await readFile(new URL('../src/core/analyze.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /const VERSION\s*=\s*['\"]\d+\.\d+\.\d+['\"]/);
  assert.match(source, /PACKAGE_VERSION/);
});
