import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFile, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { scanRepository } from '../src/core/analyze.mjs';

const schemas = [
  ['report.schema.json', 'repotrial.report.v2'],
  ['runtime.schema.json', 'repotrial.runtime.v1'],
  ['supply-chain.schema.json', 'repotrial.supply-chain.v1'],
  ['differential.schema.json', 'repotrial.differential.v1'],
  ['artifact-proof.schema.json', 'repotrial.artifact-proof.v1'],
  ['causal.schema.json', 'repotrial.causal.v2'],
  ['hypotheses.schema.json', 'repotrial.hypothesis-discovery.v1'],
  ['threat-registry.schema.json', 'repotrial.threat-registry.v1']
];

test('published JSON schemas are valid JSON and declare current contract versions', async () => {
  for (const [name, version] of schemas) {
    const schema = JSON.parse(await readFile(new URL(`../schemas/${name}`, import.meta.url), 'utf8'));
    assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
    assert.equal(schema.type, 'object');
    const serialized = JSON.stringify(schema);
    assert.match(serialized, new RegExp(version.replaceAll('.', '\\.')));
  }
  const provenance = JSON.parse(await readFile(new URL('../schemas/provenance.schema.json', import.meta.url), 'utf8'));
  assert.equal(provenance.properties.predicateType.const, 'https://slsa.dev/provenance/v1');
});

test('generated artifacts use the versions published by the schemas', async () => {
  const outputDir = await mkdtemp(path.join(tmpdir(), 'repotrial-schema-artifacts-'));
  const root = fileURLToPath(new URL('./fixtures/cautious-agent/', import.meta.url));
  const result = await scanRepository({ root, outputDir, forgeos: { mode: 'off' }, runtime: { mode: 'off' }, supplyChain: { mode: 'offline' } });
  assert.equal(result.report.schemaVersion, 'repotrial.report.v2');
  assert.equal(JSON.parse(await readFile(result.artifacts.runtime, 'utf8')).schemaVersion, 'repotrial.runtime.v1');
  assert.equal(JSON.parse(await readFile(result.artifacts.supplyChain, 'utf8')).schemaVersion, 'repotrial.supply-chain.v1');
  assert.equal(JSON.parse(await readFile(result.artifacts.proof, 'utf8')).schemaVersion, 'repotrial.artifact-proof.v1');
  assert.equal(JSON.parse(await readFile(result.artifacts.provenance, 'utf8')).predicateType, 'https://slsa.dev/provenance/v1');
});
