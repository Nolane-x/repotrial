import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

async function json(path) {
  return JSON.parse(await readFile(new URL(`../${path}`, import.meta.url), 'utf8'));
}

test('causal v2 schema publishes evidence realms and optional autonomous discovery', async () => {
  const causal = await json('schemas/causal.schema.json');
  assert.equal(causal.properties.schemaVersion.const, 'repotrial.causal.v2');
  assert.deepEqual(causal.properties.mode.enum, ['analyze', 'discover', 'active']);
  assert.deepEqual(causal.properties.realmScope.enum, ['all', 'production']);
  assert.equal(causal.properties.discovery.$ref, './hypotheses.schema.json');
  assert.equal(causal.required.includes('discovery'), false);
  for (const field of ['realms', 'realmScope']) assert.equal(causal.required.includes(field), true, field);
});

test('hypothesis discovery schema is bounded and explicitly marks candidates as non-proof', async () => {
  const schema = await json('schemas/hypotheses.schema.json');
  assert.equal(schema.properties.schemaVersion.const, 'repotrial.hypothesis-discovery.v1');
  assert.equal(schema.properties.candidates.maxItems, 128);
  const candidate = schema.properties.candidates.items;
  assert.deepEqual(candidate.properties.state.enum, ['STRUCTURAL', 'CORROBORATED', 'PROMOTABLE', 'DISMISSED']);
  assert.equal(candidate.required.includes('noveltyScore'), true);
  assert.equal(candidate.required.includes('realmAssessment'), true);
  assert.equal(candidate.required.includes('caveat'), true);
});
