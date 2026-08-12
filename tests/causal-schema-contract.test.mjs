import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('report schema keeps causal optional and references the causal contract', async () => {
  const report = JSON.parse(await readFile(new URL('../schemas/report.schema.json', import.meta.url), 'utf8'));
  assert.equal(report.properties.causal.$ref, './causal.schema.json');
  assert.equal(report.required.includes('causal'), false);
});

test('differential schema publishes the optional causal differential contract', async () => {
  const schema = JSON.parse(await readFile(new URL('../schemas/differential.schema.json', import.meta.url), 'utf8'));
  const causal = schema.properties.causal;
  assert.equal(causal.properties.schemaVersion.const, 'repotrial.causal-differential.v1');
  assert.deepEqual(causal.required, ['schemaVersion', 'newActive', 'existingActive', 'resolvedActive', 'regressed', 'improved', 'changed', 'summary', 'receipt']);
  assert.equal(schema.required.includes('causal'), false);
});
