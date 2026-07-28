import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('release workflow verifies, publishes provenance, signs artifacts, and attaches checksums', async () => {
  const workflow = await readFile(new URL('../.github/workflows/release.yml', import.meta.url), 'utf8');
  assert.match(workflow, /id-token:\s*write/);
  assert.match(workflow, /npm publish[^\n]*--provenance/);
  assert.match(workflow, /cosign sign-blob/);
  assert.match(workflow, /repotrial\.mjs verify/);
  assert.match(workflow, /sha256sum/);
  assert.match(workflow, /docker build/);
});
