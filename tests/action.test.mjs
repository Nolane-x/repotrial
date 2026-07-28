import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('GitHub Action exposes ForgeOS source checkout and powered depth inputs', async () => {
  const action = await readFile(new URL('../action.yml', import.meta.url), 'utf8');
  assert.match(action, /forgeos-root:/);
  assert.match(action, /forgeos-depth:/);
  assert.match(action, /INPUT_FORGEOS_ROOT/);
  assert.match(action, /INPUT_FORGEOS_DEPTH/);
});

test('ForgeOS compatibility workflow runs the real cross-repository acceptance gate', async () => {
  const workflow = await readFile(new URL('../.github/workflows/forgeos-compat.yml', import.meta.url), 'utf8');
  assert.match(workflow, /casioreview20-glitch\/forge-os/);
  assert.match(workflow, /verify:forgeos/);
  assert.match(workflow, /forge-root/);
});

test('GitHub Action exposes the SARIF artifact path', async () => {
  const action = await readFile(new URL('../action.yml', import.meta.url), 'utf8');
  assert.match(action, /sarif-path:/);
  assert.match(action, /sarif_path/);
});

test('GitHub output encoding prevents percent and newline command injection', async () => {
  const { encodeGithubCommandValue } = await import('../src/github.mjs');
  assert.equal(encodeGithubCommandValue('a%\r\nb'), 'a%25%0D%0Ab');
});

test('GitHub Action rejects an invalid fail-on threshold', async () => {
  const { normalizeActionThreshold } = await import('../src/github.mjs');
  assert.equal(normalizeActionThreshold('reckless'), 'RECKLESS');
  assert.throws(() => normalizeActionThreshold('banana'), /cautious, reckless, or dangerous/i);
});

test('GitHub Action exposes runtime, supply-chain, differential, signing, and code-scanning controls', async () => {
  const action = await readFile(new URL('../action.yml', import.meta.url), 'utf8');
  for (const input of ['runtime-mode:', 'supply-chain-mode:', 'baseline-ref:', 'fail-on-new:', 'signing-key:', 'sigstore:', 'sigstore-key:', 'upload-sarif:']) assert.match(action, new RegExp(input.replace('-', '\\-')));
  for (const output of ['sbom-path:', 'proof-path:', 'attestation-path:', 'sigstore-path:', 'new-findings:']) assert.match(action, new RegExp(output.replace('-', '\\-')));
  assert.match(action, /github\/codeql-action\/upload-sarif@v3/);
  assert.match(action, /sigstore\/cosign-installer@v3/);
});

test('CI tests maintained Node.js lines and builds the Docker image end to end', async () => {
  const workflow = await readFile(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8');
  assert.doesNotMatch(workflow, /20\.12/);
  assert.match(workflow, /node:\s*\['22',\s*'24'\]/);
  assert.match(workflow, /docker build/);
  assert.match(workflow, /docker run/);
});

test('Docker image uses maintained Node LTS and runs as a non-root user', async () => {
  const dockerfile = await readFile(new URL('../Dockerfile', import.meta.url), 'utf8');
  assert.match(dockerfile, /^FROM node:24\.18\.0-bookworm-slim$/m);
  assert.match(dockerfile, /^USER node$/m);
  assert.doesNotMatch(dockerfile, /^USER root$/m);
  assert.match(dockerfile, /util-linux/);
  assert.match(dockerfile, /ENTRYPOINT \["node", "\/app\/bin\/repotrial\.mjs"\]/);
});

test('GitHub Action exposes runtime source-copy budgets', async () => {
  const action = await readFile(new URL('../action.yml', import.meta.url), 'utf8');
  assert.match(action, /runtime-max-source-files:/);
  assert.match(action, /runtime-max-source-bytes:/);
  assert.match(action, /INPUT_RUNTIME_MAX_SOURCE_FILES/);
  assert.match(action, /INPUT_RUNTIME_MAX_SOURCE_BYTES/);
});


test('GitHub Action exposes operator path exclusions', async () => {
  const action = await readFile(new URL('../action.yml', import.meta.url), 'utf8');
  assert.match(action, /exclude-paths:/);
  assert.match(action, /INPUT_EXCLUDE_PATHS/);
  const runner = await readFile(new URL('../scripts/github-action.mjs', import.meta.url), 'utf8');
  assert.match(runner, /excludedPaths:\s*commaSeparated\(process\.env\.INPUT_EXCLUDE_PATHS\)/);
});
