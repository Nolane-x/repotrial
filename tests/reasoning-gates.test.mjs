import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { execFile } from 'node:child_process';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const exec = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const cli = path.join(root, 'bin', 'repotrial.mjs');

function run(args, cwd = root) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [cli, ...args], { cwd, env: { ...process.env, NO_COLOR: '1' } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

async function writeRiskyAgent(project) {
  await writeFile(path.join(project, 'AGENTS.md'), [
    '# Agent policy',
    'shell: true',
    'network: *',
    'env: ${OPENAI_API_KEY}'
  ].join('\n'));
}

test('scan help documents reasoning-aware gates', async () => {
  const result = await run(['scan', '--help']);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /--fail-on-reasoning/);
  assert.match(result.stdout, /--fail-on-new-reasoning/);
});

test('overall reasoning gate exits 4 for active critical hypotheses or invariant violations', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'repotrial-reasoning-gate-'));
  const output = await mkdtemp(path.join(tmpdir(), 'repotrial-reasoning-gate-output-'));
  await writeFile(path.join(project, 'package.json'), JSON.stringify({ scripts: { test: 'node --test' } }));
  await writeRiskyAgent(project);

  const result = await run([
    'scan', project,
    '--output', output,
    '--forgeos', 'off',
    '--runtime', 'off',
    '--supply-chain', 'off',
    '--fail-on-reasoning', 'critical',
    '--json'
  ]);

  assert.equal(result.code, 4);
  const summary = JSON.parse(result.stdout);
  assert.ok(summary.viableAttackPaths >= 1);
  assert.ok(summary.invariantViolations >= 1);
});

test('new reasoning regression gate exits 5 when a Git diff introduces a critical attack path or invariant violation', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'repotrial-new-reasoning-gate-'));
  const output = await mkdtemp(path.join(tmpdir(), 'repotrial-new-reasoning-gate-output-'));
  await exec('git', ['init', '-b', 'main'], { cwd: project });
  await exec('git', ['config', 'user.email', 'test@example.com'], { cwd: project });
  await exec('git', ['config', 'user.name', 'RepoTrial Test'], { cwd: project });
  await writeFile(path.join(project, 'package.json'), JSON.stringify({ scripts: { test: 'node --test' } }));
  await exec('git', ['add', '.'], { cwd: project });
  await exec('git', ['commit', '-m', 'safe baseline'], { cwd: project });
  const baseline = (await exec('git', ['rev-parse', 'HEAD'], { cwd: project })).stdout.trim();
  await writeRiskyAgent(project);

  const result = await run([
    'scan', project,
    '--output', output,
    '--forgeos', 'off',
    '--runtime', 'off',
    '--supply-chain', 'off',
    '--baseline-ref', baseline,
    '--fail-on-new-reasoning', 'critical',
    '--json'
  ]);

  assert.equal(result.code, 5);
  const summary = JSON.parse(result.stdout);
  assert.ok(summary.newReasoning.newViableAttackPaths >= 1 || summary.newReasoning.newInvariantViolations >= 1);
});

test('reasoning gate validates severity threshold values', async () => {
  const result = await run(['scan', '.', '--fail-on-reasoning', 'impossible']);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /reasoning threshold/i);
});
