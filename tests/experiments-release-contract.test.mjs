import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as api from '../src/index.mjs';
import { scanRepository } from '../src/core/analyze.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const fixture = path.join(here, 'fixtures', 'reckless-agent');

async function text(relative) { return readFile(path.join(root, relative), 'utf8'); }

test('RepoTrial 0.6 package and public API publish adaptive experiment capabilities', async () => {
  const pkg = JSON.parse(await text('package.json'));
  assert.equal(pkg.version, '0.6.0');
  assert.equal(Object.keys(pkg.dependencies ?? {}).length, 0);
  for (const name of [
    'planAdaptiveExperiments', 'getExperimentTemplate', 'validateExperimentScenario',
    'classifyExperimentObservation', 'experimentObservationsToCharges', 'buildEpistemicDelta', 'runAdaptiveExperiments'
  ]) assert.equal(typeof api[name], 'function', `${name} must be exported`);
});

test('published schemas expose an optional repotrial.experiments.v1 contract', async () => {
  const experiments = JSON.parse(await text('schemas/experiments.schema.json'));
  const report = JSON.parse(await text('schemas/report.schema.json'));
  assert.equal(experiments.properties.schemaVersion.const, 'repotrial.experiments.v1');
  assert.ok(experiments.required.includes('mode'));
  assert.ok(experiments.required.includes('epistemicDelta'));
  assert.equal(report.properties.experiments.$ref, './experiments.schema.json');
  assert.equal(report.required.includes('experiments'), false);
});

test('CLI and GitHub Action expose bounded experiment controls while defaulting execution off', async () => {
  const cli = await text('src/cli.mjs');
  const action = await text('action.yml');
  const runner = await text('scripts/github-action.mjs');
  for (const flag of ['--experiments', '--experiment-max-runs', '--experiment-max-per-candidate', '--experiment-timeout']) assert.match(cli, new RegExp(flag));
  assert.match(action, /experiment-mode:/);
  assert.match(action, /default: ['"]?off['"]?/);
  assert.match(action, /experiment-max-runs:/);
  assert.match(action, /experiment-max-per-candidate:/);
  assert.match(action, /experiment-timeout:/);
  assert.match(runner, /INPUT_EXPERIMENT_MODE/);
});

test('portable report renders Adaptive Experiments and epistemic caveat in plan mode', async () => {
  const outputDir = await mkdtemp(path.join(tmpdir(), 'repotrial-exp-release-html-'));
  const result = await scanRepository({
    root: fixture, outputDir, forgeos: { mode: 'off' }, runtime: { mode: 'off' }, supplyChain: { mode: 'off' },
    experiments: { mode: 'plan', maxRuns: 1, maxPerCandidate: 1 }, scanId: 'release-contract', now: '2026-08-12T00:00:00.000Z'
  });
  const html = await readFile(result.artifacts.report, 'utf8');
  assert.match(html, /Adaptive Experiments/i);
  assert.match(html, /NOT_OBSERVED/i);
  assert.match(html, /not proof of absence/i);
});
