import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanRepository } from '../src/core/analyze.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.join(here, 'fixtures', 'reckless-agent');

function baseOptions(outputDir) {
  return {
    root: fixture,
    outputDir,
    forgeos: { mode: 'off' },
    runtime: { mode: 'off' },
    supplyChain: { mode: 'off' },
    now: '2026-08-12T00:00:00.000Z',
    scanId: 'experiment-scan-contract'
  };
}

test('experiment off mode preserves the 0.5 report shape and verdict semantics', async () => {
  const outA = await mkdtemp(path.join(tmpdir(), 'repotrial-exp-off-a-'));
  const outB = await mkdtemp(path.join(tmpdir(), 'repotrial-exp-off-b-'));
  const legacy = await scanRepository(baseOptions(outA));
  const explicitOff = await scanRepository({ ...baseOptions(outB), experiments: { mode: 'off' } });
  assert.equal('experiments' in legacy.report, false);
  assert.equal('experiments' in explicitOff.report, false);
  assert.deepEqual(explicitOff.report.verdict, legacy.report.verdict);
  assert.deepEqual(explicitOff.report.reasoning, legacy.report.reasoning);
  assert.equal(explicitOff.report.receipt.sha256, legacy.report.receipt.sha256);
});

test('plan mode attaches a deterministic experiment plan without executing or changing verdict', async () => {
  const outOff = await mkdtemp(path.join(tmpdir(), 'repotrial-exp-plan-off-'));
  const outPlan = await mkdtemp(path.join(tmpdir(), 'repotrial-exp-plan-on-'));
  const off = await scanRepository(baseOptions(outOff));
  const planned = await scanRepository({
    ...baseOptions(outPlan),
    experiments: { mode: 'plan', maxRuns: 2, maxPerCandidate: 1 }
  });
  assert.equal(planned.report.experiments.schemaVersion, 'repotrial.experiments.v1');
  assert.equal(planned.report.experiments.mode, 'plan');
  assert.equal(planned.report.experiments.status, 'planned');
  assert.ok(planned.report.experiments.plan.experiments.length > 0);
  assert.equal(planned.report.experiments.runs.length, 0);
  assert.equal(planned.report.experiments.observations.length, 0);
  assert.deepEqual(planned.report.verdict, off.report.verdict);
  assert.deepEqual(planned.report.reasoning, off.report.reasoning);
  assert.equal(planned.report.experiments.epistemicDelta.summary.hypothesisTransitionCount, 0);
});

test('plan mode writes an experiments artifact that is included in the artifact proof', async () => {
  const outputDir = await mkdtemp(path.join(tmpdir(), 'repotrial-exp-artifact-'));
  const result = await scanRepository({
    ...baseOptions(outputDir),
    experiments: { mode: 'plan', maxRuns: 1, maxPerCandidate: 1 }
  });
  assert.ok((await stat(path.join(outputDir, 'experiments.json'))).isFile());
  assert.equal(result.artifacts.experiments, path.join(outputDir, 'experiments.json'));
  assert.equal(result.proof.artifacts.some((item) => item.path === 'experiments.json'), true);
});
