import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  normalizeCausalThreshold,
  causalMeetsSeverity,
  causalDifferentialMeetsSeverity
} from '../src/reasoning/causal-gates.mjs';

async function text(path) {
  return readFile(new URL(`../${path}`, import.meta.url), 'utf8');
}

test('shared causal gate helpers validate thresholds and active causal states', () => {
  assert.equal(normalizeCausalThreshold('CRITICAL', '--gate'), 'critical');
  assert.throws(() => normalizeCausalThreshold('impossible', '--gate'), /causal threshold/i);
  assert.equal(causalMeetsSeverity({ reasoning: { chains: [{ state: 'PROVEN', severity: 'critical' }] } }, 'critical'), true);
  assert.equal(causalMeetsSeverity({ reasoning: { chains: [{ state: 'PARTIAL', severity: 'critical' }] } }, 'critical'), false);
  assert.equal(causalDifferentialMeetsSeverity({ newActive: [{ severity: 'high' }], threats: { regressed: [] } }, 'high'), true);
});

test('GitHub Action exposes causal modes, budgets, gates and outputs', async () => {
  const action = await text('action.yml');
  for (const token of [
    'causal-mode:',
    'causal-max-depth:',
    'causal-max-chains:',
    'causal-max-runs:',
    'causal-max-per-candidate:',
    'causal-timeout:',
    'fail-on-causal:',
    'fail-on-new-causal:',
    'causal-active-chains:',
    'causal-high-impact-active-chains:',
    'new-causal-active-chains:',
    'causal-path:'
  ]) assert.match(action, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  for (const env of [
    'INPUT_CAUSAL_MODE', 'INPUT_CAUSAL_MAX_DEPTH', 'INPUT_CAUSAL_MAX_CHAINS',
    'INPUT_CAUSAL_MAX_RUNS', 'INPUT_CAUSAL_MAX_PER_CANDIDATE', 'INPUT_CAUSAL_TIMEOUT',
    'INPUT_FAIL_ON_CAUSAL', 'INPUT_FAIL_ON_NEW_CAUSAL'
  ]) assert.match(action, new RegExp(env));
});

test('GitHub Action runner uses shared causal gates and exposes causal artifacts', async () => {
  const source = await text('scripts/github-action.mjs');
  assert.match(source, /reasoning\/causal-gates\.mjs/);
  assert.match(source, /INPUT_CAUSAL_MODE/);
  assert.match(source, /INPUT_FAIL_ON_CAUSAL/);
  assert.match(source, /INPUT_FAIL_ON_NEW_CAUSAL/);
  assert.match(source, /causal_active_chains/);
  assert.match(source, /causal_high_impact_active_chains/);
  assert.match(source, /new_causal_active_chains/);
  assert.match(source, /causal_path/);
  assert.match(source, /process\.exitCode = 6/);
  assert.match(source, /process\.exitCode = 7/);
});
