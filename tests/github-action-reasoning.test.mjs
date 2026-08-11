import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  normalizeReasoningThreshold,
  reasoningMeetsSeverity,
  reasoningDifferentialMeetsSeverity
} from '../src/reasoning/gates.mjs';

async function text(path) {
  return readFile(new URL(`../${path}`, import.meta.url), 'utf8');
}

test('shared reasoning gate helpers validate thresholds and risk states', () => {
  assert.equal(normalizeReasoningThreshold('CRITICAL', '--gate'), 'critical');
  assert.throws(() => normalizeReasoningThreshold('impossible', '--gate'), /reasoning threshold/i);

  assert.equal(reasoningMeetsSeverity({
    hypotheses: [{ state: 'PROVEN', severity: 'critical' }],
    invariants: { results: [] }
  }, 'critical'), true);
  assert.equal(reasoningMeetsSeverity({
    hypotheses: [{ state: 'UNKNOWN', severity: 'critical' }],
    invariants: { results: [{ state: 'SATISFIED', severity: 'critical' }] }
  }, 'critical'), false);

  assert.equal(reasoningDifferentialMeetsSeverity({
    attackPaths: { new: [{ severity: 'critical' }] },
    invariants: { newViolations: [] },
    hypotheses: { regressed: [] }
  }, 'critical'), true);
});

test('GitHub Action exposes reasoning gate inputs and outputs', async () => {
  const action = await text('action.yml');
  for (const token of [
    'fail-on-reasoning:',
    'fail-on-new-reasoning:',
    'viable-attack-paths:',
    'invariant-violations:',
    'new-viable-attack-paths:',
    'new-invariant-violations:'
  ]) assert.match(action, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  assert.match(action, /INPUT_FAIL_ON_REASONING/);
  assert.match(action, /INPUT_FAIL_ON_NEW_REASONING/);
});

test('GitHub Action runner uses the shared reasoning gate implementation', async () => {
  const source = await text('scripts/github-action.mjs');
  assert.match(source, /reasoning\/gates\.mjs/);
  assert.match(source, /INPUT_FAIL_ON_REASONING/);
  assert.match(source, /INPUT_FAIL_ON_NEW_REASONING/);
  assert.match(source, /viable_attack_paths/);
  assert.match(source, /invariant_violations/);
  assert.match(source, /new_viable_attack_paths/);
  assert.match(source, /new_invariant_violations/);
});
