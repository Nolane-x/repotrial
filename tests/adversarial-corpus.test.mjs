import test from 'node:test';
import assert from 'node:assert/strict';
import { runAdversarialCorpus } from '../src/benchmark/adversarial-corpus.mjs';

test('repository-native adversarial corpus meets deterministic precision and recall gates', async () => {
  const result = await runAdversarialCorpus();
  assert.equal(result.summary.caseCount >= 12, true);
  assert.equal(result.metrics.threatRecall >= 0.95, true, JSON.stringify(result.metrics));
  assert.equal(result.metrics.activePrecision >= 0.95, true, JSON.stringify(result.metrics));
  assert.equal(result.metrics.stageRecall >= 0.95, true, JSON.stringify(result.metrics));
  assert.equal(result.metrics.benignFalsePositiveRate <= 0.05, true, JSON.stringify(result.metrics));
  assert.equal(result.metrics.deterministicReplayRatio, 1);
  assert.match(result.receipt, /^[a-f0-9]{64}$/);
});
