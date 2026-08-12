import test from 'node:test';
import assert from 'node:assert/strict';
import { runDiscoveryBenchmark } from '../src/benchmark/discovery-corpus.mjs';

test('autonomous discovery corpus meets novelty, precision, realm isolation, and replay gates', () => {
  const result = runDiscoveryBenchmark();
  assert.equal(result.schemaVersion, 'repotrial.discovery-benchmark.v1');
  assert.ok(result.caseCount >= 9);
  assert.ok(result.metrics.novelCandidateRecall >= 0.95);
  assert.ok(result.metrics.promotablePrecision >= 0.95);
  assert.ok(result.metrics.benignProductionFalsePositiveRate <= 0.05);
  assert.equal(result.metrics.realmIsolationAccuracy, 1);
  assert.equal(result.metrics.deterministicReplayRatio, 1);
});
