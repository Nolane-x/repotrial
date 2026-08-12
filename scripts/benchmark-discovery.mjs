#!/usr/bin/env node
import { runDiscoveryBenchmark } from '../src/benchmark/discovery-corpus.mjs';

const result = runDiscoveryBenchmark();
const { metrics, thresholds } = result;
console.log(JSON.stringify(result, null, 2));
if (metrics.novelCandidateRecall < thresholds.novelCandidateRecall
  || metrics.promotablePrecision < thresholds.promotablePrecision
  || metrics.benignProductionFalsePositiveRate > thresholds.benignProductionFalsePositiveRate
  || metrics.realmIsolationAccuracy < thresholds.realmIsolationAccuracy
  || metrics.deterministicReplayRatio < thresholds.deterministicReplayRatio) process.exitCode = 1;
