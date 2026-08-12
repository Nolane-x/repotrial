#!/usr/bin/env node
import { runAdversarialCorpus } from '../src/benchmark/adversarial-corpus.mjs';
const result = await runAdversarialCorpus();
console.log(JSON.stringify(result, null, 2));
const m = result.metrics;
if (m.threatRecall < 0.95 || m.activePrecision < 0.95 || m.stageRecall < 0.95 || m.benignFalsePositiveRate > 0.05 || m.deterministicReplayRatio !== 1) process.exitCode = 1;
