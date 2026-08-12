import { readFile, mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { scanRepository } from '../core/analyze.mjs';
import { sha256, stableStringify } from '../core/hash.mjs';

const DEFAULT_MANIFEST = new URL('../../tests/adversarial-corpus/manifest.json', import.meta.url);
const DEFAULT_CASES = fileURLToPath(new URL('../../tests/adversarial-corpus/cases/', import.meta.url));
const ACTIVE = new Set(['PROVEN', 'SUPPORTED']);

export async function runAdversarialCorpus(options = {}) {
  const manifest = options.manifest ?? JSON.parse(await readFile(options.manifestUrl ?? DEFAULT_MANIFEST, 'utf8'));
  validateManifest(manifest);
  const casesRoot = path.resolve(options.casesRoot ?? DEFAULT_CASES);
  const results = [];
  let expectedThreats = 0;
  let detectedExpectedThreats = 0;
  let activePredictions = 0;
  let allowedActivePredictions = 0;
  let expectedStages = 0;
  let detectedStages = 0;
  let benignWithActive = 0;
  let deterministicCases = 0;
  let benignCases = 0;

  for (const definition of [...manifest.cases].sort((a, b) => a.id.localeCompare(b.id))) {
    const root = path.join(casesRoot, definition.id);
    const first = await scanCase(root, definition.id, options.scanRepository ?? scanRepository);
    const second = await scanCase(root, definition.id, options.scanRepository ?? scanRepository);
    const chains = first.causal.reasoning?.chains ?? [];
    const activeThreatIds = uniqueSorted(chains.filter((item) => ACTIVE.has(item.state)).map((item) => item.threatId));
    const observedStages = uniqueSorted(chains.flatMap((chain) =>
      (chain.stages ?? []).filter((stage) => stage.satisfied).map((stage) => `${chain.threatId}:${stage.id}`)));
    const expected = uniqueSorted(definition.expectedActiveThreatIds);
    const allowed = new Set(uniqueSorted(definition.allowedActiveThreatIds));
    const expectedStageIds = uniqueSorted(definition.expectedObservedStages);
    const expectedSet = new Set(expected);
    const observedSet = new Set(observedStages);

    expectedThreats += expected.length;
    detectedExpectedThreats += expected.filter((id) => activeThreatIds.includes(id)).length;
    activePredictions += activeThreatIds.length;
    allowedActivePredictions += activeThreatIds.filter((id) => allowed.has(id)).length;
    expectedStages += expectedStageIds.length;
    detectedStages += expectedStageIds.filter((id) => observedSet.has(id)).length;
    if (definition.benign) {
      benignCases += 1;
      if (activeThreatIds.length) benignWithActive += 1;
    }
    const deterministic = first.causal.receipt === second.causal.receipt;
    if (deterministic) deterministicCases += 1;

    results.push({
      id: definition.id,
      benign: Boolean(definition.benign),
      expectedActiveThreatIds: expected,
      activeThreatIds,
      missedThreatIds: expected.filter((id) => !activeThreatIds.includes(id)),
      unexpectedActiveThreatIds: activeThreatIds.filter((id) => !allowed.has(id)),
      expectedObservedStages: expectedStageIds,
      missedObservedStages: expectedStageIds.filter((id) => !observedSet.has(id)),
      deterministic,
      causalReceipt: first.causal.receipt,
      activeChainCount: chains.filter((item) => ACTIVE.has(item.state)).length,
      expectedThreatHitCount: activeThreatIds.filter((id) => expectedSet.has(id)).length
    });
  }

  const metrics = {
    threatRecall: ratio(detectedExpectedThreats, expectedThreats),
    activePrecision: ratio(allowedActivePredictions, activePredictions),
    stageRecall: ratio(detectedStages, expectedStages),
    benignFalsePositiveRate: ratio(benignWithActive, benignCases),
    deterministicReplayRatio: ratio(deterministicCases, results.length)
  };
  const summary = {
    caseCount: results.length,
    benignCaseCount: benignCases,
    expectedThreatCount: expectedThreats,
    activePredictionCount: activePredictions,
    expectedStageCount: expectedStages
  };
  const body = { schemaVersion: 'repotrial.adversarial-corpus-result.v1', summary, metrics, cases: results };
  return { ...body, receipt: sha256(stableStringify(body)) };
}

async function scanCase(root, id, scanner) {
  const outputDir = await mkdtemp(path.join(tmpdir(), `repotrial-corpus-${safeId(id)}-`));
  try {
    const result = await scanner({
      root,
      outputDir,
      forgeos: { mode: 'off' },
      runtime: { mode: 'off' },
      supplyChain: { mode: 'off' },
      experiments: { mode: 'off' },
      causal: { mode: 'analyze' },
      scanId: `corpus-${id}`,
      now: '2026-08-12T00:00:00.000Z'
    });
    if (!result.report.causal) throw new Error(`Corpus case ${id} produced no causal analysis.`);
    return { causal: result.report.causal };
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
}

function validateManifest(manifest) {
  if (manifest?.schemaVersion !== 'repotrial.adversarial-corpus.v1' || !Array.isArray(manifest.cases) || manifest.cases.length < 12) {
    throw new Error('Adversarial corpus manifest must contain at least 12 versioned cases.');
  }
  const ids = new Set();
  for (const item of manifest.cases) {
    if (!item || typeof item.id !== 'string' || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(item.id)) throw new Error('Invalid adversarial corpus case id.');
    if (ids.has(item.id)) throw new Error(`Duplicate adversarial corpus case: ${item.id}`);
    ids.add(item.id);
    for (const key of ['expectedActiveThreatIds', 'allowedActiveThreatIds', 'expectedObservedStages']) if (!Array.isArray(item[key])) throw new Error(`Corpus case ${item.id} must define ${key}.`);
  }
}

function ratio(numerator, denominator) {
  if (!denominator) return 1;
  return Math.round((numerator / denominator) * 1_000_000) / 1_000_000;
}
function uniqueSorted(values) { return [...new Set((Array.isArray(values) ? values : []).map(String))].sort(); }
function safeId(value) { return String(value).replace(/[^a-z0-9-]/gi, '-').slice(0, 48); }
