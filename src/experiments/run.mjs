import { planAdaptiveExperiments } from './planner.mjs';
import { classifyExperimentObservation } from './observe.mjs';
import { experimentObservationsToCharges } from './evidence.mjs';
import { runRuntimeScenario } from '../runtime/sandbox.mjs';

const MODES = new Set(['off', 'plan', 'sandbox']);

export async function runAdaptiveExperiments(options = {}) {
  const mode = String(options.mode ?? 'off').toLowerCase();
  if (!MODES.has(mode)) throw new Error('Experiment mode must be off, plan, or sandbox.');
  const emptyPlan = {
    schemaVersion: 'repotrial.experiment-plan.v1',
    budget: { maxExperiments: 0, maxPerCandidate: 0, hardMaxExperiments: 32, hardMaxPerCandidate: 8 },
    experiments: [],
    summary: { partialPathCount: 0, addressablePathCount: 0, candidateCount: 0, plannedExperimentCount: 0, truncatedByBudget: false }
  };
  if (mode === 'off') return buildResult({ mode, status: 'disabled', plan: emptyPlan, runs: [], observations: [], charges: [] });

  const plan = planAdaptiveExperiments({
    reasoning: options.reasoning,
    candidates: options.candidates,
    maxExperiments: options.maxExperiments,
    maxPerCandidate: options.maxPerCandidate
  });
  if (mode === 'plan') return buildResult({ mode, status: 'planned', plan, runs: [], observations: [], charges: [] });
  if (!plan.experiments.length) return buildResult({ mode, status: 'skipped', plan, runs: [], observations: [], charges: [] });

  const executeBaseline = options.executeBaseline ?? defaultBaselineExecutor;
  const executeScenario = options.executeScenario ?? defaultScenarioExecutor;
  const baselineCache = new Map();
  const runs = [];
  const observations = [];

  for (const experiment of plan.experiments) {
    const candidateKey = experiment.candidate.id;
    let baseline = baselineCache.get(candidateKey);
    if (!baseline) {
      baseline = await safeExecute(() => executeBaseline({
        root: options.root,
        candidate: experiment.candidate,
        scanId: options.scanId,
        timeoutMs: options.timeoutMs,
        maxSourceFiles: options.maxSourceFiles,
        maxSourceBytes: options.maxSourceBytes,
        ignoredPaths: options.ignoredPaths
      }));
      baselineCache.set(candidateKey, baseline);
    }

    const scenario = await safeExecute(() => executeScenario({
      root: options.root,
      candidate: experiment.candidate,
      scenario: experiment.scenario,
      experiment,
      scanId: options.scanId,
      canarySeed: `${String(options.scanId ?? 'repotrial')}\0${experiment.id}`,
      timeoutMs: options.timeoutMs,
      maxSourceFiles: options.maxSourceFiles,
      maxSourceBytes: options.maxSourceBytes,
      ignoredPaths: options.ignoredPaths
    }));

    const baselineRun = internalRun(baseline);
    const scenarioRun = internalRun(scenario);
    const canaries = internalCanaries(scenario);
    const observation = classifyExperimentObservation({
      experiment,
      baselineRun,
      scenarioRun,
      canaries,
      sentinelPaths: experiment.scenario.sentinelPaths
    });
    observations.push(observation);
    runs.push({
      experimentId: experiment.id,
      candidateId: experiment.candidate.id,
      baselineStatus: String(baseline?.status ?? 'unavailable'),
      scenarioStatus: String(scenario?.status ?? 'unavailable'),
      provider: scenario?.provider ?? baseline?.provider ?? null,
      canaryFingerprints: canaries.map(({ key, fingerprint }) => ({ key, fingerprint })),
      sentinelPaths: [...experiment.scenario.sentinelPaths],
      observationId: observation.id,
      observationState: observation.state
    });
  }

  const charges = experimentObservationsToCharges({ observations, snapshot: options.snapshot });
  const positive = observations.filter((item) => item.state === 'OBSERVED').length;
  const triggered = observations.filter((item) => item.state === 'TRIGGERED').length;
  const inconclusive = observations.filter((item) => item.state === 'INCONCLUSIVE').length;
  const status = inconclusive === observations.length ? 'inconclusive' : 'completed';
  return buildResult({ mode, status, plan, runs, observations, charges, positive, triggered, inconclusive });
}

async function defaultBaselineExecutor(options) {
  return runRuntimeScenario({
    root: options.root,
    candidate: options.candidate,
    scenario: { templateId: 'ci-context-trigger-v1', envKeys: [], sentinelPaths: [] },
    canarySeed: `${String(options.scanId ?? 'repotrial')}\0baseline\0${String(options.candidate?.id ?? '')}`,
    timeoutMs: options.timeoutMs,
    maxSourceFiles: options.maxSourceFiles,
    maxSourceBytes: options.maxSourceBytes,
    ignoredPaths: options.ignoredPaths
  });
}

async function defaultScenarioExecutor(options) {
  return runRuntimeScenario({
    root: options.root,
    candidate: options.candidate,
    scenario: options.scenario,
    canarySeed: options.canarySeed,
    timeoutMs: options.timeoutMs,
    maxSourceFiles: options.maxSourceFiles,
    maxSourceBytes: options.maxSourceBytes,
    ignoredPaths: options.ignoredPaths
  });
}

async function safeExecute(callback) {
  try { return await callback(); }
  catch (error) {
    return { status: 'unavailable', provider: null, reason: String(error?.message ?? error), run: null, canaries: [] };
  }
}

function internalRun(result) {
  if (!result || typeof result !== 'object') return null;
  return result.rawRun ?? result.run ?? null;
}

function internalCanaries(result) {
  if (!result || typeof result !== 'object') return [];
  const canaries = result.canaries;
  if (!Array.isArray(canaries)) return [];
  return canaries
    .filter((item) => item && typeof item === 'object' && item.value != null)
    .map((item) => ({ key: String(item.key ?? 'CANARY'), value: String(item.value), fingerprint: String(item.fingerprint ?? '') }));
}

function buildResult({ mode, status, plan, runs, observations, charges, positive, triggered, inconclusive }) {
  const observed = positive ?? observations.filter((item) => item.state === 'OBSERVED').length;
  const contextual = triggered ?? observations.filter((item) => item.state === 'TRIGGERED').length;
  const uncertain = inconclusive ?? observations.filter((item) => item.state === 'INCONCLUSIVE').length;
  const notObserved = observations.filter((item) => item.state === 'NOT_OBSERVED').length;
  return {
    schemaVersion: 'repotrial.experiments.v1',
    mode,
    status,
    budget: { ...plan.budget },
    plan,
    runs,
    observations,
    charges,
    epistemicDelta: null,
    summary: {
      plannedExperimentCount: plan.experiments.length,
      executedExperimentCount: runs.length,
      positiveObservationCount: observed,
      triggeredObservationCount: contextual,
      notObservedCount: notObserved,
      inconclusiveObservationCount: uncertain,
      experimentChargeCount: charges.length
    }
  };
}
