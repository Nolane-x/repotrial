import { sha256, stableStringify } from '../core/hash.mjs';
import { buildAdversarialEpisode, executeAdversarialEpisode } from './episodes.mjs';
import { buildCausalTrace } from './causal-trace.mjs';
import { experimentObservationsToCharges } from './evidence.mjs';

const TEMPLATE_TO_EPISODE = Object.freeze({
  'secret-egress-canary-v1': 'secret-propagation-episode-v1',
  'filesystem-sentinel-v1': 'filesystem-destruction-episode-v1',
  'ci-context-trigger-v1': 'ci-conditional-episode-v1',
  'memory-persistence-v1': 'memory-persistence-episode-v1'
});

export async function runCausalActiveExperiments(options = {}) {
  const plan = options.causal?.activePlan ?? emptyPlan();
  const episodeExecutor = typeof options.episodeExecutor === 'function' ? options.episodeExecutor : executeAdversarialEpisode;
  const episodeResults = [];
  const traces = [];
  const observations = [];

  for (const experiment of plan.experiments ?? []) {
    const episodeTemplateId = TEMPLATE_TO_EPISODE[experiment.templateId];
    if (!episodeTemplateId) {
      episodeResults.push({
        schemaVersion: 'repotrial.adversarial-episode-result.v1',
        episodeId: `episode:unsupported:${experiment.id}`,
        templateId: 'unsupported',
        chainId: experiment.chainId,
        threatId: experiment.threatId,
        status: 'INCONCLUSIVE',
        reason: `no-episode-template:${experiment.templateId}`,
        scope: 'single-bounded-episode',
        phaseResults: []
      });
      continue;
    }
    const episode = buildAdversarialEpisode({
      templateId: episodeTemplateId,
      chainId: experiment.chainId,
      threatId: experiment.threatId,
      candidate: experiment.candidate
    });
    const result = await episodeExecutor({
      episode,
      root: options.root,
      canarySeed: `${String(options.scanId ?? 'repotrial')}\0${experiment.id}`,
      timeoutMs: options.timeoutMs
    });
    episodeResults.push(result);
    const phaseObservations = (result.phaseResults ?? []).flatMap((item) => Array.isArray(item.observations) ? item.observations : []);
    observations.push(...phaseObservations);
    traces.push(buildCausalTrace({
      episodeId: result.episodeId,
      chainId: result.chainId,
      threatId: result.threatId,
      targetCapabilities: experiment.targetCapabilities,
      phaseResults: result.phaseResults
    }));
  }

  const charges = experimentObservationsToCharges({ observations, snapshot: options.snapshot });
  const body = {
    schemaVersion: 'repotrial.causal-active-run.v1',
    status: overallStatus(episodeResults),
    planReceipt: plan.receipt ?? null,
    episodes: episodeResults,
    traces,
    observations,
    evidence: charges,
    summary: {
      plannedEpisodeCount: plan.experiments?.length ?? 0,
      executedEpisodeCount: episodeResults.length,
      observedEpisodeCount: episodeResults.filter((item) => item.status === 'OBSERVED').length,
      triggeredEpisodeCount: episodeResults.filter((item) => item.status === 'TRIGGERED').length,
      notObservedEpisodeCount: episodeResults.filter((item) => item.status === 'NOT_OBSERVED').length,
      inconclusiveEpisodeCount: episodeResults.filter((item) => item.status === 'INCONCLUSIVE').length,
      emittedChargeCount: charges.length
    }
  };
  const publicBody = structuredClone(body);
  return Object.defineProperty({ ...publicBody, receipt: sha256(stableStringify(publicBody)) }, 'charges', {
    value: charges,
    enumerable: false,
    configurable: false,
    writable: false
  });
}

function overallStatus(results) {
  if (!results.length) return 'skipped';
  if (results.some((item) => item.status === 'OBSERVED')) return 'completed';
  if (results.every((item) => item.status === 'INCONCLUSIVE')) return 'inconclusive';
  return 'completed';
}

function emptyPlan() {
  return { schemaVersion: 'repotrial.active-experiment-plan.v1', experiments: [], receipt: null };
}
