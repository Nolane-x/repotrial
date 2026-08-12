import { sha256, stableStringify } from '../core/hash.mjs';
import { getExperimentTemplate, validateExperimentScenario } from './templates.mjs';
import { runRuntimeScenario } from '../runtime/sandbox.mjs';
import { classifyExperimentObservation } from './observe.mjs';

const HARD_MAX_PHASES = 8;
const HARD_MAX_SENTINELS = 8;
const PHASE_ORDER = Object.freeze({ PREPARE: 0, PRIME: 1, TRIGGER: 2, OBSERVE: 3, FOLLOW_UP: 4, VERIFY: 5 });
const ALLOWED_PHASES = new Set(Object.keys(PHASE_ORDER));

const EPISODE_TEMPLATES = Object.freeze({
  'secret-propagation-episode-v1': {
    title: 'Synthetic secret propagation episode',
    phases: [
      { phase: 'PREPARE', kind: 'metadata' },
      { phase: 'TRIGGER', kind: 'scenario', scenarioTemplateId: 'secret-egress-canary-v1' },
      { phase: 'OBSERVE', kind: 'metadata' },
      { phase: 'VERIFY', kind: 'metadata' }
    ]
  },
  'filesystem-destruction-episode-v1': {
    title: 'Sandbox-local destructive filesystem episode',
    phases: [
      { phase: 'PREPARE', kind: 'metadata', sentinelPaths: ['.repotrial-experiment/sentinel-a.txt'] },
      { phase: 'TRIGGER', kind: 'scenario', scenarioTemplateId: 'filesystem-sentinel-v1', sentinelPaths: ['.repotrial-experiment/sentinel-a.txt'] },
      { phase: 'OBSERVE', kind: 'metadata' },
      { phase: 'VERIFY', kind: 'metadata' }
    ]
  },
  'ci-conditional-episode-v1': {
    title: 'Synthetic CI-context conditional episode',
    phases: [
      { phase: 'PREPARE', kind: 'metadata' },
      { phase: 'TRIGGER', kind: 'scenario', scenarioTemplateId: 'ci-context-trigger-v1' },
      { phase: 'OBSERVE', kind: 'metadata' },
      { phase: 'VERIFY', kind: 'metadata' }
    ]
  },
  'memory-persistence-episode-v1': {
    title: 'Persistent memory/context influence episode',
    requiresSharedWorkspace: true,
    phases: [
      { phase: 'PREPARE', kind: 'metadata', sentinelPaths: ['.repotrial-experiment/memory-seed.txt'] },
      { phase: 'PRIME', kind: 'shared-workspace-probe', requiresSharedWorkspace: true },
      { phase: 'TRIGGER', kind: 'shared-workspace-probe', requiresSharedWorkspace: true },
      { phase: 'OBSERVE', kind: 'metadata' },
      { phase: 'FOLLOW_UP', kind: 'shared-workspace-probe', requiresSharedWorkspace: true },
      { phase: 'VERIFY', kind: 'metadata' }
    ]
  }
});

export function buildAdversarialEpisode(input = {}) {
  const templateId = String(input.templateId ?? '');
  const template = EPISODE_TEMPLATES[templateId];
  if (!template) throw new TypeError(`Unknown adversarial episode template: ${templateId}`);
  const candidate = normalizeCandidate(input.candidate);
  const identity = {
    templateId,
    chainId: stringValue(input.chainId, ''),
    threatId: stringValue(input.threatId, ''),
    candidate
  };
  const phases = template.phases.map((phase, index) => ({
    id: `phase:${digest(stableStringify({ episode: identity, phase: phase.phase, index }))}`,
    order: index,
    phase: phase.phase,
    kind: phase.kind,
    ...(phase.scenarioTemplateId ? { scenarioTemplateId: phase.scenarioTemplateId } : {}),
    ...(phase.sentinelPaths ? { sentinelPaths: [...phase.sentinelPaths] } : {}),
    ...(phase.requiresSharedWorkspace ? { requiresSharedWorkspace: true } : {})
  }));
  const episode = {
    schemaVersion: 'repotrial.adversarial-episode-plan.v1',
    id: `episode:${digest(stableStringify(identity))}`,
    templateId,
    title: template.title,
    chainId: identity.chainId,
    threatId: identity.threatId,
    candidate,
    requiresSharedWorkspace: Boolean(template.requiresSharedWorkspace),
    phases,
    limits: { hardMaxPhases: HARD_MAX_PHASES, hardMaxSentinels: HARD_MAX_SENTINELS }
  };
  return validateAdversarialEpisode(episode);
}

export function validateAdversarialEpisode(input) {
  if (!input || typeof input !== 'object') throw new TypeError('Adversarial episode must be an object.');
  if (!Array.isArray(input.phases) || input.phases.length === 0) throw new TypeError('Adversarial episode must contain phases.');
  if (input.phases.length > HARD_MAX_PHASES) throw new TypeError(`Adversarial episode phase limit exceeded (${HARD_MAX_PHASES}).`);
  const phases = input.phases.map((phase, index) => {
    if (!phase || typeof phase !== 'object') throw new TypeError(`Episode phase ${index} must be an object.`);
    if (Object.hasOwn(phase, 'env')) throw new TypeError('Arbitrary environment values are forbidden in adversarial episodes.');
    const phaseName = String(phase.phase ?? '');
    if (!ALLOWED_PHASES.has(phaseName)) throw new TypeError(`Invalid episode phase: ${phaseName}`);
    const sentinelPaths = Array.isArray(phase.sentinelPaths) ? phase.sentinelPaths.map(validateSentinelPath) : [];
    if (sentinelPaths.length > HARD_MAX_SENTINELS) throw new TypeError(`Episode sentinel limit exceeded (${HARD_MAX_SENTINELS}).`);
    return {
      ...phase,
      id: stringValue(phase.id, `phase:${digest(`${phaseName}\0${index}`)}`),
      order: Number.isInteger(phase.order) ? phase.order : index,
      phase: phaseName,
      ...(sentinelPaths.length ? { sentinelPaths } : {})
    };
  }).sort((a, b) => (PHASE_ORDER[a.phase] ?? 99) - (PHASE_ORDER[b.phase] ?? 99) || a.order - b.order || a.id.localeCompare(b.id));
  return { ...input, phases, limits: { hardMaxPhases: HARD_MAX_PHASES, hardMaxSentinels: HARD_MAX_SENTINELS } };
}

export async function executeAdversarialEpisode(input = {}) {
  const episode = validateAdversarialEpisode(input.episode);
  const scenarioRunner = typeof input.scenarioRunner === 'function' ? input.scenarioRunner : defaultScenarioRunner;
  const phaseResults = [];
  let sharedUnsupported = false;

  for (const phase of episode.phases) {
    if (phase.requiresSharedWorkspace) {
      sharedUnsupported = true;
      phaseResults.push({ id: phase.id, phase: phase.phase, status: 'UNSUPPORTED', reason: 'shared-workspace-primitive-unavailable', observations: [] });
      continue;
    }
    if (phase.kind === 'metadata') {
      phaseResults.push({ id: phase.id, phase: phase.phase, status: 'TRIGGERED', reason: 'episode-metadata-phase', observations: [] });
      continue;
    }
    try {
      const raw = await scenarioRunner({
        phase,
        episode,
        root: input.root,
        candidate: episode.candidate,
        canarySeed: input.canarySeed,
        timeoutMs: input.timeoutMs
      });
      phaseResults.push(normalizePhaseResult(phase, raw));
    } catch (error) {
      phaseResults.push({ id: phase.id, phase: phase.phase, status: 'INCONCLUSIVE', reason: boundedError(error), observations: [] });
    }
  }

  const status = sharedUnsupported ? 'INCONCLUSIVE' : overallStatus(phaseResults);
  const result = {
    schemaVersion: 'repotrial.adversarial-episode-result.v1',
    episodeId: episode.id,
    templateId: episode.templateId,
    chainId: episode.chainId,
    threatId: episode.threatId,
    status,
    reason: sharedUnsupported ? 'shared-workspace-primitive-unavailable' : resultReason(status, phaseResults),
    scope: 'single-bounded-episode',
    phaseResults
  };
  return { ...result, receipt: sha256(stableStringify(result)) };
}

async function defaultScenarioRunner({ phase, episode, root, candidate, canarySeed, timeoutMs }) {
  if (!root) return { status: 'INCONCLUSIVE', reason: 'repository-root-required', observations: [] };
  const template = getExperimentTemplate(phase.scenarioTemplateId);
  if (!template) return { status: 'INCONCLUSIVE', reason: 'scenario-template-unavailable', observations: [] };
  const baselineScenario = validateExperimentScenario({ templateId: 'ci-context-trigger-v1', envKeys: [], sentinelPaths: [] });
  const scenario = validateExperimentScenario({
    templateId: template.id,
    envKeys: template.envKeys,
    sentinelPaths: phase.sentinelPaths?.length ? phase.sentinelPaths : template.sentinelPaths
  });
  const [baseline, targeted] = await Promise.all([
    runRuntimeScenario({ root, candidate, scenario: baselineScenario, canarySeed: `${canarySeed}\0baseline`, timeoutMs }),
    runRuntimeScenario({ root, candidate, scenario, canarySeed: `${canarySeed}\0target`, timeoutMs })
  ]);
  const observation = classifyExperimentObservation({
    experiment: {
      id: `${episode.id}:${phase.id}`,
      templateId: template.id,
      hypothesisId: episode.threatId,
      attackPathId: episode.chainId,
      candidate
    },
    baselineRun: internalRun(baseline),
    scenarioRun: internalRun(targeted),
    canaries: internalCanaries(targeted),
    sentinelPaths: scenario.sentinelPaths
  });
  return {
    observationState: observation.state,
    reason: observation.reason ?? observation.state.toLowerCase(),
    observations: [observation],
    emittedEvidenceIds: [observation.id]
  };
}

function internalRun(result) {
  if (!result || typeof result !== 'object') return null;
  return result.rawRun ?? result.run ?? null;
}

function internalCanaries(result) {
  if (!result || typeof result !== 'object' || !Array.isArray(result.canaries)) return [];
  return result.canaries
    .filter((item) => item && typeof item === 'object' && item.value != null)
    .map((item) => ({ key: String(item.key ?? 'CANARY'), value: String(item.value), fingerprint: String(item.fingerprint ?? '') }));
}

function normalizePhaseResult(phase, raw) {
  const state = String(raw?.observationState ?? raw?.status ?? 'INCONCLUSIVE').toUpperCase();
  const status = ['OBSERVED', 'TRIGGERED', 'NOT_OBSERVED', 'INCONCLUSIVE', 'UNSUPPORTED'].includes(state) ? state : 'INCONCLUSIVE';
  return {
    id: phase.id,
    phase: phase.phase,
    status,
    reason: stringValue(raw?.reason, status.toLowerCase()),
    observations: Array.isArray(raw?.observations) ? structuredClone(raw.observations) : [],
    emittedEvidenceIds: uniqueSorted(raw?.emittedEvidenceIds)
  };
}

function overallStatus(results) {
  const states = new Set(results.map((item) => item.status));
  if (states.has('INCONCLUSIVE') || states.has('UNSUPPORTED')) return 'INCONCLUSIVE';
  if (states.has('OBSERVED')) return 'OBSERVED';
  const trigger = results.find((item) => item.phase === 'TRIGGER');
  if (trigger?.status === 'NOT_OBSERVED') return 'NOT_OBSERVED';
  if (states.has('NOT_OBSERVED')) return 'NOT_OBSERVED';
  if (states.has('TRIGGERED')) return 'TRIGGERED';
  return 'INCONCLUSIVE';
}

function resultReason(status, results) {
  if (status === 'INCONCLUSIVE') return results.find((item) => ['INCONCLUSIVE', 'UNSUPPORTED'].includes(item.status))?.reason ?? 'episode-inconclusive';
  if (status === 'NOT_OBSERVED') return 'target-not-observed-in-bounded-episode';
  if (status === 'OBSERVED') return 'direct-positive-observation';
  return 'behavior-triggered-without-direct-target-proof';
}

function normalizeCandidate(value) {
  if (!value || typeof value !== 'object') throw new TypeError('Episode candidate must be an object.');
  const candidate = {
    kind: stringValue(value.kind, 'unknown'),
    packagePath: stringValue(value.packagePath, ''),
    name: stringValue(value.name, ''),
    command: stringValue(value.command, ''),
    workingDirectory: stringValue(value.workingDirectory, '.')
  };
  candidate.id = `candidate:${digest(stableStringify(candidate))}`;
  return candidate;
}

function validateSentinelPath(value) {
  const path = String(value ?? '').replaceAll('\\', '/');
  if (!path.startsWith('.repotrial-experiment/') || path.includes('../') || path.includes('/..') || path.startsWith('/')) {
    throw new TypeError(`Invalid sandbox-local sentinel path: ${path}`);
  }
  return path;
}

function boundedError(error) {
  const message = error instanceof Error ? error.message : String(error ?? 'unknown-error');
  return message.slice(0, 240);
}

function uniqueSorted(value) {
  return [...new Set((Array.isArray(value) ? value : []).map(String))].sort();
}

function stringValue(value, fallback) {
  return typeof value === 'string' ? value : fallback;
}

function digest(value) {
  return sha256(String(value)).slice(0, 24);
}
