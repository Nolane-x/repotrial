import { sha256, stableStringify } from '../core/hash.mjs';

const NETWORK_KINDS = new Set(['network', 'dns', 'network-tool']);
const PROCESS_KINDS = new Set(['process']);

export function classifyExperimentObservation(input = {}) {
  const experiment = normalizeExperiment(input.experiment);
  const baseline = normalizeRun(input.baselineRun);
  const scenario = normalizeRun(input.scenarioRun);
  const canaries = normalizeCanaries(input.canaries);
  const sentinelPaths = uniqueSorted(input.sentinelPaths ?? []);

  if (!scenario.present) return inconclusiveObservation(experiment, canaries, 'scenario-result-unavailable');

  const baselineEvents = baseline.events;
  const scenarioEvents = scenario.events;
  const baselineNetwork = baselineEvents.filter(isNetworkEvent);
  const scenarioNetwork = scenarioEvents.filter(isNetworkEvent);
  const baselineProcess = baselineEvents.filter(isProcessEvent);
  const scenarioProcess = scenarioEvents.filter(isProcessEvent);
  const networkDelta = positiveMultisetDelta(scenarioNetwork, baselineNetwork, eventIdentity);
  const processDelta = positiveMultisetDelta(scenarioProcess, baselineProcess, eventIdentity);
  const filesystemDelta = positiveMultisetDelta(scenario.filesystemChanges, baseline.filesystemChanges, changeIdentity);

  const rawNetworkText = scenarioNetwork.map(rawSearchText).join('\n');
  const rawProcessText = scenarioProcess.map(rawSearchText).join('\n');
  const rawOutputText = `${scenario.stdout}\n${scenario.stderr}`;
  const propagatedNetwork = canaries.filter((item) => item.value && rawNetworkText.includes(item.value));
  const propagatedProcess = canaries.filter((item) => item.value && rawProcessText.includes(item.value));
  const propagatedOutput = canaries.filter((item) => item.value && rawOutputText.includes(item.value));
  const sentinelMutations = scenario.filesystemChanges.filter((change) =>
    sentinelPaths.includes(normalizePath(change?.path)) && ['modified', 'deleted'].includes(String(change?.change ?? '').toLowerCase()));

  const signals = {
    canaryNetworkPropagation: propagatedNetwork.length > 0,
    canaryProcessPropagation: propagatedProcess.length > 0,
    canaryOutputPropagation: propagatedOutput.length > 0,
    networkDeltaCount: networkDelta.length,
    processDeltaCount: processDelta.length,
    filesystemDeltaCount: filesystemDelta.length,
    sentinelMutationCount: sentinelMutations.length
  };

  const strongPositive = signals.canaryNetworkPropagation || signals.networkDeltaCount > 0 || signals.sentinelMutationCount > 0;
  const contextualDelta = signals.canaryProcessPropagation || signals.canaryOutputPropagation
    || signals.processDeltaCount > 0 || signals.filesystemDeltaCount > 0;

  let state;
  let reason = null;
  if (strongPositive) state = 'OBSERVED';
  else if (scenario.timedOut || scenario.status === 'timeout') { state = 'INCONCLUSIVE'; reason = 'scenario-timeout'; }
  else if (scenario.outputTruncated) { state = 'INCONCLUSIVE'; reason = 'scenario-output-truncated'; }
  else if (['unavailable', 'skipped'].includes(scenario.status)) { state = 'INCONCLUSIVE'; reason = `scenario-${scenario.status}`; }
  else if (scenario.status === 'failed' && !contextualDelta) { state = 'INCONCLUSIVE'; reason = 'scenario-failed-before-target-signal'; }
  else if (contextualDelta) state = 'TRIGGERED';
  else state = 'NOT_OBSERVED';

  return {
    schemaVersion: 'repotrial.experiment-observation.v1',
    id: observationId(experiment.id, state, signals),
    experimentId: experiment.id,
    templateId: experiment.templateId,
    hypothesisId: experiment.hypothesisId,
    attackPathId: experiment.attackPathId,
    candidate: experiment.candidate,
    state,
    ...(reason ? { reason } : {}),
    signals,
    canaryFingerprints: canaries.map(({ key, fingerprint }) => ({ key, fingerprint })),
    evidence: {
      networkDelta: sanitizeCanaries(networkDelta, canaries),
      processDelta: sanitizeCanaries(processDelta, canaries),
      filesystemDelta: sanitizeCanaries(filesystemDelta, canaries),
      sentinelMutations: sanitizeCanaries(sentinelMutations, canaries),
      propagatedCanaryFingerprints: uniqueSorted([
        ...propagatedNetwork.map((item) => item.fingerprint),
        ...propagatedProcess.map((item) => item.fingerprint),
        ...propagatedOutput.map((item) => item.fingerprint)
      ])
    }
  };
}

function inconclusiveObservation(experiment, canaries, reason) {
  const signals = {
    canaryNetworkPropagation: false,
    canaryProcessPropagation: false,
    canaryOutputPropagation: false,
    networkDeltaCount: 0,
    processDeltaCount: 0,
    filesystemDeltaCount: 0,
    sentinelMutationCount: 0
  };
  return {
    schemaVersion: 'repotrial.experiment-observation.v1',
    id: observationId(experiment.id, 'INCONCLUSIVE', signals),
    experimentId: experiment.id,
    templateId: experiment.templateId,
    hypothesisId: experiment.hypothesisId,
    attackPathId: experiment.attackPathId,
    candidate: experiment.candidate,
    state: 'INCONCLUSIVE',
    reason,
    signals,
    canaryFingerprints: canaries.map(({ key, fingerprint }) => ({ key, fingerprint })),
    evidence: { networkDelta: [], processDelta: [], filesystemDelta: [], sentinelMutations: [], propagatedCanaryFingerprints: [] }
  };
}

function normalizeExperiment(value = {}) {
  const candidate = value?.candidate && typeof value.candidate === 'object' ? value.candidate : {};
  return {
    id: String(value?.id ?? 'exp:unknown'),
    templateId: String(value?.templateId ?? 'unknown-template'),
    hypothesisId: String(value?.hypothesisId ?? 'unknown-hypothesis'),
    attackPathId: String(value?.attackPathId ?? 'unknown-path'),
    candidate: {
      id: String(candidate.id ?? 'candidate:unknown'),
      kind: String(candidate.kind ?? 'unknown'),
      packagePath: String(candidate.packagePath ?? ''),
      name: String(candidate.name ?? ''),
      command: String(candidate.command ?? ''),
      workingDirectory: String(candidate.workingDirectory ?? '.'),
      ...(candidate.event ? { event: String(candidate.event) } : {}),
      ...(candidate.sourceId ? { sourceId: String(candidate.sourceId) } : {})
    }
  };
}

function normalizeRun(value) {
  if (!value || typeof value !== 'object') {
    return { present: false, status: 'unavailable', timedOut: false, outputTruncated: false, events: [], filesystemChanges: [], stdout: '', stderr: '' };
  }
  return {
    present: true,
    status: String(value.status ?? 'completed').toLowerCase(),
    timedOut: Boolean(value.timedOut),
    outputTruncated: Boolean(value.outputTruncated),
    events: Array.isArray(value.events) ? value.events : [],
    filesystemChanges: Array.isArray(value.filesystemChanges) ? value.filesystemChanges : [],
    stdout: String(value.stdout ?? ''),
    stderr: String(value.stderr ?? '')
  };
}

function normalizeCanaries(value) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item) => item && typeof item === 'object' && item.value != null)
    .map((item) => ({
      key: String(item.key ?? 'CANARY'),
      value: String(item.value),
      fingerprint: String(item.fingerprint ?? sha256(String(item.value)))
    }))
    .sort((a, b) => a.key.localeCompare(b.key) || a.fingerprint.localeCompare(b.fingerprint));
}

function isNetworkEvent(event) { return NETWORK_KINDS.has(String(event?.kind ?? '').toLowerCase()); }
function isProcessEvent(event) { return PROCESS_KINDS.has(String(event?.kind ?? '').toLowerCase()); }
function eventIdentity(event) { return stableStringify(event ?? {}); }
function changeIdentity(change) { return stableStringify(change ?? {}); }
function rawSearchText(value) { try { return JSON.stringify(value); } catch { return String(value ?? ''); } }

function positiveMultisetDelta(current, baseline, identity) {
  const remaining = new Map();
  for (const item of baseline) {
    const key = identity(item);
    remaining.set(key, (remaining.get(key) ?? 0) + 1);
  }
  const delta = [];
  for (const item of current) {
    const key = identity(item);
    const count = remaining.get(key) ?? 0;
    if (count > 0) remaining.set(key, count - 1);
    else delta.push(item);
  }
  return delta;
}

function sanitizeCanaries(value, canaries) {
  const replacements = canaries.filter((item) => item.value).sort((a, b) => b.value.length - a.value.length);
  const sanitize = (input, seen = new WeakSet(), depth = 0) => {
    if (depth > 32) return '[TRUNCATED_DEPTH]';
    if (typeof input === 'string') {
      let output = input;
      for (const item of replacements) output = output.split(item.value).join(`[EXPERIMENT_CANARY:${item.fingerprint.slice(0, 16)}]`);
      return output;
    }
    if (input == null || typeof input !== 'object') return input;
    if (seen.has(input)) return '[CIRCULAR]';
    seen.add(input);
    if (Array.isArray(input)) return input.map((item) => sanitize(item, seen, depth + 1));
    const output = {};
    for (const [key, child] of Object.entries(input)) output[key] = sanitize(child, seen, depth + 1);
    return output;
  };
  return sanitize(value);
}

function observationId(experimentId, state, signals) {
  return `obs:${sha256(stableStringify({ experimentId, state, signals })).slice(0, 24)}`;
}

function normalizePath(value) { return String(value ?? '').replaceAll('\\', '/').replace(/^\.\//, ''); }
function uniqueSorted(values) { return [...new Set((Array.isArray(values) ? values : []).map(String))].sort(); }
