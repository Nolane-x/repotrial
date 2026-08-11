import { sha256, stableStringify } from '../core/hash.mjs';
import { getExperimentTemplate, validateExperimentScenario } from './templates.mjs';

const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });
const DEFAULT_MAX_EXPERIMENTS = 6;
const DEFAULT_MAX_PER_CANDIDATE = 2;
const HARD_MAX_EXPERIMENTS = 32;
const HARD_MAX_PER_CANDIDATE = 8;

export function planAdaptiveExperiments(input = {}) {
  const reasoning = input.reasoning && typeof input.reasoning === 'object' ? input.reasoning : {};
  const candidates = normalizeCandidates(input.candidates);
  const maxExperiments = boundedInteger(input.maxExperiments, DEFAULT_MAX_EXPERIMENTS, 0, HARD_MAX_EXPERIMENTS);
  const maxPerCandidate = boundedInteger(input.maxPerCandidate, DEFAULT_MAX_PER_CANDIDATE, 0, HARD_MAX_PER_CANDIDATE);
  const hypothesisById = new Map((reasoning.hypotheses ?? []).map((item) => [String(item.id), item]));
  const rankedPaths = [];

  for (const path of reasoning.attackPaths ?? []) {
    if (path?.viability !== 'PARTIAL') continue;
    const hypothesis = hypothesisById.get(String(path.hypothesisId));
    if (!hypothesis || !['UNKNOWN', 'UNTESTED'].includes(hypothesis.state)) continue;
    const templateId = templateForPath(path, hypothesis);
    if (!templateId || !candidates.length) continue;
    rankedPaths.push({
      path,
      hypothesis,
      templateId,
      priority: priorityForPath(path, hypothesis)
    });
  }

  rankedPaths.sort((a, b) =>
    b.priority - a.priority
    || severityRank(b.path.severity) - severityRank(a.path.severity)
    || String(a.path.hypothesisId).localeCompare(String(b.path.hypothesisId))
    || String(a.path.id).localeCompare(String(b.path.id)));

  const perCandidate = new Map();
  const experiments = [];
  const seen = new Set();

  outer:
  for (const target of rankedPaths) {
    for (const candidate of candidates) {
      if (experiments.length >= maxExperiments) break outer;
      const used = perCandidate.get(candidate.id) ?? 0;
      if (used >= maxPerCandidate) continue;
      const key = `${target.templateId}\0${target.hypothesis.id}\0${candidate.id}`;
      if (seen.has(key)) continue;
      const template = getExperimentTemplate(target.templateId);
      if (!template) continue;
      const scenario = validateExperimentScenario({
        templateId: template.id,
        envKeys: template.envKeys,
        sentinelPaths: template.sentinelPaths
      });
      const targetStageIds = uniqueSorted(target.path.missingStages ?? target.hypothesis.missingStages ?? []);
      const experiment = {
        id: experimentId({
          templateId: target.templateId,
          hypothesisId: target.hypothesis.id,
          attackPathId: target.path.id,
          candidateId: candidate.id,
          targetStageIds
        }),
        templateId: target.templateId,
        title: template.title,
        hypothesisId: String(target.hypothesis.id),
        attackPathId: String(target.path.id),
        severity: normalizedSeverity(target.path.severity ?? target.hypothesis.severity),
        priority: target.priority,
        rationale: rationaleFor(target.path, target.hypothesis, target.templateId),
        targetStageIds,
        targetCapabilities: uniqueSorted(template.targetCapabilities),
        candidate,
        scenario
      };
      experiments.push(experiment);
      seen.add(key);
      perCandidate.set(candidate.id, used + 1);
    }
  }

  experiments.sort((a, b) =>
    b.priority - a.priority
    || severityRank(b.severity) - severityRank(a.severity)
    || a.hypothesisId.localeCompare(b.hypothesisId)
    || a.candidate.id.localeCompare(b.candidate.id)
    || a.id.localeCompare(b.id));

  return {
    schemaVersion: 'repotrial.experiment-plan.v1',
    budget: {
      maxExperiments,
      maxPerCandidate,
      hardMaxExperiments: HARD_MAX_EXPERIMENTS,
      hardMaxPerCandidate: HARD_MAX_PER_CANDIDATE
    },
    experiments,
    summary: {
      partialPathCount: (reasoning.attackPaths ?? []).filter((path) => path?.viability === 'PARTIAL').length,
      addressablePathCount: rankedPaths.length,
      candidateCount: candidates.length,
      plannedExperimentCount: experiments.length,
      truncatedByBudget: rankedPaths.length > 0 && candidates.length > 0
        && experiments.length >= maxExperiments
        && potentialExperimentCount(rankedPaths.length, candidates.length, maxPerCandidate) > experiments.length
    }
  };
}

function normalizeCandidates(value) {
  if (!Array.isArray(value)) return [];
  const normalized = value
    .filter((item) => item && typeof item === 'object')
    .map((item) => {
      const identity = {
        kind: stringValue(item.kind, 'unknown'),
        packagePath: stringValue(item.packagePath, ''),
        name: stringValue(item.name, ''),
        command: stringValue(item.command, ''),
        workingDirectory: stringValue(item.workingDirectory, '.'),
        id: item.id ? String(item.id) : null,
        event: item.event ? String(item.event) : null
      };
      return {
        id: `candidate:${digest(stableStringify(identity))}`,
        kind: identity.kind,
        packagePath: identity.packagePath,
        name: identity.name,
        command: identity.command,
        workingDirectory: identity.workingDirectory,
        ...(identity.event ? { event: identity.event } : {}),
        ...(identity.id ? { sourceId: identity.id } : {})
      };
    });
  const byId = new Map(normalized.map((item) => [item.id, item]));
  return [...byId.values()].sort((a, b) =>
    a.packagePath.localeCompare(b.packagePath)
    || a.name.localeCompare(b.name)
    || a.id.localeCompare(b.id));
}

function templateForPath(path, hypothesis) {
  const missing = new Set([...(path.missingStages ?? []), ...(hypothesis.missingStages ?? [])].map(String));
  if (String(hypothesis.id) === 'credential-exfiltration'
    && (missing.has('secret-source') || missing.has('network-egress'))) return 'secret-egress-canary-v1';
  if (String(hypothesis.id) === 'unapproved-destructive-action'
    && missing.has('destructive-capability')) return 'filesystem-sentinel-v1';
  if (['high', 'critical'].includes(normalizedSeverity(path.severity ?? hypothesis.severity))) return 'ci-context-trigger-v1';
  return null;
}

function priorityForPath(path, hypothesis) {
  const severity = severityRank(path.severity ?? hypothesis.severity);
  const missing = uniqueSorted(path.missingStages ?? hypothesis.missingStages ?? []).length;
  const confidence = clamp01(Number(hypothesis.confidence ?? path.confidence ?? 0));
  return (severity * 100) + Math.max(0, 20 - (missing * 5)) + Math.round((1 - confidence) * 10);
}

function rationaleFor(path, hypothesis, templateId) {
  const missing = uniqueSorted(path.missingStages ?? hypothesis.missingStages ?? []);
  return `Probe ${String(hypothesis.id)} with ${templateId}; missing stages: ${missing.join(', ') || 'none'}.`;
}

function experimentId(value) {
  return `exp:${digest(stableStringify(value))}`;
}

function digest(value) {
  return sha256(value).slice(0, 24);
}

function uniqueSorted(values) {
  return [...new Set((Array.isArray(values) ? values : []).map(String))].sort();
}

function normalizedSeverity(value) {
  const severity = String(value ?? 'info').toLowerCase();
  return severity in SEVERITY_RANK ? severity : 'info';
}

function severityRank(value) {
  return SEVERITY_RANK[normalizedSeverity(value)];
}

function stringValue(value, fallback) {
  return value == null ? fallback : String(value);
}

function clamp01(value) {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

function boundedInteger(value, fallback, min, max) {
  const number = Number(value ?? fallback);
  return Number.isInteger(number) ? Math.min(max, Math.max(min, number)) : fallback;
}

function potentialExperimentCount(pathCount, candidateCount, maxPerCandidate) {
  return Math.min(pathCount * candidateCount, candidateCount * maxPerCandidate);
}
