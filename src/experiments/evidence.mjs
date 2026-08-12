import { sha256, stableStringify } from '../core/hash.mjs';
import { redactSensitiveText } from '../core/redact.mjs';

export function experimentObservationsToCharges(input = {}) {
  const observations = Array.isArray(input.observations) ? input.observations : [];
  const snapshot = input.snapshot && typeof input.snapshot === 'object' ? input.snapshot : { files: [] };
  const charges = [];

  for (const observation of observations) {
    if (!observation || typeof observation !== 'object') continue;
    const signals = observation.signals ?? {};
    if (observation.state === 'OBSERVED') {
      if (signals.canaryNetworkPropagation) {
        charges.push(buildCharge(observation, snapshot, {
          ruleId: 'adaptive-secret-egress-observed',
          title: 'Synthetic credential reached a network execution path',
          severity: 'critical',
          rationale: 'A RepoTrial synthetic credential canary propagated into a network-related runtime observation under the targeted experiment.',
          remediation: 'Remove credential access from the execution surface, restrict outbound communication, and re-run the experiment before restoring trust.'
        }));
      } else if (Number(signals.networkDeltaCount ?? 0) > 0) {
        const criticalContext = ['credential-exfiltration', 'supply-chain-compromise'].includes(String(observation.hypothesisId));
        charges.push(buildCharge(observation, snapshot, {
          ruleId: 'adaptive-network-trigger-observed',
          title: 'Adaptive experiment triggered new network behavior',
          severity: criticalContext ? 'critical' : 'high',
          rationale: `The experiment introduced ${Number(signals.networkDeltaCount)} network-related runtime observation(s) that were absent from the matching baseline run.`,
          remediation: 'Remove or constrain the conditionally triggered egress path and repeat the experiment under the same bounded scenario.'
        }));
      }

      if (Number(signals.sentinelMutationCount ?? 0) > 0) {
        charges.push(buildCharge(observation, snapshot, {
          ruleId: 'adaptive-sentinel-destruction-observed',
          title: 'Adaptive experiment mutated a protected sandbox sentinel',
          severity: 'high',
          rationale: `The experiment modified or deleted ${Number(signals.sentinelMutationCount)} RepoTrial sandbox-local sentinel file(s).`,
          remediation: 'Reduce filesystem authority, constrain destructive operations to explicit paths, and require effective approval before mutation.'
        }));
      }
    } else if (observation.state === 'TRIGGERED') {
      charges.push(buildCharge(observation, snapshot, {
        ruleId: 'adaptive-ci-triggered-behavior',
        title: 'Adaptive experiment triggered contextual behavior',
        severity: 'medium',
        rationale: 'Synthetic execution context produced a measurable runtime behavior delta without enough evidence to assert a dangerous target capability.',
        remediation: 'Review the conditional execution path and make context-dependent behavior explicit, bounded, and independently verifiable.'
      }));
    }
  }

  return dedupeCharges(charges).sort((a, b) =>
    a.ruleId.localeCompare(b.ruleId)
    || stableEvidenceKey(a).localeCompare(stableEvidenceKey(b)));
}

function buildCharge(observation, snapshot, definition) {
  const evidence = [anchorForObservation(observation, snapshot, definition.severity)];
  return {
    ruleId: definition.ruleId,
    title: definition.title,
    severity: definition.severity,
    status: 'proven',
    confidence: 'high',
    evidence,
    rationale: redactSensitiveText(definition.rationale),
    remediation: redactSensitiveText(definition.remediation),
    source: 'repotrial-experiment',
    experiment: {
      observationId: String(observation.id ?? ''),
      experimentId: String(observation.experimentId ?? ''),
      templateId: String(observation.templateId ?? ''),
      hypothesisId: String(observation.hypothesisId ?? ''),
      attackPathId: String(observation.attackPathId ?? '')
    }
  };
}

function anchorForObservation(observation, snapshot, severity) {
  const candidate = observation.candidate ?? {};
  const targetPath = String(candidate.packagePath ?? '');
  const file = (snapshot.files ?? []).find((item) => item.path === targetPath);
  const line = findCandidateLine(file?.content, String(candidate.name ?? ''));
  const stable = sha256(stableStringify({
    source: 'repotrial-experiment',
    experimentId: String(observation.experimentId ?? ''),
    templateId: String(observation.templateId ?? ''),
    candidateId: String(candidate.id ?? ''),
    packagePath: targetPath,
    name: String(candidate.name ?? '')
  }));
  return {
    path: targetPath || '.',
    startLine: line,
    endLine: line,
    snippet: redactSensitiveText(`${String(candidate.name ?? 'experiment')}: ${String(candidate.command ?? '')}`),
    fileSha256: file?.sha256 ?? null,
    fingerprint: sha256(`${stable}\0${String(observation.id ?? '')}`),
    stableFingerprint: stable,
    severity
  };
}

function findCandidateLine(content, name) {
  if (!content || !name) return 1;
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const expression = new RegExp(`(?:["']${escaped}["']|\\b${escaped}\\b)\\s*:`);
  const lines = String(content).split(/\r?\n/);
  const index = lines.findIndex((line) => expression.test(line));
  return index >= 0 ? index + 1 : 1;
}

function dedupeCharges(charges) {
  const byId = new Map();
  for (const charge of charges) {
    const key = `${charge.ruleId}\0${stableEvidenceKey(charge)}`;
    if (!byId.has(key)) byId.set(key, charge);
  }
  return [...byId.values()];
}

function stableEvidenceKey(charge) {
  return String(charge.evidence?.[0]?.stableFingerprint ?? '');
}
