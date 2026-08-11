import { sha256, stableStringify } from '../core/hash.mjs';

const CONFIDENCE_WEIGHT = Object.freeze({
  high: 0.96,
  'external-evidence-anchored': 0.9,
  'external-evidence': 0.76,
  medium: 0.65,
  low: 0.45
});

const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });

const HYPOTHESES = Object.freeze([
  {
    id: 'credential-exfiltration',
    title: 'Credential or secret exfiltration',
    severity: 'critical',
    stages: [
      { id: 'secret-source', label: 'Secret access', anyOf: ['secret-access'] },
      { id: 'execution-control', label: 'Execution or tool-control primitive', anyOf: ['shell-exec', 'broad-tool-access', 'instruction-control', 'dependency-execution'] },
      { id: 'network-egress', label: 'Network egress', anyOf: ['network-egress'] }
    ],
    mitigatedBy: ['secret-protection']
  },
  {
    id: 'arbitrary-code-execution',
    title: 'Arbitrary or attacker-influenced code execution',
    severity: 'critical',
    stages: [
      { id: 'execution-surface', label: 'Execution surface', anyOf: ['shell-exec', 'dependency-execution'] }
    ],
    mitigatedBy: []
  },
  {
    id: 'unapproved-destructive-action',
    title: 'Destructive action without effective human approval',
    severity: 'high',
    stages: [
      { id: 'destructive-capability', label: 'Destructive capability', anyOf: ['destructive-action'] },
      { id: 'execution-control', label: 'Execution or tool-control primitive', anyOf: ['shell-exec', 'broad-tool-access', 'dependency-execution'] }
    ],
    mitigatedBy: ['human-approval']
  },
  {
    id: 'prompt-to-tool-escalation',
    title: 'Instruction boundary override escalates into powerful tools',
    severity: 'high',
    stages: [
      { id: 'instruction-control', label: 'Instruction control', anyOf: ['instruction-control'] },
      { id: 'tool-power', label: 'Broad tool power', anyOf: ['broad-tool-access', 'shell-exec'] }
    ],
    mitigatedBy: ['least-privilege']
  },
  {
    id: 'supply-chain-compromise',
    title: 'High-impact supply-chain exposure reaches an execution surface',
    severity: 'critical',
    stages: [
      { id: 'supply-chain-exposure', label: 'High-impact supply-chain exposure', anyOf: ['supply-chain-exposure'] },
      { id: 'execution-surface', label: 'Execution surface', anyOf: ['dependency-execution', 'shell-exec'] }
    ],
    mitigatedBy: []
  }
]);

export function reasonAboutEvidence(input = {}) {
  const normalized = normalizeInput(input);
  const core = buildReasoningCore(normalized);
  const remediation = buildCounterfactualRemediation(normalized, core);
  const summary = buildSummary(core, remediation);

  return {
    schemaVersion: 'repotrial.reasoning.v1',
    graph: core.graph,
    hypotheses: core.hypotheses,
    attackPaths: core.attackPaths,
    remediation,
    summary
  };
}

function normalizeInput(input) {
  const charges = Array.isArray(input.charges) ? [...input.charges] : [];
  const safeguards = Array.isArray(input.safeguards) ? [...input.safeguards] : [];
  const coverage = input.coverage && typeof input.coverage === 'object'
    ? { ratio: clamp01(Number(input.coverage.ratio ?? 0)), complete: Boolean(input.coverage.complete) }
    : { ratio: 0, complete: false };
  const providers = input.providers && typeof input.providers === 'object' ? input.providers : {};

  charges.sort((a, b) => canonicalChargeKey(a).localeCompare(canonicalChargeKey(b)));
  safeguards.sort((a, b) => canonicalSafeguardKey(a).localeCompare(canonicalSafeguardKey(b)));

  return { charges, safeguards, coverage, providers };
}

function buildReasoningCore(input) {
  const evidenceNodes = dedupeById(input.charges.map(buildEvidenceNode));
  const safeguardNodes = dedupeById(input.safeguards.map(buildSafeguardNode));
  const chargeByEvidenceId = new Map();
  for (const charge of input.charges) {
    const id = evidenceNodeId(charge);
    if (!chargeByEvidenceId.has(id)) chargeByEvidenceId.set(id, charge);
  }
  const capabilitySupport = new Map();
  const capabilityNodes = new Map();
  const edges = [];

  for (const evidenceNode of evidenceNodes) {
    const charge = chargeByEvidenceId.get(evidenceNode.id);
    if (!charge || charge.status !== 'proven') continue;
    for (const capability of capabilitiesForCharge(charge)) {
      const capabilityId = capabilityNodeId(capability);
      capabilityNodes.set(capability, { id: capabilityId, type: 'CAPABILITY', capability });
      const support = capabilitySupport.get(capability) ?? [];
      support.push({ evidenceId: evidenceNode.id, score: chargeConfidence(charge), direct: isDirectProof(charge) });
      capabilitySupport.set(capability, support);
      edges.push(buildEdge(evidenceNode.id, capabilityId, 'SUPPORTS'));
    }
  }

  for (const support of capabilitySupport.values()) {
    support.sort((a, b) => b.score - a.score || a.evidenceId.localeCompare(b.evidenceId));
  }

  const safeguardById = new Map(safeguardNodes.map((node) => [node.safeguardId, node]));
  const hypotheses = HYPOTHESES.map((definition) => evaluateHypothesis(definition, capabilitySupport, safeguardById, input.coverage));
  const claimNodes = hypotheses.map((item) => ({
    id: claimNodeId(item.id),
    type: 'CLAIM',
    claimId: item.id,
    state: item.state,
    severity: item.severity,
    confidence: item.confidence
  }));

  for (const definition of HYPOTHESES) {
    const claimId = claimNodeId(definition.id);
    for (const stage of definition.stages) {
      for (const capability of stage.anyOf) {
        if (!capabilityNodes.has(capability)) continue;
        edges.push(buildEdge(capabilityNodeId(capability), claimId, 'ENABLES'));
      }
    }
    for (const safeguardId of definition.mitigatedBy) {
      const safeguard = safeguardById.get(safeguardId);
      if (safeguard) edges.push(buildEdge(safeguard.id, claimId, 'MITIGATES'));
    }
  }

  const nodes = [
    ...evidenceNodes,
    ...safeguardNodes,
    ...[...capabilityNodes.values()],
    ...claimNodes
  ].sort(compareNodes);

  const graph = {
    schemaVersion: 'repotrial.evidence-graph.v1',
    nodes,
    edges: dedupeById(edges).sort(compareEdges)
  };

  const attackPaths = buildAttackPaths(hypotheses, capabilitySupport);
  return { graph, hypotheses, attackPaths };
}

function buildEvidenceNode(charge) {
  return {
    id: evidenceNodeId(charge),
    type: 'EVIDENCE',
    ruleId: stringValue(charge.ruleId, 'unknown-rule'),
    title: stringValue(charge.title, stringValue(charge.ruleId, 'Unknown evidence')),
    severity: normalizedSeverity(charge.severity),
    status: stringValue(charge.status, 'unknown'),
    confidence: stringValue(charge.confidence, 'low'),
    source: stringValue(charge.source, 'unknown'),
    evidenceFingerprints: evidenceFingerprints(charge)
  };
}

function buildSafeguardNode(safeguard) {
  return {
    id: safeguardNodeId(safeguard),
    type: 'SAFEGUARD',
    safeguardId: stringValue(safeguard.id, 'unknown-safeguard'),
    detail: stringValue(safeguard.detail, ''),
    path: stringValue(safeguard.path, '')
  };
}

function evaluateHypothesis(definition, capabilitySupport, safeguardById, coverage) {
  const evaluatedStages = definition.stages.map((stage) => {
    const candidates = stage.anyOf
      .flatMap((capability) => (capabilitySupport.get(capability) ?? []).map((support) => ({ capability, ...support })))
      .sort((a, b) => b.score - a.score || a.capability.localeCompare(b.capability) || a.evidenceId.localeCompare(b.evidenceId));
    const best = candidates[0] ?? null;
    return {
      id: stage.id,
      label: stage.label,
      anyOf: [...stage.anyOf],
      satisfied: Boolean(best),
      selectedCapability: best?.capability ?? null,
      confidence: best?.score ?? 0,
      direct: best?.direct ?? false,
      evidenceIds: [...new Set(candidates.map((item) => item.evidenceId))].sort()
    };
  });

  const satisfied = evaluatedStages.filter((stage) => stage.satisfied);
  const missingStages = evaluatedStages.filter((stage) => !stage.satisfied).map((stage) => stage.id);
  const supportingEvidenceIds = [...new Set(evaluatedStages.flatMap((stage) => stage.evidenceIds))].sort();
  const contradictions = definition.mitigatedBy
    .map((id) => safeguardById.get(id))
    .filter(Boolean)
    .map((node) => node.id)
    .sort();

  let state;
  if (missingStages.length === 0) {
    state = evaluatedStages.every((stage) => stage.direct) ? 'PROVEN' : 'SUPPORTED';
    if (contradictions.length) state = 'CONTRADICTED';
  } else if (satisfied.length === 0 && coverage.ratio === 0) {
    state = 'UNTESTED';
  } else {
    state = 'UNKNOWN';
  }

  const supportFraction = evaluatedStages.length ? satisfied.length / evaluatedStages.length : 0;
  const meanSupport = satisfied.length
    ? satisfied.reduce((sum, stage) => sum + stage.confidence, 0) / satisfied.length
    : 0;
  const coverageFactor = 0.7 + (0.3 * coverage.ratio);
  let confidence = meanSupport * supportFraction * coverageFactor;
  if (state === 'CONTRADICTED') confidence *= 0.55;
  confidence = round3(clamp01(confidence));

  return {
    id: definition.id,
    title: definition.title,
    severity: definition.severity,
    state,
    confidence,
    requiredStages: evaluatedStages.map((stage) => ({ id: stage.id, anyOf: stage.anyOf })),
    supportingEvidenceIds,
    missingStages,
    contradictions
  };
}

function buildAttackPaths(hypotheses, capabilitySupport) {
  const hypothesisById = new Map(hypotheses.map((item) => [item.id, item]));
  const paths = [];

  for (const definition of HYPOTHESES) {
    const hypothesis = hypothesisById.get(definition.id);
    const directHighImpact = definition.severity === 'critical';
    if (definition.stages.length < 2 && !directHighImpact) continue;

    const stages = definition.stages.map((stage) => {
      const evidenceIds = [...new Set(stage.anyOf.flatMap((capability) => (capabilitySupport.get(capability) ?? []).map((item) => item.evidenceId)))].sort();
      return {
        id: stage.id,
        label: stage.label,
        capabilities: [...stage.anyOf],
        satisfied: evidenceIds.length > 0,
        evidenceIds
      };
    });

    const viability = ['PROVEN', 'SUPPORTED'].includes(hypothesis.state)
      ? 'VIABLE'
      : ['CONTRADICTED', 'REFUTED'].includes(hypothesis.state)
        ? 'BLOCKED'
        : 'PARTIAL';

    paths.push({
      id: attackPathId(definition.id, stages),
      hypothesisId: definition.id,
      severity: definition.severity,
      viability,
      confidence: hypothesis.confidence,
      stages,
      supportingEvidenceIds: hypothesis.supportingEvidenceIds,
      missingStages: hypothesis.missingStages,
      contradictions: hypothesis.contradictions
    });
  }

  return paths.sort((a, b) => a.hypothesisId.localeCompare(b.hypothesisId) || a.id.localeCompare(b.id));
}

function buildCounterfactualRemediation(input, current) {
  const currentViable = new Map(current.attackPaths.filter((path) => path.viability === 'VIABLE').map((path) => [path.hypothesisId, path]));
  const currentHighImpact = new Map(current.hypotheses
    .filter((item) => ['high', 'critical'].includes(item.severity) && ['PROVEN', 'SUPPORTED'].includes(item.state))
    .map((item) => [item.id, item]));
  const candidates = [];
  const seenEvidenceIds = new Set();

  for (const charge of input.charges) {
    if (charge.status !== 'proven') continue;
    const evidenceId = evidenceNodeId(charge);
    if (seenEvidenceIds.has(evidenceId)) continue;
    seenEvidenceIds.add(evidenceId);

    const simulatedInput = {
      ...input,
      charges: input.charges.filter((item) => evidenceNodeId(item) !== evidenceId)
    };
    const simulated = buildReasoningCore(simulatedInput);
    const simulatedViable = new Set(simulated.attackPaths.filter((path) => path.viability === 'VIABLE').map((path) => path.hypothesisId));
    const simulatedHighImpact = new Set(simulated.hypotheses
      .filter((item) => ['high', 'critical'].includes(item.severity) && ['PROVEN', 'SUPPORTED'].includes(item.state))
      .map((item) => item.id));

    const eliminated = [...currentViable.keys()].filter((id) => !simulatedViable.has(id));
    const downgraded = [...currentHighImpact.keys()].filter((id) => !simulatedHighImpact.has(id));

    candidates.push({
      evidenceId,
      ruleId: stringValue(charge.ruleId, 'unknown-rule'),
      title: stringValue(charge.title, stringValue(charge.ruleId, 'Unknown evidence')),
      severity: normalizedSeverity(charge.severity),
      attackPathsEliminated: eliminated.length,
      hypothesesDowngraded: downgraded.length,
      affectedHypothesisIds: [...new Set([...eliminated, ...downgraded])].sort(),
      remediation: stringValue(charge.remediation, '')
    });
  }

  candidates.sort((a, b) =>
    b.attackPathsEliminated - a.attackPathsEliminated
    || b.hypothesesDowngraded - a.hypothesesDowngraded
    || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
    || a.ruleId.localeCompare(b.ruleId)
    || a.evidenceId.localeCompare(b.evidenceId));

  return {
    schemaVersion: 'repotrial.counterfactual-remediation.v1',
    model: 'counterfactual-charge-removal-v1',
    caveat: 'Rankings model removal of current evidence; they do not certify that applying a recommendation makes the repository safe.',
    candidates
  };
}

function buildSummary(core, remediation) {
  const stateCounts = Object.fromEntries(['PROVEN', 'SUPPORTED', 'CONTRADICTED', 'REFUTED', 'UNKNOWN', 'UNTESTED'].map((state) => [state, 0]));
  for (const hypothesis of core.hypotheses) stateCounts[hypothesis.state] = (stateCounts[hypothesis.state] ?? 0) + 1;
  const pathCounts = { VIABLE: 0, PARTIAL: 0, BLOCKED: 0 };
  for (const path of core.attackPaths) pathCounts[path.viability] += 1;
  const active = core.hypotheses.filter((item) => ['PROVEN', 'SUPPORTED', 'CONTRADICTED'].includes(item.state));
  const maximumReasoningSeverity = active
    .map((item) => item.severity)
    .sort((a, b) => SEVERITY_RANK[b] - SEVERITY_RANK[a])[0] ?? 'info';
  const confidenceFloor = active.length ? Math.min(...active.map((item) => item.confidence)) : 0;

  return {
    evidenceNodeCount: core.graph.nodes.filter((node) => node.type === 'EVIDENCE').length,
    capabilityCount: core.graph.nodes.filter((node) => node.type === 'CAPABILITY').length,
    hypothesisCounts: stateCounts,
    attackPathCounts: pathCounts,
    maximumReasoningSeverity,
    confidenceFloor: round3(confidenceFloor),
    topRemediationEvidenceIds: remediation.candidates.slice(0, 5).map((item) => item.evidenceId)
  };
}

function capabilitiesForCharge(charge) {
  const id = stringValue(charge.ruleId, '');
  if (id === 'dangerous-lifecycle-script') return ['dependency-execution', 'shell-exec'];
  if (id === 'pipe-to-shell') return ['network-egress', 'shell-exec'];
  if (id === 'unrestricted-shell-capability') return ['broad-tool-access', 'shell-exec'];
  if (id === 'broad-mcp-permissions') return ['broad-tool-access'];
  if (id === 'secret-to-egress-path') return ['network-egress', 'secret-access'];
  if (id === 'destructive-without-approval') return ['destructive-action'];
  if (id === 'prompt-boundary-override') return ['instruction-control'];
  if (id === 'self-certified-completion') return ['verification-bypass'];
  if (id === 'runtime-network-attempt') return ['network-egress'];
  if (id === 'runtime-filesystem-mutation') return ['filesystem-write'];
  if ((id.startsWith('known-vulnerable-dependency:') || id.startsWith('container-vulnerability:'))
    && ['high', 'critical'].includes(normalizedSeverity(charge.severity))) return ['supply-chain-exposure'];
  return [];
}

function chargeConfidence(charge) {
  let value = CONFIDENCE_WEIGHT[charge.confidence] ?? 0.55;
  if (charge.status === 'mitigated') value *= 0.45;
  if (charge.status !== 'proven' && charge.status !== 'mitigated') value *= 0.25;
  return round3(clamp01(value));
}

function isDirectProof(charge) {
  return charge.status === 'proven' && charge.confidence === 'high';
}

function evidenceNodeId(charge) {
  return `ev:${digest(canonicalEvidenceIdentityKey(charge))}`;
}

function safeguardNodeId(safeguard) {
  return `sg:${digest(canonicalSafeguardKey(safeguard))}`;
}

function capabilityNodeId(capability) {
  return `cap:${capability}`;
}

function claimNodeId(id) {
  return `claim:${id}`;
}

function attackPathId(hypothesisId, stages) {
  return `path:${digest(stableStringify({ hypothesisId, stages: stages.map((stage) => ({ id: stage.id, capabilities: stage.capabilities })) }))}`;
}

function buildEdge(from, to, relation) {
  return { id: `edge:${digest(`${from}\0${relation}\0${to}`)}`, from, to, relation };
}

function canonicalEvidenceIdentityKey(charge) {
  const fingerprints = evidenceFingerprints(charge);
  return stableStringify({
    ruleId: stringValue(charge?.ruleId, 'unknown-rule'),
    source: stringValue(charge?.source, 'unknown'),
    evidenceFingerprints: fingerprints.length
      ? fingerprints
      : [`unanchored:${stringValue(charge?.title, stringValue(charge?.ruleId, 'unknown-rule'))}`]
  });
}

function canonicalChargeKey(charge) {
  return stableStringify({
    identity: canonicalEvidenceIdentityKey(charge),
    title: stringValue(charge?.title, ''),
    severity: normalizedSeverity(charge?.severity),
    status: stringValue(charge?.status, 'unknown'),
    confidence: stringValue(charge?.confidence, 'low'),
    rationale: stringValue(charge?.rationale, ''),
    remediation: stringValue(charge?.remediation, '')
  });
}

function canonicalSafeguardKey(safeguard) {
  return stableStringify({
    id: stringValue(safeguard?.id, 'unknown-safeguard'),
    detail: stringValue(safeguard?.detail, ''),
    path: stringValue(safeguard?.path, '')
  });
}

function evidenceFingerprints(charge) {
  const evidence = Array.isArray(charge?.evidence) ? charge.evidence : [];
  return evidence.map((item) => stringValue(
    item?.stableFingerprint ?? item?.fingerprint,
    `${stringValue(item?.path, '')}:${Number(item?.startLine ?? 0)}-${Number(item?.endLine ?? 0)}`
  )).sort();
}

function normalizedSeverity(value) {
  const severity = stringValue(value, 'medium').toLowerCase();
  return severity in SEVERITY_RANK ? severity : 'medium';
}

function digest(value) {
  return sha256(String(value)).slice(0, 24);
}

function dedupeById(items) {
  const map = new Map();
  for (const item of items) if (!map.has(item.id)) map.set(item.id, item);
  return [...map.values()];
}

function compareNodes(a, b) {
  const order = { EVIDENCE: 0, SAFEGUARD: 1, CAPABILITY: 2, CLAIM: 3 };
  return (order[a.type] ?? 99) - (order[b.type] ?? 99) || a.id.localeCompare(b.id);
}

function compareEdges(a, b) {
  return a.from.localeCompare(b.from) || a.relation.localeCompare(b.relation) || a.to.localeCompare(b.to) || a.id.localeCompare(b.id);
}

function stringValue(value, fallback) {
  return typeof value === 'string' ? value : fallback;
}

function clamp01(value) {
  if (!Number.isFinite(value)) return 0;
  return Math.min(1, Math.max(0, value));
}

function round3(value) {
  return Math.round(value * 1000) / 1000;
}
