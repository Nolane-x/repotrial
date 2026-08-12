export function buildEpistemicDelta(initialReasoning = {}, finalReasoning = {}) {
  const initialHypotheses = byId(initialReasoning.hypotheses);
  const finalHypotheses = byId(finalReasoning.hypotheses);
  const hypothesisTransitions = [];

  for (const id of uniqueSorted([...initialHypotheses.keys(), ...finalHypotheses.keys()])) {
    const before = initialHypotheses.get(id);
    const after = finalHypotheses.get(id);
    const from = before?.state ?? 'UNTESTED';
    const to = after?.state ?? 'UNTESTED';
    if (from === to) continue;
    hypothesisTransitions.push({
      id,
      severity: String(after?.severity ?? before?.severity ?? 'info'),
      from,
      to,
      confidenceBefore: number(before?.confidence),
      confidenceAfter: number(after?.confidence)
    });
  }

  const initialPaths = pathByHypothesis(initialReasoning.attackPaths);
  const finalPaths = pathByHypothesis(finalReasoning.attackPaths);
  const attackPathTransitions = [];
  const newlySatisfiedStages = [];

  for (const hypothesisId of uniqueSorted([...initialPaths.keys(), ...finalPaths.keys()])) {
    const before = initialPaths.get(hypothesisId);
    const after = finalPaths.get(hypothesisId);
    const from = before?.viability ?? 'PARTIAL';
    const to = after?.viability ?? 'PARTIAL';
    if (from !== to) {
      attackPathTransitions.push({
        hypothesisId,
        pathIdBefore: before?.id ?? null,
        pathIdAfter: after?.id ?? null,
        severity: String(after?.severity ?? before?.severity ?? 'info'),
        from,
        to,
        confidenceBefore: number(before?.confidence),
        confidenceAfter: number(after?.confidence)
      });
    }

    const beforeStages = byStageId(before?.stages);
    const afterStages = byStageId(after?.stages);
    for (const stageId of uniqueSorted([...beforeStages.keys(), ...afterStages.keys()])) {
      const wasSatisfied = Boolean(beforeStages.get(stageId)?.satisfied);
      const isSatisfied = Boolean(afterStages.get(stageId)?.satisfied);
      if (!wasSatisfied && isSatisfied) {
        newlySatisfiedStages.push({
          hypothesisId,
          stageId,
          selectedCapabilities: uniqueSorted(afterStages.get(stageId)?.capabilities ?? [])
        });
      }
    }
  }

  const initialCapabilities = observedCapabilities(initialReasoning);
  const finalCapabilities = observedCapabilities(finalReasoning);
  const newCapabilities = [...finalCapabilities].filter((capability) => !initialCapabilities.has(capability)).sort();
  const unresolvedTargets = (finalReasoning.hypotheses ?? [])
    .filter((item) => ['UNKNOWN', 'UNTESTED'].includes(item?.state))
    .map((item) => ({
      hypothesisId: String(item.id),
      severity: String(item.severity ?? 'info'),
      state: String(item.state),
      missingStages: uniqueSorted(item.missingStages ?? [])
    }))
    .sort((a, b) => a.hypothesisId.localeCompare(b.hypothesisId));

  return {
    schemaVersion: 'repotrial.epistemic-delta.v1',
    interpretation: 'knowledge-change-not-trust-change',
    hypothesisTransitions,
    attackPathTransitions,
    newlySatisfiedStages,
    newCapabilities,
    unresolvedTargets,
    summary: {
      hypothesisTransitionCount: hypothesisTransitions.length,
      attackPathTransitionCount: attackPathTransitions.length,
      newlySatisfiedStageCount: newlySatisfiedStages.length,
      newCapabilityCount: newCapabilities.length,
      unresolvedTargetCount: unresolvedTargets.length
    }
  };
}

function byId(values) {
  const map = new Map();
  for (const item of Array.isArray(values) ? values : []) {
    if (!item || item.id == null) continue;
    map.set(String(item.id), item);
  }
  return map;
}

function pathByHypothesis(values) {
  const map = new Map();
  for (const item of Array.isArray(values) ? values : []) {
    if (!item || item.hypothesisId == null) continue;
    const id = String(item.hypothesisId);
    const existing = map.get(id);
    if (!existing || String(item.id ?? '').localeCompare(String(existing.id ?? '')) < 0) map.set(id, item);
  }
  return map;
}

function byStageId(values) {
  const map = new Map();
  for (const item of Array.isArray(values) ? values : []) {
    if (!item || item.id == null) continue;
    map.set(String(item.id), item);
  }
  return map;
}

function observedCapabilities(reasoning) {
  return new Set((reasoning.graph?.nodes ?? [])
    .filter((node) => node?.type === 'CAPABILITY' && node.observed === true && node.capability)
    .map((node) => String(node.capability)));
}

function uniqueSorted(values) {
  return [...new Set((Array.isArray(values) ? values : []).map(String))].sort();
}

function number(value) {
  const parsed = Number(value ?? 0);
  return Number.isFinite(parsed) ? parsed : 0;
}
