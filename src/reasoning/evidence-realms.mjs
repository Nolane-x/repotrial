import { sha256, stableStringify } from '../core/hash.mjs';

const REALMS = new Set(['production', 'test', 'benchmark', 'fixture', 'docs', 'generated', 'vendor', 'unknown']);

export function classifyEvidencePath(value) {
  const path = normalizePath(value);
  if (!path) return { realm: 'unknown', confidence: 0, reason: 'missing-path' };

  const lower = path.toLowerCase();
  if (/(^|\/)tests\/adversarial-corpus(\/|$)|(^|\/)adversarial-corpus(\/|$)|(^|\/)benchmark(s)?(\/|$)/.test(lower)) {
    return result('benchmark', 1, 'adversarial-or-benchmark-path');
  }
  if (/(^|\/)(fixtures?|__fixtures__|testdata|test-data)(\/|$)/.test(lower)) {
    return result('fixture', 0.98, 'fixture-path');
  }
  if (/(^|\/)(coverage|dist|build|out|generated)(\/|$)|(^|\/)\.repotrial(?:[-_][^/]*)?(\/|$)|(^|\/)lcov\.info$/.test(lower)) {
    return result('generated', 0.98, 'generated-output-path');
  }
  if (/(^|\/)(vendor|third[_-]party|node_modules)(\/|$)/.test(lower)) {
    return result('vendor', 0.98, 'vendored-path');
  }
  if (/(^|\/)(docs?|documentation)(\/|$)|(^|\/)(readme|changelog|contributing|security|code_of_conduct)(\.[^/]*)?$/i.test(path)) {
    return result('docs', 0.96, 'documentation-path');
  }
  if (/(^|\/)(tests?|__tests__|spec)(\/|$)|\.(test|spec)\.[cm]?[jt]sx?$/.test(lower)) {
    return result('test', 0.95, 'test-path');
  }
  return result('production', 0.85, 'default-repository-surface');
}

export function buildEvidenceRealmIndex(input = {}) {
  const reasoning = input.reasoning && typeof input.reasoning === 'object' ? input.reasoning : { graph: { nodes: [] } };
  const charges = Array.isArray(input.charges) ? input.charges : [];
  const graphNodes = Array.isArray(reasoning?.graph?.nodes) ? reasoning.graph.nodes : [];
  const positiveIds = new Set(graphNodes
    .filter((node) => node?.type === 'EVIDENCE' && node?.polarity !== 'NEGATIVE' && typeof node.id === 'string')
    .map((node) => node.id));

  const byEvidenceId = {};
  const realmCounts = Object.fromEntries([...REALMS].sort().map((realm) => [realm, 0]));
  for (const charge of charges) {
    const id = chargeEvidenceNodeId(charge);
    if (!positiveIds.has(id)) continue;
    const anchors = canonicalAnchors(charge?.evidence);
    const realms = uniqueSorted(anchors.map((anchor) => anchor.realm));
    const realm = collapseChargeRealm(realms);
    byEvidenceId[id] = {
      evidenceId: id,
      ruleId: stringValue(charge?.ruleId, 'unknown-rule'),
      source: stringValue(charge?.source, 'unknown'),
      realm,
      realms,
      anchors,
      fingerprints: evidenceFingerprints(charge)
    };
    for (const item of realms.length ? realms : ['unknown']) realmCounts[item] = (realmCounts[item] ?? 0) + 1;
  }

  const body = {
    schemaVersion: 'repotrial.evidence-realms.v1',
    byEvidenceId: Object.fromEntries(Object.entries(byEvidenceId).sort(([a], [b]) => a.localeCompare(b))),
    summary: {
      evidenceCount: Object.keys(byEvidenceId).length,
      realmCounts
    }
  };
  return { ...body, receipt: sha256(stableStringify(body)) };
}

export function assessChainRealm(chain, realmIndex, causalGraph = {}) {
  const ids = uniqueSorted(chain?.supportingEvidenceIds);
  const entries = ids.map((id) => realmIndex?.byEvidenceId?.[id]).filter(Boolean);
  const realms = uniqueSorted(entries.flatMap((entry) => entry.realms ?? [entry.realm]).filter((realm) => REALMS.has(realm)));
  const fingerprints = new Set(entries.flatMap((entry) => entry.fingerprints ?? []));
  const hasProduction = realms.includes('production');
  const hasNonProduction = realms.some((realm) => realm !== 'production' && realm !== 'unknown');
  const hasExplicitCrossing = explicitCrossingMatches(causalGraph, fingerprints);

  let state;
  let productionRelevant;
  if (!realms.length || realms.every((realm) => realm === 'unknown')) {
    state = 'UNKNOWN_REALM';
    productionRelevant = false;
  } else if (hasProduction && hasNonProduction && !hasExplicitCrossing) {
    state = 'CROSS_REALM_UNPROVEN';
    productionRelevant = false;
  } else if (hasProduction) {
    state = 'PRODUCTION_RELEVANT';
    productionRelevant = true;
  } else {
    state = 'NON_PRODUCTION_ONLY';
    productionRelevant = false;
  }

  return {
    state,
    productionRelevant,
    realms,
    explicitCrossing: hasExplicitCrossing,
    supportingEvidenceIds: ids
  };
}

function explicitCrossingMatches(graph, fingerprints) {
  if (!fingerprints.size) return false;
  for (const edge of Array.isArray(graph?.edges) ? graph.edges : []) {
    if (edge?.relation !== 'CROSSES_TRUST_BOUNDARY') continue;
    const fp = edge?.basis?.evidenceFingerprint;
    if (typeof fp === 'string' && fingerprints.has(fp)) return true;
  }
  return false;
}

function canonicalAnchors(value) {
  const anchors = Array.isArray(value) ? value : [];
  return anchors.map((anchor) => {
    const path = normalizePath(anchor?.path);
    const classified = classifyEvidencePath(path);
    return {
      path,
      realm: classified.realm,
      confidence: classified.confidence,
      reason: classified.reason,
      fingerprint: stringValue(anchor?.stableFingerprint ?? anchor?.fingerprint, fallbackFingerprint(anchor))
    };
  }).sort((a, b) => a.path.localeCompare(b.path) || a.fingerprint.localeCompare(b.fingerprint));
}

function collapseChargeRealm(realms) {
  if (!realms.length) return 'unknown';
  if (realms.length === 1) return realms[0];
  if (realms.includes('production')) return 'mixed';
  return realms[0];
}

function chargeEvidenceNodeId(charge) {
  return `ev:${sha256(canonicalEvidenceIdentityKey(charge)).slice(0, 24)}`;
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

function evidenceFingerprints(charge) {
  const evidence = Array.isArray(charge?.evidence) ? charge.evidence : [];
  return evidence.map((item) => stringValue(
    item?.stableFingerprint ?? item?.fingerprint,
    `${stringValue(item?.path, '')}:${Number(item?.startLine ?? 0)}-${Number(item?.endLine ?? 0)}`
  )).sort();
}

function fallbackFingerprint(anchor) {
  return sha256(stableStringify({
    path: normalizePath(anchor?.path),
    startLine: finiteInteger(anchor?.startLine),
    endLine: finiteInteger(anchor?.endLine)
  }));
}

function normalizePath(value) {
  if (typeof value !== 'string') return '';
  return value.replaceAll('\\', '/').replace(/^\.\//, '').replace(/\/+/g, '/').trim();
}

function result(realm, confidence, reason) {
  return { realm, confidence, reason };
}

function finiteInteger(value) {
  const n = Number(value ?? 0);
  return Number.isInteger(n) && n >= 0 ? n : 0;
}

function stringValue(value, fallback) {
  return typeof value === 'string' ? value : fallback;
}

function uniqueSorted(values) {
  return [...new Set((Array.isArray(values) ? values : []).map(String))].sort();
}
