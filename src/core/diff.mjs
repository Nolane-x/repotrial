import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { sha256, stableStringify } from './hash.mjs';

const exec = promisify(execFile);

const HYPOTHESIS_RISK = Object.freeze({
  REFUTED: 0,
  UNTESTED: 1,
  UNKNOWN: 2,
  CONTRADICTED: 3,
  SUPPORTED: 4,
  PROVEN: 5
});

export function compareReports(baseline, current) {
  validateReport(baseline, 'baseline');
  validateReport(current, 'current');
  const baselineMap = new Map(provenCharges(baseline).map((item) => [findingIdentity(item), item]));
  const currentMap = new Map(provenCharges(current).map((item) => [findingIdentity(item), item]));
  const added = [];
  const existing = [];
  const resolved = [];
  for (const [identity, item] of currentMap) (baselineMap.has(identity) ? existing : added).push(withIdentity(item, identity));
  for (const [identity, item] of baselineMap) if (!currentMap.has(identity)) resolved.push(withIdentity(item, identity));
  const payload = {
    schemaVersion: 'repotrial.differential.v1',
    baselineReceipt: baseline.receipt?.sha256 ?? null,
    currentReceipt: current.receipt?.sha256 ?? null,
    new: sortCharges(added),
    existing: sortCharges(existing),
    resolved: sortCharges(resolved),
    summary: { new: added.length, existing: existing.length, resolved: resolved.length }
  };
  if (hasReasoning(baseline) && hasReasoning(current)) payload.reasoning = compareReasoning(baseline.reasoning, current.reasoning);
  return { ...payload, receipt: { algorithm: 'sha256', sha256: sha256(stableStringify(payload)) } };
}

export async function readReport(filename) {
  const parsed = JSON.parse(await readFile(path.resolve(filename), 'utf8'));
  validateReport(parsed, filename);
  return parsed;
}

export async function loadBaselineFromGit(root, ref, analyze) {
  const repository = path.resolve(root);
  await exec('git', ['rev-parse', '--is-inside-work-tree'], { cwd: repository });
  await exec('git', ['rev-parse', '--verify', `${ref}^{commit}`], { cwd: repository });
  const parent = await mkdtemp(path.join(tmpdir(), 'repotrial-baseline-ref-'));
  const worktree = path.join(parent, 'worktree');
  let attached = false;
  try {
    await exec('git', ['worktree', 'add', '--detach', '--no-checkout', worktree, ref], { cwd: repository });
    attached = true;
    await exec('git', ['checkout', '--force', ref, '--', '.'], { cwd: worktree });
    return await analyze(worktree);
  } finally {
    if (attached) {
      try { await exec('git', ['worktree', 'remove', '--force', worktree], { cwd: repository }); }
      catch { /* cleanup below */ }
      try { await exec('git', ['worktree', 'prune'], { cwd: repository }); } catch { /* ignore */ }
    }
    await rm(parent, { recursive: true, force: true });
  }
}

export function findingIdentity(charge) {
  const anchors = Array.isArray(charge.evidence) ? charge.evidence : [];
  const stableFingerprints = anchors.map((item) => item.stableFingerprint).filter((item) => typeof item === 'string').sort();
  if (stableFingerprints.length) return sha256(`${charge.ruleId}\0${stableFingerprints.join('\0')}`);
  const fingerprints = anchors.map((item) => item.fingerprint).filter((item) => typeof item === 'string').sort();
  if (fingerprints.length) return sha256(`${charge.ruleId}\0${fingerprints.join('\0')}`);
  const locations = anchors.map((item) => `${item.path ?? ''}:${item.startLine ?? item.line ?? ''}:${item.endLine ?? ''}`).sort();
  return sha256(`${charge.ruleId}\0${locations.join('\0')}\0${charge.rationale ?? ''}`);
}

function compareReasoning(baseline, current) {
  const baselineCapabilities = observedCapabilities(baseline);
  const currentCapabilities = observedCapabilities(current);
  const capabilityNew = difference(currentCapabilities, baselineCapabilities);
  const capabilityResolved = difference(baselineCapabilities, currentCapabilities);
  const capabilityExisting = intersection(currentCapabilities, baselineCapabilities);

  const baselinePaths = viablePathMap(baseline);
  const currentPaths = viablePathMap(current);
  const newPaths = [];
  const existingPaths = [];
  const resolvedPaths = [];
  for (const [id, item] of currentPaths) (baselinePaths.has(id) ? existingPaths : newPaths).push(structuredClone(item));
  for (const [id, item] of baselinePaths) if (!currentPaths.has(id)) resolvedPaths.push(structuredClone(item));

  const baselineHypotheses = mapById(baseline.hypotheses);
  const currentHypotheses = mapById(current.hypotheses);
  const hypothesisRegressed = [];
  const hypothesisImproved = [];
  const hypothesisChanged = [];
  for (const id of unionKeys(baselineHypotheses, currentHypotheses)) {
    const before = baselineHypotheses.get(id);
    const after = currentHypotheses.get(id);
    if (!before || !after || before.state === after.state) continue;
    const change = {
      id,
      severity: after.severity ?? before.severity ?? 'medium',
      from: before.state,
      to: after.state,
      confidenceBefore: Number(before.confidence ?? 0),
      confidenceAfter: Number(after.confidence ?? 0)
    };
    hypothesisChanged.push(change);
    const beforeRank = HYPOTHESIS_RISK[before.state] ?? 2;
    const afterRank = HYPOTHESIS_RISK[after.state] ?? 2;
    if (afterRank > beforeRank) hypothesisRegressed.push(change);
    else if (afterRank < beforeRank) hypothesisImproved.push(change);
  }

  const baselineViolations = invariantViolationMap(baseline);
  const currentViolations = invariantViolationMap(current);
  const newViolations = [];
  const existingViolations = [];
  const resolvedViolations = [];
  for (const [id, item] of currentViolations) (baselineViolations.has(id) ? existingViolations : newViolations).push(structuredClone(item));
  for (const [id, item] of baselineViolations) if (!currentViolations.has(id)) resolvedViolations.push(structuredClone(item));

  const payload = {
    schemaVersion: 'repotrial.reasoning-differential.v1',
    capabilities: {
      new: capabilityNew,
      existing: capabilityExisting,
      resolved: capabilityResolved
    },
    attackPaths: {
      new: sortPaths(newPaths),
      existing: sortPaths(existingPaths),
      resolved: sortPaths(resolvedPaths)
    },
    hypotheses: {
      regressed: sortHypothesisChanges(hypothesisRegressed),
      improved: sortHypothesisChanges(hypothesisImproved),
      changed: sortHypothesisChanges(hypothesisChanged)
    },
    invariants: {
      newViolations: sortInvariants(newViolations),
      existingViolations: sortInvariants(existingViolations),
      resolvedViolations: sortInvariants(resolvedViolations)
    },
    summary: {
      newCapabilityCount: capabilityNew.length,
      resolvedCapabilityCount: capabilityResolved.length,
      newViableAttackPathCount: newPaths.length,
      resolvedViableAttackPathCount: resolvedPaths.length,
      regressedHypothesisCount: hypothesisRegressed.length,
      improvedHypothesisCount: hypothesisImproved.length,
      newInvariantViolationCount: newViolations.length,
      resolvedInvariantViolationCount: resolvedViolations.length
    }
  };
  return { ...payload, receipt: { algorithm: 'sha256', sha256: sha256(stableStringify(payload)) } };
}

function observedCapabilities(reasoning) {
  const values = (reasoning.graph?.nodes ?? [])
    .filter((item) => item?.type === 'CAPABILITY' && item.observed !== false && typeof item.capability === 'string')
    .map((item) => item.capability);
  return [...new Set(values)].sort();
}

function viablePathMap(reasoning) {
  return new Map((reasoning.attackPaths ?? [])
    .filter((item) => item?.viability === 'VIABLE' && typeof item.hypothesisId === 'string')
    .map((item) => [pathIdentity(item), item]));
}

function pathIdentity(path) {
  if (typeof path.id === 'string' && path.id) return path.id;
  return sha256(stableStringify({
    hypothesisId: path.hypothesisId,
    stages: (path.stages ?? []).map((stage) => stage?.id ?? '').filter(Boolean)
  }));
}

function invariantViolationMap(reasoning) {
  return new Map((reasoning.invariants?.results ?? [])
    .filter((item) => item?.state === 'VIOLATED' && typeof item.id === 'string')
    .map((item) => [item.id, item]));
}

function mapById(items) {
  return new Map((Array.isArray(items) ? items : []).filter((item) => typeof item?.id === 'string').map((item) => [item.id, item]));
}

function unionKeys(a, b) {
  return [...new Set([...a.keys(), ...b.keys()])].sort();
}

function difference(a, b) {
  const right = new Set(b);
  return a.filter((item) => !right.has(item));
}

function intersection(a, b) {
  const right = new Set(b);
  return a.filter((item) => right.has(item));
}

function sortPaths(items) {
  return items.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || String(a.hypothesisId).localeCompare(String(b.hypothesisId)) || pathIdentity(a).localeCompare(pathIdentity(b)));
}

function sortHypothesisChanges(items) {
  return items.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.id.localeCompare(b.id) || a.from.localeCompare(b.from) || a.to.localeCompare(b.to));
}

function sortInvariants(items) {
  return items.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.id.localeCompare(b.id));
}

function hasReasoning(report) {
  return report?.reasoning?.schemaVersion === 'repotrial.reasoning.v1';
}

function provenCharges(report) { return (report.charges ?? []).filter((item) => item?.status === 'proven'); }
function withIdentity(item, identity) { return { ...structuredClone(item), differentialIdentity: identity }; }
function sortCharges(items) { return items.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.ruleId.localeCompare(b.ruleId) || a.differentialIdentity.localeCompare(b.differentialIdentity)); }
function severityRank(value) { return ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 })[value] ?? 0; }
function validateReport(report, label) { if (!report || typeof report !== 'object' || !Array.isArray(report.charges)) throw new Error(`Invalid RepoTrial ${label} report.`); }
