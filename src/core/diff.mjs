import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { sha256, stableStringify } from './hash.mjs';

const exec = promisify(execFile);

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

function provenCharges(report) { return (report.charges ?? []).filter((item) => item?.status === 'proven'); }
function withIdentity(item, identity) { return { ...structuredClone(item), differentialIdentity: identity }; }
function sortCharges(items) { return items.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.ruleId.localeCompare(b.ruleId) || a.differentialIdentity.localeCompare(b.differentialIdentity)); }
function severityRank(value) { return ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 })[value] ?? 0; }
function validateReport(report, label) { if (!report || typeof report !== 'object' || !Array.isArray(report.charges)) throw new Error(`Invalid RepoTrial ${label} report.`); }
