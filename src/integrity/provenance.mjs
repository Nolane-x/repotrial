import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { sha256, stableStringify } from '../core/hash.mjs';
import { calculateVerdict } from '../core/verdict.mjs';
import { redactSensitiveText } from '../core/redact.mjs';

export async function buildArtifactProof(directory, artifactNames, options = {}) {
  const root = path.resolve(directory);
  const artifacts = [];
  for (const name of [...new Set(artifactNames)].sort()) {
    if (path.isAbsolute(name) || name.split(/[\\/]/).includes('..')) throw new Error(`Artifact path must be relative: ${name}`);
    const buffer = await readFile(path.join(root, name));
    artifacts.push({ name: name.replaceAll('\\', '/'), size: buffer.length, sha256: sha256(buffer) });
  }
  let reportReceipt = null;
  let invariantResults = [];
  const verdict = artifacts.find((item) => item.name === 'verdict.json');
  if (verdict) {
    try {
      const report = JSON.parse(await readFile(path.join(root, verdict.name), 'utf8'));
      reportReceipt = report.receipt?.sha256 ?? null;
      invariantResults = evaluateReportInvariants(report).results;
    } catch { /* verified later */ }
  }
  const payload = {
    schemaVersion: 'repotrial.artifact-proof.v1',
    createdAt: options.createdAt ?? new Date().toISOString(),
    artifacts,
    reportReceipt,
    invariants: ['artifact-digests-match', 'report-receipt-matches', 'paths-are-relative', 'verdict-is-deterministic', 'trusted-requires-complete-coverage', 'evidence-anchors-are-portable'],
    invariantResults
  };
  return { ...payload, receipt: { algorithm: 'sha256', sha256: sha256(stableStringify(payload)) } };
}

export async function verifyArtifactProof(directory, proof) {
  const root = path.resolve(directory);
  const errors = [];
  const payload = { ...proof };
  delete payload.receipt;
  if (proof?.receipt?.sha256 !== sha256(stableStringify(payload))) errors.push({ code: 'proof-receipt-mismatch' });
  for (const artifact of proof?.artifacts ?? []) {
    if (!artifact || typeof artifact.name !== 'string' || path.isAbsolute(artifact.name) || artifact.name.split(/[\\/]/).includes('..')) { errors.push({ code: 'invalid-artifact-path', artifact: artifact?.name }); continue; }
    try {
      const buffer = await readFile(path.join(root, artifact.name));
      if (buffer.length !== artifact.size || sha256(buffer) !== artifact.sha256) errors.push({ code: 'digest-mismatch', artifact: artifact.name });
    } catch { errors.push({ code: 'missing-artifact', artifact: artifact.name }); }
  }
  if (proof?.reportReceipt) {
    try {
      const report = JSON.parse(await readFile(path.join(root, 'verdict.json'), 'utf8'));
      const withoutReceipt = { ...report };
      delete withoutReceipt.receipt;
      const calculated = sha256(stableStringify(withoutReceipt));
      if (report.receipt?.sha256 !== calculated || proof.reportReceipt !== calculated) errors.push({ code: 'report-receipt-mismatch' });
      const invariantCheck = evaluateReportInvariants(report);
      errors.push(...invariantCheck.errors);
      const recorded = Array.isArray(proof.invariantResults) ? proof.invariantResults : [];
      if (stableStringify(recorded) !== stableStringify(invariantCheck.results)) errors.push({ code: 'invariant-results-mismatch' });
    } catch { errors.push({ code: 'invalid-verdict-report' }); }
  }
  return { valid: errors.length === 0, errors };
}

export function buildProvenance(proof, options = {}) {
  return {
    _type: 'https://in-toto.io/Statement/v1',
    subject: (proof.artifacts ?? []).map((artifact) => ({ name: artifact.name, digest: { sha256: artifact.sha256 } })),
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: {
        buildType: 'https://repotrial.dev/buildtypes/scan/v1',
        externalParameters: {
          repository: safeMetadataUrl(options.repository),
          revision: safeMetadataString(options.commit),
          reportReceipt: proof.reportReceipt ?? null
        },
        internalParameters: { proofReceipt: proof.receipt?.sha256 ?? null },
        resolvedDependencies: []
      },
      runDetails: {
        builder: { id: safeMetadataUrl(options.builderId) ?? 'https://repotrial.dev/local-builder/v1' },
        metadata: { invocationId: safeMetadataString(options.invocationId), startedOn: safeMetadataString(options.startedOn), finishedOn: safeMetadataString(options.finishedOn) ?? new Date().toISOString() },
        byproducts: [{ name: 'repotrial-artifact-proof', digest: { sha256: proof.receipt?.sha256 ?? '' } }]
      }
    }
  };
}

export function verifyProvenanceBinding(provenance, proof) {
  const errors = [];
  if (provenance?._type !== 'https://in-toto.io/Statement/v1') errors.push({ code: 'invalid-provenance-statement-type' });
  if (provenance?.predicateType !== 'https://slsa.dev/provenance/v1') errors.push({ code: 'invalid-provenance-predicate-type' });

  const expectedSubjects = (proof?.artifacts ?? []).map((artifact) => ({
    name: artifact.name,
    digest: { sha256: artifact.sha256 }
  })).sort((a, b) => a.name.localeCompare(b.name));
  const observedSubjects = Array.isArray(provenance?.subject) ? provenance.subject.map((subject) => ({
    name: typeof subject?.name === 'string' ? subject.name : null,
    digest: { sha256: typeof subject?.digest?.sha256 === 'string' ? subject.digest.sha256 : null }
  })).sort((a, b) => String(a.name).localeCompare(String(b.name))) : [];
  if (stableStringify(observedSubjects) !== stableStringify(expectedSubjects)) errors.push({ code: 'provenance-subject-mismatch' });

  const external = provenance?.predicate?.buildDefinition?.externalParameters ?? {};
  const internal = provenance?.predicate?.buildDefinition?.internalParameters ?? {};
  if ((external.reportReceipt ?? null) !== (proof?.reportReceipt ?? null)) errors.push({ code: 'provenance-report-receipt-mismatch' });
  if ((internal.proofReceipt ?? null) !== (proof?.receipt?.sha256 ?? null)) errors.push({ code: 'provenance-proof-receipt-mismatch' });

  const byproduct = (provenance?.predicate?.runDetails?.byproducts ?? []).find((item) => item?.name === 'repotrial-artifact-proof');
  if ((byproduct?.digest?.sha256 ?? null) !== (proof?.receipt?.sha256 ?? null)) errors.push({ code: 'provenance-byproduct-mismatch' });
  return { valid: errors.length === 0, errors };
}


export function evaluateReportInvariants(report) {
  const errors = [];
  const coverage = report?.scan?.coverage ?? { ratio: 0, complete: false };
  const charges = Array.isArray(report?.charges) ? report.charges : [];
  const expected = calculateVerdict(charges, coverage);
  const observed = report?.verdict ?? {};
  const comparableExpected = pickVerdict(expected);
  const comparableObserved = pickVerdict(observed);
  const verdictPassed = stableStringify(comparableExpected) === stableStringify(comparableObserved);
  if (!verdictPassed) errors.push({ code: 'verdict-invariant-mismatch', expected: comparableExpected, observed: comparableObserved });

  const trustedCoveragePassed = observed.label !== 'TRUSTED' || (coverage.complete === true && Number(coverage.ratio) === 1);
  if (!trustedCoveragePassed) errors.push({ code: 'trusted-with-incomplete-coverage' });

  let evidencePassed = true;
  for (const charge of charges) {
    for (const evidence of Array.isArray(charge?.evidence) ? charge.evidence : []) {
      if (!portableRelativePath(evidence?.path)) {
        evidencePassed = false;
        errors.push({ code: 'invalid-evidence-path', ruleId: charge.ruleId, path: evidence?.path ?? null });
      }
      if (evidence?.fingerprint != null && !/^[a-f0-9]{64}$/i.test(String(evidence.fingerprint))) {
        evidencePassed = false;
        errors.push({ code: 'invalid-evidence-fingerprint', ruleId: charge.ruleId, path: evidence?.path ?? null });
      }
      if (evidence?.stableFingerprint != null && !/^[a-f0-9]{64}$/i.test(String(evidence.stableFingerprint))) {
        evidencePassed = false;
        errors.push({ code: 'invalid-stable-evidence-fingerprint', ruleId: charge.ruleId, path: evidence?.path ?? null });
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    results: [
      { id: 'verdict-is-deterministic', passed: verdictPassed },
      { id: 'trusted-requires-complete-coverage', passed: trustedCoveragePassed },
      { id: 'evidence-anchors-are-portable', passed: evidencePassed }
    ]
  };
}

function pickVerdict(value) {
  return {
    label: value?.label ?? null,
    rank: value?.rank ?? null,
    score: value?.score ?? null,
    severityCounts: value?.severityCounts ?? null,
    coverage: value?.coverage ?? null
  };
}

function portableRelativePath(value) {
  if (typeof value !== 'string' || !value) return false;
  const normalized = value.replaceAll('\\', '/').replace(/^\.\//, '');
  if (normalized.startsWith('/') || /^[A-Za-z]:\//.test(normalized)) return false;
  return !normalized.split('/').includes('..');
}


function safeMetadataUrl(value) {
  if (value == null || value === '') return null;
  const text = redactSensitiveText(String(value).slice(0, 4096));
  try {
    const url = new URL(text);
    url.username = '';
    url.password = '';
    for (const key of [...url.searchParams.keys()]) {
      if (/(?:token|secret|password|passwd|api[_-]?key|auth|signature|credential)/i.test(key)) url.searchParams.set(key, '[REDACTED]');
    }
    return url.toString();
  } catch {
    return text;
  }
}

function safeMetadataString(value) {
  if (value == null || value === '') return null;
  return redactSensitiveText(String(value).slice(0, 4096));
}
