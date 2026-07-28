import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { generateSigningKeyPair, signStatement, verifyEnvelope } from '../src/integrity/sign.mjs';
import { buildProvenance, buildArtifactProof, verifyArtifactProof } from '../src/integrity/provenance.mjs';
import { calculateVerdict } from '../src/core/verdict.mjs';

const posixFakeUnavailable = process.platform === 'win32' ? 'POSIX shebang test executable is unavailable on Windows' : false;

test('creates and verifies an Ed25519 DSSE envelope without exposing the private key', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'repotrial-sign-'));
  const keys = await generateSigningKeyPair(directory);
  const statement = { _type: 'https://in-toto.io/Statement/v1', subject: [{ name: 'verdict.json', digest: { sha256: 'a'.repeat(64) } }], predicateType: 'https://slsa.dev/provenance/v1', predicate: {} };
  const envelope = await signStatement(statement, keys.privateKey);
  const verified = await verifyEnvelope(envelope, keys.publicKey);
  assert.equal(verified.valid, true);
  assert.deepEqual(verified.statement, statement);
  assert.doesNotMatch(JSON.stringify(envelope), /PRIVATE KEY/);
  envelope.payload = Buffer.from('{}').toString('base64');
  assert.equal((await verifyEnvelope(envelope, keys.publicKey)).valid, false);
});

test('builds SLSA provenance and verifies artifact hashes and report receipt', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'repotrial-proof-'));
  const coverage = { ratio: 1, complete: true };
  const verdict = { schemaVersion: 'repotrial.report.v2', scan: { id: 'scan', coverage }, verdict: calculateVerdict([], coverage), charges: [], receipt: { algorithm: 'sha256', sha256: '' } };
  const { stableStringify, sha256 } = await import('../src/core/hash.mjs');
  const without = { ...verdict }; delete without.receipt;
  verdict.receipt.sha256 = sha256(stableStringify(without));
  await writeFile(path.join(directory, 'verdict.json'), JSON.stringify(verdict));
  await writeFile(path.join(directory, 'evidence.json'), JSON.stringify({ anchors: [] }));
  const proof = await buildArtifactProof(directory, ['verdict.json', 'evidence.json']);
  assert.equal((await verifyArtifactProof(directory, proof)).valid, true);
  const provenance = buildProvenance(proof, { repository: 'https://example.invalid/repo', commit: 'b'.repeat(40), builderId: 'https://github.com/example/repotrial/.github/workflows/scan.yml' });
  assert.equal(provenance.predicateType, 'https://slsa.dev/provenance/v1');
  assert.equal(provenance.subject.length, 2);
  await writeFile(path.join(directory, 'evidence.json'), 'tampered');
  const failure = await verifyArtifactProof(directory, proof);
  assert.equal(failure.valid, false);
  assert.ok(failure.errors.some((item) => item.code === 'digest-mismatch'));
});


test('rejects a receipt-valid report whose verdict violates deterministic invariants', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'repotrial-proof-invariant-'));
  const { stableStringify, sha256 } = await import('../src/core/hash.mjs');
  const coverage = { ratio: 1, complete: true };
  const report = {
    schemaVersion: 'repotrial.report.v2',
    scan: { id: 'scan', coverage },
    charges: [],
    verdict: { ...calculateVerdict([], coverage), score: 99, label: 'DANGEROUS' }
  };
  report.receipt = { algorithm: 'sha256', sha256: sha256(stableStringify(report)) };
  await writeFile(path.join(directory, 'verdict.json'), JSON.stringify(report));
  const proof = await buildArtifactProof(directory, ['verdict.json']);
  const verification = await verifyArtifactProof(directory, proof);
  assert.equal(verification.valid, false);
  assert.ok(verification.errors.some((item) => item.code === 'verdict-invariant-mismatch'));
});

test('invokes cosign sign-blob with a bundle and optional key without a shell', { skip: posixFakeUnavailable }, async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'repotrial-cosign-'));
  const statement = path.join(directory, 'provenance.intoto.json');
  const bundle = path.join(directory, 'provenance.sigstore.json');
  const capture = path.join(directory, 'args.json');
  const fake = path.join(directory, 'cosign-fake.mjs');
  await writeFile(statement, '{}');
  await writeFile(fake, `#!/usr/bin/env node\nimport fs from 'node:fs';const args=process.argv.slice(2);fs.writeFileSync(${JSON.stringify(capture)},JSON.stringify(args));const out=args[args.indexOf('--bundle')+1];fs.writeFileSync(out,JSON.stringify({mediaType:'application/vnd.dev.sigstore.bundle.v0.3+json'}));`);
  await (await import('node:fs/promises')).chmod(fake, 0o755);
  const { signWithCosign } = await import('../src/integrity/cosign.mjs');
  const result = await signWithCosign(statement, bundle, { cosignBin: fake, key: 'key.pem', timeoutMs: 5_000 });
  assert.equal(result.status, 'signed');
  assert.equal(result.keyless, false);
  const args = JSON.parse(await readFile(capture, 'utf8'));
  assert.deepEqual(args, ['sign-blob', '--yes', '--bundle', bundle, '--key', 'key.pem', statement]);
  assert.match(await readFile(bundle, 'utf8'), /sigstore/);
});

test('invokes cosign verify-blob against the recorded Sigstore bundle', { skip: posixFakeUnavailable }, async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'repotrial-cosign-verify-'));
  const statement = path.join(directory, 'provenance.intoto.json');
  const bundle = path.join(directory, 'provenance.sigstore.json');
  const capture = path.join(directory, 'verify-args.json');
  const fake = path.join(directory, 'cosign-verify-fake.mjs');
  await writeFile(statement, '{}');
  await writeFile(bundle, '{}');
  await writeFile(fake, `#!/usr/bin/env node\nimport fs from 'node:fs';const args=process.argv.slice(2);fs.writeFileSync(${JSON.stringify(capture)},JSON.stringify(args));`);
  await (await import('node:fs/promises')).chmod(fake, 0o755);
  const { verifyWithCosign } = await import('../src/integrity/cosign.mjs');
  const result = await verifyWithCosign(statement, bundle, { cosignBin: fake, key: 'key.pub' });
  assert.equal(result.valid, true);
  assert.deepEqual(JSON.parse(await readFile(capture, 'utf8')), ['verify-blob', '--bundle', bundle, '--key', 'key.pub', statement]);
});

test('passes only the allowlisted Sigstore environment into cosign', { skip: posixFakeUnavailable }, async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'repotrial-cosign-env-'));
  const statement = path.join(directory, 'provenance.intoto.json');
  const bundle = path.join(directory, 'provenance.sigstore.json');
  const capture = path.join(directory, 'env.json');
  const fake = path.join(directory, 'cosign-env-fake.mjs');
  await writeFile(statement, '{}');
  await writeFile(fake, `#!/usr/bin/env node\nimport fs from 'node:fs';fs.writeFileSync(${JSON.stringify(capture)},JSON.stringify(process.env));const args=process.argv.slice(2);fs.writeFileSync(args[args.indexOf('--bundle')+1],'{}');`);
  await (await import('node:fs/promises')).chmod(fake, 0o755);
  const previousPassword = process.env.COSIGN_PASSWORD;
  const previousSecret = process.env.REPOTRIAL_DO_NOT_FORWARD;
  process.env.COSIGN_PASSWORD = 'allowed-password';
  process.env.REPOTRIAL_DO_NOT_FORWARD = 'host-secret';
  try {
    const { signWithCosign } = await import('../src/integrity/cosign.mjs');
    await signWithCosign(statement, bundle, { cosignBin: fake, key: 'key.pem' });
  } finally {
    if (previousPassword === undefined) delete process.env.COSIGN_PASSWORD; else process.env.COSIGN_PASSWORD = previousPassword;
    if (previousSecret === undefined) delete process.env.REPOTRIAL_DO_NOT_FORWARD; else process.env.REPOTRIAL_DO_NOT_FORWARD = previousSecret;
  }
  const environment = JSON.parse(await readFile(capture, 'utf8'));
  assert.equal(environment.COSIGN_PASSWORD, 'allowed-password');
  assert.equal(environment.REPOTRIAL_DO_NOT_FORWARD, undefined);
});

test('verifies that SLSA provenance subjects and receipts are bound to the artifact proof', async () => {
  const { verifyProvenanceBinding } = await import('../src/integrity/provenance.mjs');
  const proof = {
    schemaVersion: 'repotrial.artifact-proof.v1',
    artifacts: [{ name: 'verdict.json', size: 2, sha256: 'a'.repeat(64) }],
    reportReceipt: 'b'.repeat(64),
    receipt: { algorithm: 'sha256', sha256: 'c'.repeat(64) }
  };
  const provenance = buildProvenance(proof, { repository: 'https://example.invalid/repo', commit: 'd'.repeat(40) });
  assert.equal(verifyProvenanceBinding(provenance, proof).valid, true);
  provenance.subject[0].digest.sha256 = 'e'.repeat(64);
  const invalid = verifyProvenanceBinding(provenance, proof);
  assert.equal(invalid.valid, false);
  assert.ok(invalid.errors.some((item) => item.code === 'provenance-subject-mismatch'));
});

test('provenance strips credentials from repository and builder metadata', () => {
  const proof = {
    artifacts: [], reportReceipt: null,
    receipt: { algorithm: 'sha256', sha256: 'a'.repeat(64) }
  };
  const provenance = buildProvenance(proof, {
    repository: 'https://alice:super-secret@example.invalid/org/repo.git',
    builderId: 'https://ci.invalid/run?token=super-secret',
    commit: 'b'.repeat(40)
  });
  const text = JSON.stringify(provenance);
  assert.doesNotMatch(text, /super-secret/);
  assert.equal(provenance.predicate.buildDefinition.externalParameters.repository, 'https://example.invalid/org/repo.git');
});
