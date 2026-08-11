import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { discoverRepository } from './discover.mjs';
import { evaluateRules } from './rules.mjs';
import { calculateVerdict } from './verdict.mjs';
import { stableStringify, sha256 } from './hash.mjs';
import { renderHtmlReport } from './report.mjs';
import { renderBadge } from './badge.mjs';
import { buildSarifReport } from './sarif.mjs';
import { redactSensitiveText, redactSensitiveValues } from './redact.mjs';
import { compareReports, loadBaselineFromGit, readReport } from './diff.mjs';
import { buildForgeOsManifest } from '../bridge/manifest.mjs';
import { runForgeOsBridge } from '../bridge/forgeos.mjs';
import { runRuntimeAnalysis } from '../runtime/sandbox.mjs';
import { analyzeSupplyChain } from '../supply/analyze.mjs';
import { buildArtifactProof, buildProvenance } from '../integrity/provenance.mjs';
import { signStatement } from '../integrity/sign.mjs';
import { signWithCosign } from '../integrity/cosign.mjs';
import { reasonAboutEvidence } from '../reasoning/engine.mjs';

const VERSION = '0.4.2';

export async function scanRepository(options = {}) {
  const root = path.resolve(options.root ?? process.cwd());
  const outputDir = path.resolve(options.outputDir ?? path.join(process.cwd(), '.repotrial'));
  if (outputDir === root) throw new Error('Output directory must not be the scan root.');
  const now = options.now ?? new Date().toISOString();
  const scanId = options.scanId ?? randomUUID();

  const outputInsideRoot = outputDir.startsWith(`${root}${path.sep}`);
  const excludedPaths = (options.discovery?.excludedPaths ?? []).map((entry) => path.resolve(root, entry));
  const discovery = {
    ...(options.discovery ?? {}),
    ignoredPaths: [
      ...(options.discovery?.ignoredPaths ?? []),
      ...(outputInsideRoot ? [outputDir] : [])
    ],
    excludedPaths
  };
  const providerIgnoredPaths = [...discovery.ignoredPaths, ...excludedPaths];
  const snapshot = await discoverRepository(root, discovery);
  const local = evaluateRules(snapshot);
  const forgeManifest = buildForgeOsManifest(snapshot);
  const [forgeos, runtime, supplyChain] = await Promise.all([
    runForgeOsBridge(forgeManifest, options.forgeos ?? { mode: 'auto' }),
    runRuntimeAnalysis({ root, snapshot, ignoredPaths: providerIgnoredPaths, ...(options.runtime ?? { mode: 'off' }) }),
    analyzeSupplyChain({ root, ignoredPaths: providerIgnoredPaths, ...(options.supplyChain ?? { mode: 'offline' }) })
  ]);
  const charges = [
    ...local.charges,
    ...forgeos.findings.map((finding) => forgeFindingToCharge(finding, snapshot)),
    ...runtimeCharges(runtime, snapshot),
    ...supplyChainCharges(supplyChain, snapshot)
  ];
  const verdict = calculateVerdict(charges, snapshot.coverage);
  const reasoning = reasonAboutEvidence({
    charges,
    safeguards: local.safeguards,
    coverage: snapshot.coverage,
    providers: {
      forgeos: { status: forgeos.status, mode: forgeos.mode },
      runtime: { status: runtime.status, provider: runtime.provider },
      supplyChain: { status: supplyChain.status, mode: supplyChain.mode }
    }
  });

  const draft = {
    schemaVersion: 'repotrial.report.v2',
    scan: {
      id: scanId,
      createdAt: now,
      target: options.includeAbsolutePaths ? root : '.',
      targetName: path.basename(root),
      coverage: snapshot.coverage,
      totalBytes: snapshot.totalBytes,
      omissions: snapshot.omissions
    },
    verdict,
    charges,
    safeguards: local.safeguards,
    reasoning,
    forgeos,
    runtime,
    supplyChain: supplySummary(supplyChain),
    integrity: {
      artifactProof: 'artifact-proof.json',
      provenance: 'provenance.intoto.json',
      signature: options.signing?.privateKey ? 'provenance.dsse.json' : options.signing?.cosign ? 'provenance.sigstore.json' : null,
      signatures: [
        ...(options.signing?.privateKey ? ['provenance.dsse.json'] : []),
        ...(options.signing?.cosign ? ['provenance.sigstore.json'] : [])
      ]
    }
  };

  const baseline = await resolveBaseline(options, root);
  if (baseline) draft.differential = compareReports(baseline, draft);
  const reportWithoutReceipt = redactSensitiveValues(draft);
  const receipt = { algorithm: 'sha256', sha256: sha256(stableStringify(reportWithoutReceipt)) };
  const report = { ...reportWithoutReceipt, receipt };

  await mkdir(outputDir, { recursive: true });
  const artifacts = {
    verdict: path.join(outputDir, 'verdict.json'),
    evidence: path.join(outputDir, 'evidence.json'),
    report: path.join(outputDir, 'report.html'),
    badge: path.join(outputDir, 'repotrial-badge.svg'),
    forgeosManifest: path.join(outputDir, 'forgeos-agent-surface.json'),
    sarif: path.join(outputDir, 'repotrial.sarif'),
    runtime: path.join(outputDir, 'runtime.json'),
    supplyChain: path.join(outputDir, 'supply-chain.json')
  };
  if (supplyChain.sbom) artifacts.sbom = path.join(outputDir, 'sbom.cdx.json');
  if (report.differential) artifacts.differential = path.join(outputDir, 'differential.json');

  const writes = [
    atomicWrite(artifacts.verdict, `${JSON.stringify(report, null, 2)}\n`),
    atomicWrite(artifacts.evidence, `${JSON.stringify(buildEvidenceArtifact(report), null, 2)}\n`),
    atomicWrite(artifacts.report, renderHtmlReport(report)),
    atomicWrite(artifacts.badge, renderBadge(verdict)),
    atomicWrite(artifacts.forgeosManifest, `${JSON.stringify(forgeManifest, null, 2)}\n`),
    atomicWrite(artifacts.sarif, `${JSON.stringify(buildSarifReport(report, { version: VERSION }), null, 2)}\n`),
    atomicWrite(artifacts.runtime, `${JSON.stringify(runtime, null, 2)}\n`),
    atomicWrite(artifacts.supplyChain, `${JSON.stringify(supplyChain, null, 2)}\n`)
  ];
  if (artifacts.sbom) writes.push(atomicWrite(artifacts.sbom, `${JSON.stringify(supplyChain.sbom, null, 2)}\n`));
  if (artifacts.differential) writes.push(atomicWrite(artifacts.differential, `${JSON.stringify(report.differential, null, 2)}\n`));
  await Promise.all(writes);

  const proofNames = Object.values(artifacts).map((filename) => path.basename(filename)).sort();
  const proof = await buildArtifactProof(outputDir, proofNames, { createdAt: now });
  artifacts.proof = path.join(outputDir, 'artifact-proof.json');
  await atomicWrite(artifacts.proof, `${JSON.stringify(proof, null, 2)}\n`);
  const git = await gitMetadata(root);
  const provenance = buildProvenance(proof, {
    repository: options.provenance?.repository ?? git.repository,
    commit: options.provenance?.commit ?? git.commit,
    builderId: options.provenance?.builderId,
    invocationId: scanId,
    startedOn: now,
    finishedOn: new Date().toISOString()
  });
  artifacts.provenance = path.join(outputDir, 'provenance.intoto.json');
  await atomicWrite(artifacts.provenance, `${JSON.stringify(provenance, null, 2)}\n`);
  if (options.signing?.privateKey) {
    const envelope = await signStatement(provenance, options.signing.privateKey, { passphrase: options.signing.passphrase });
    artifacts.attestation = path.join(outputDir, 'provenance.dsse.json');
    await atomicWrite(artifacts.attestation, `${JSON.stringify(envelope, null, 2)}\n`);
  }

  let sigstore = null;
  if (options.signing?.cosign) {
    artifacts.sigstore = path.join(outputDir, 'provenance.sigstore.json');
    sigstore = await signWithCosign(artifacts.provenance, artifacts.sigstore, {
      cosignBin: options.signing.cosignBin,
      key: options.signing.cosignKey,
      timeoutMs: options.signing.cosignTimeoutMs,
      maxOutputBytes: options.signing.cosignMaxOutputBytes,
      env: options.signing.cosignEnv
    });
  }

  return { report, artifacts, proof, provenance, sigstore };
}

async function resolveBaseline(options, root) {
  if (options.baselineReport) return typeof options.baselineReport === 'string' ? readReport(options.baselineReport) : options.baselineReport;
  if (!options.baselineRef) return null;
  return loadBaselineFromGit(root, options.baselineRef, async (baselineRoot) => {
    const outputDir = await mkdtemp(path.join(tmpdir(), 'repotrial-baseline-scan-'));
    try {
      return (await scanRepository({
        root: baselineRoot,
        outputDir,
        discovery: options.discovery,
        forgeos: options.forgeos ?? { mode: 'auto' },
        runtime: options.runtime ?? { mode: 'off' },
        supplyChain: options.supplyChain ?? { mode: 'offline' },
        includeAbsolutePaths: false,
        scanId: `baseline-${options.baselineRef}`
      })).report;
    } finally { await rm(outputDir, { recursive: true, force: true }); }
  });
}

function runtimeCharges(runtime, snapshot) {
  if (runtime.status !== 'completed') return [];
  const charges = [];
  for (const run of runtime.runs) {
    const candidate = run.candidate;
    const file = snapshot.files.find((item) => item.path === candidate.packagePath);
    const baseEvidence = [{
      path: candidate.packagePath,
      startLine: file ? findLine(file, new RegExp(`"${escapeRegex(candidate.name)}"\\s*:`)) ?? 1 : 1,
      endLine: file ? findLine(file, new RegExp(`"${escapeRegex(candidate.name)}"\\s*:`)) ?? 1 : 1,
      snippet: redactSensitiveText(`${candidate.name}: ${candidate.command}`),
      fileSha256: file?.sha256 ?? null,
      fingerprint: sha256(`runtime\0${candidate.packagePath}\0${candidate.name}\0${candidate.command}`),
      stableFingerprint: sha256(`runtime\0${candidate.packagePath}\0${candidate.name}\0${candidate.command}`),
      severity: 'high'
    }];
    const networkEvents = run.events.filter((item) => ['network', 'dns', 'network-tool'].includes(item.kind));
    if (networkEvents.length) charges.push(externalCharge({
      ruleId: 'runtime-network-attempt', title: 'Runtime network activity from an agent execution surface', severity: 'critical', evidence: baseEvidence,
      rationale: `Sandbox execution of ${candidate.name} attempted ${networkEvents.length} network operation(s).`,
      remediation: 'Remove runtime downloads and remote execution. Vendor and verify inputs before executing them.', source: 'repotrial-runtime'
    }));
    if (run.filesystemChanges.length) charges.push(externalCharge({
      ruleId: 'runtime-filesystem-mutation', title: 'Runtime filesystem mutation', severity: 'medium', evidence: baseEvidence,
      rationale: `Sandbox execution of ${candidate.name} created, modified, or deleted ${run.filesystemChanges.length} file(s).`,
      remediation: 'Constrain writable paths and review every runtime mutation before allowing the agent action.', source: 'repotrial-runtime'
    }));
  }
  return charges;
}

function supplyChainCharges(supplyChain, snapshot) {
  if (supplyChain.status !== 'completed') return [];
  const charges = [];
  for (const vuln of supplyChain.vulnerabilities ?? []) {
    const component = supplyChain.components.find((item) => item.purl === vuln.component.purl);
    const file = snapshot.files.find((item) => item.path === component?.sourceFile);
    const line = file ? findLine(file, new RegExp(escapeRegex(component.name), 'i')) ?? 1 : 1;
    charges.push(externalCharge({
      ruleId: `known-vulnerable-dependency:${vuln.id}`, title: `Known vulnerable dependency: ${vuln.id}`, severity: vuln.severity === 'unknown' ? 'medium' : vuln.severity,
      evidence: component ? [{ path: component.sourceFile, startLine: line, endLine: line, snippet: `${component.name}@${component.version}`, fileSha256: file?.sha256 ?? null, fingerprint: sha256(`supply\0${vuln.id}\0${component.purl}`), stableFingerprint: sha256(`supply\0${vuln.id}\0${component.purl}`), severity: vuln.severity }] : [],
      rationale: `${vuln.summary} affects ${vuln.component.name}@${vuln.component.version}.`,
      remediation: 'Upgrade to a non-affected version or apply the advisory mitigation and verify the resolved lockfile.', source: 'repotrial-supply-chain'
    }));
  }
  for (const finding of supplyChain.container?.findings ?? []) charges.push(externalCharge({
    ruleId: `container-vulnerability:${finding.id}`, title: `Container vulnerability: ${finding.id}`, severity: finding.severity === 'unknown' ? 'medium' : finding.severity,
    evidence: [], rationale: `${finding.package || 'Container component'} ${finding.installedVersion ?? ''}: ${finding.title || finding.id}`,
    remediation: finding.fixedVersion ? `Upgrade to ${finding.fixedVersion} or later and rebuild the image.` : 'Apply the scanner remediation, rebuild, and rescan the image.', source: 'repotrial-container'
  }));
  return charges;
}

function externalCharge(input) {
  const evidence = input.evidence.map((item) => ({ ...item }));
  return { ruleId: input.ruleId, title: input.title, severity: input.severity, status: 'proven', confidence: evidence.length ? 'high' : 'external-evidence', evidence, rationale: redactSensitiveText(input.rationale), remediation: redactSensitiveText(input.remediation), source: input.source };
}

function supplySummary(value) {
  return {
    schemaVersion: value.schemaVersion,
    status: value.status,
    mode: value.mode,
    componentCount: value.components?.length ?? 0,
    vulnerabilityCount: value.vulnerabilities?.length ?? 0,
    unknownLicenseCount: value.licenses?.unknownCount ?? 0,
    imageCount: value.images?.length ?? 0,
    container: { status: value.container?.status ?? 'not-configured', provider: value.container?.provider ?? null, findingCount: value.container?.findings?.length ?? 0 },
    diagnostics: value.diagnostics ?? []
  };
}

function forgeFindingToCharge(finding, snapshot) {
  const anchor = resolveForgeOsAnchor(finding.path, snapshot);
  const evidence = anchor ? [{
    path: anchor.file.path, startLine: anchor.line, endLine: anchor.line, snippet: anchor.snippet, fileSha256: anchor.file.sha256,
    fingerprint: sha256(`forgeos\0${finding.id}\0${anchor.file.path}\0${anchor.line}\0${finding.title}`), stableFingerprint: sha256(`forgeos\0${finding.id}\0${anchor.file.path}\0${finding.title}`), severity: finding.severity, externalLocation: finding.path
  }] : finding.path ? [{
    path: finding.path, startLine: finding.line, endLine: finding.line, snippet: finding.description || finding.title, fileSha256: null,
    fingerprint: sha256(`forgeos\0${finding.id}\0${finding.path}\0${finding.line}\0${finding.title}`), stableFingerprint: sha256(`forgeos\0${finding.id}\0${finding.path}\0${finding.title}`), severity: finding.severity, externalLocation: finding.path
  }] : [];
  return {
    ruleId: `forgeos:${finding.id}`, title: redactSensitiveText(finding.title), severity: finding.severity, status: 'proven',
    confidence: anchor ? 'external-evidence-anchored' : 'external-evidence', evidence,
    rationale: redactSensitiveText(finding.description || 'Imported from the ForgeOS agent-surface security engine.'),
    remediation: redactSensitiveText(finding.remediation || 'Review the ForgeOS finding and apply the least-privilege remediation.'), source: 'forgeos'
  };
}

function resolveForgeOsAnchor(location, snapshot) {
  if (!location) return null;
  const direct = snapshot.files.find((file) => file.path === location);
  if (direct) return anchorAt(direct, 1);
  const packageMatch = /^package:([^:]+):(.+)$/.exec(location);
  if (packageMatch) {
    const [, packageName, scriptName] = packageMatch;
    for (const file of snapshot.files.filter((candidate) => /(?:^|\/)package\.json$/i.test(candidate.path))) {
      const parsed = safeJson(file.content);
      if (String(parsed?.name ?? '') !== packageName) continue;
      const line = findLine(file, new RegExp(`"${escapeRegex(scriptName)}"\\s*:`));
      if (line) return anchorAt(file, line);
    }
  }
  const mcpMatch = /^mcp:([^/]+)(?:\/(.+))?$/.exec(location);
  if (mcpMatch) {
    const serverId = mcpMatch[1];
    for (const file of snapshot.files.filter((candidate) => /\.(?:json|ya?ml|toml)$/i.test(candidate.path))) {
      const line = findLine(file, new RegExp(escapeRegex(serverId), 'i'));
      if (line) return anchorAt(file, line);
    }
  }
  const envMatch = /^env:(.+)$/.exec(location);
  if (envMatch) {
    const name = envMatch[1];
    const file = snapshot.files.find((candidate) => candidate.content.includes(name));
    const line = file ? findLine(file, new RegExp(escapeRegex(name))) : null;
    if (file && line) return anchorAt(file, line);
  }
  const hookMatch = /^hook:(.+?\.(?:json|ya?ml|toml))(?::|$)/i.exec(location);
  if (hookMatch) {
    const file = snapshot.files.find((candidate) => candidate.path === hookMatch[1]);
    if (file) return anchorAt(file, 1);
  }
  return null;
}

function anchorAt(file, line) { const index = Math.max(0, line - 1); return { file, line, snippet: redactSensitiveText(file.lines.slice(Math.max(0, index - 1), Math.min(file.lines.length, index + 2)).join('\n')) }; }
function findLine(file, pattern) { const index = file.lines.findIndex((line) => pattern.test(line)); return index >= 0 ? index + 1 : null; }
function safeJson(content) { try { return JSON.parse(content); } catch { return null; } }
function escapeRegex(value) { return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function buildEvidenceArtifact(report) {
  return {
    schemaVersion: 'repotrial.evidence.v2', scanId: report.scan.id, receipt: report.receipt,
    anchors: report.charges.flatMap((charge) => charge.evidence.map((evidence) => ({ ruleId: charge.ruleId, source: charge.source, severity: charge.severity, ...evidence }))),
    omissions: report.scan.omissions
  };
}

async function gitMetadata(root) {
  const run = (args) => new Promise((resolve) => {
    const child = spawn('git', args, { cwd: root, shell: false, stdio: ['ignore', 'pipe', 'ignore'] });
    let stdout = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.on('error', () => resolve(null));
    child.on('close', (code) => resolve(code === 0 ? stdout.trim() : null));
  });
  const [commit, repository] = await Promise.all([run(['rev-parse', 'HEAD']), run(['config', '--get', 'remote.origin.url'])]);
  return { commit, repository };
}

export async function atomicWrite(filename, content, operations = { writeFile, rename, rm }) {
  const temporary = `${filename}.${process.pid}.${Math.random().toString(16).slice(2)}.tmp`;
  await operations.writeFile(temporary, content, { mode: 0o644 });
  try {
    await operations.rename(temporary, filename);
  } catch (error) {
    if (!['EEXIST', 'EPERM', 'ENOTEMPTY'].includes(error?.code)) {
      await operations.rm(temporary, { force: true }).catch(() => {});
      throw error;
    }
    await operations.rm(filename, { force: true });
    try {
      await operations.rename(temporary, filename);
    } catch (replacementError) {
      await operations.rm(temporary, { force: true }).catch(() => {});
      throw replacementError;
    }
  }
}