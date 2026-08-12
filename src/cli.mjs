import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { scanRepository } from './core/analyze.mjs';
import { discoverRepository } from './core/discover.mjs';
import { calculateVerdict, verdictMeetsThreshold } from './core/verdict.mjs';
import { compareReports, readReport } from './core/diff.mjs';
import { assertSupportedNode } from './core/node-version.mjs';
import { buildForgeOsManifest } from './bridge/manifest.mjs';
import { probeForgeOsCli } from './bridge/forgeos.mjs';
import { generateSigningKeyPair, verifyEnvelope } from './integrity/sign.mjs';
import { verifyArtifactProof, verifyProvenanceBinding } from './integrity/provenance.mjs';
import { verifyWithCosign } from './integrity/cosign.mjs';
import { createReportServer } from './server.mjs';
import { stableStringify } from './core/hash.mjs';
import { normalizeReasoningThreshold, reasoningMeetsSeverity, reasoningDifferentialMeetsSeverity } from './reasoning/gates.mjs';
import { normalizeCausalThreshold, causalMeetsSeverity, causalDifferentialMeetsSeverity } from './reasoning/causal-gates.mjs';

const VERSION = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8')).version;

export async function main(argv = process.argv.slice(2), io = console) {
  const command = argv[0] ?? 'help';
  try {
    assertSupportedNode();
    if (['help', '--help', '-h'].includes(command)) { io.log(helpText()); return 0; }
    if (['version', '--version', '-v'].includes(command)) { io.log(`repotrial ${VERSION}`); return 0; }
    if (['--help', '-h'].includes(argv[1])) { io.log(helpText()); return 0; }
    if (command === 'scan') return await scanCommand(argv.slice(1), io);
    if (command === 'diff') return await diffCommand(argv.slice(1), io);
    if (command === 'keygen') return await keygenCommand(argv.slice(1), io);
    if (command === 'verify') return await verifyCommand(argv.slice(1), io);
    if (command === 'serve') return await serveCommand(argv.slice(1), io);
    if (command === 'bridge-manifest') return await manifestCommand(argv.slice(1), io);
    if (command === 'forgeos-doctor') return await forgeOsDoctorCommand(argv.slice(1), io);
    io.error(`Unknown command: ${command}\n\n${helpText()}`);
    return 1;
  } catch (error) {
    io.error(`RepoTrial error: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }
}

async function scanCommand(args, io) {
  const parsed = parseOptions(args, new Set([
    '--output', '--forgeos', '--forgeos-url', '--forgeos-token', '--forgeos-bin', '--forgeos-root', '--forgeos-depth',
    '--runtime', '--runtime-script', '--runtime-timeout', '--runtime-max-runs', '--runtime-max-source-files', '--runtime-max-source-bytes',
    '--experiments', '--experiment-max-runs', '--experiment-max-per-candidate', '--experiment-timeout',
    '--causal', '--causal-max-depth', '--causal-max-chains', '--causal-max-runs', '--causal-max-per-candidate', '--causal-realm-scope', '--causal-max-discovered', '--causal-min-novelty', '--causal-timeout',
    '--supply-chain', '--osv-url', '--osv-timeout', '--container-scanner-command', '--container-scanner-args',
    '--baseline-report', '--baseline-ref', '--fail-on', '--fail-on-new', '--fail-on-reasoning', '--fail-on-new-reasoning', '--fail-on-causal', '--fail-on-new-causal',
    '--signing-key', '--signing-passphrase-env', '--cosign', '--cosign-key', '--cosign-bin',
    '--builder-id', '--repository-url', '--commit', '--json', '--quiet', '--include-absolute-paths',
    '--allow-insecure-forgeos-http', '--exclude', '--max-files', '--max-file-bytes', '--max-total-bytes'
  ]));
  const root = parsed.positionals[0] ?? '.';
  if (parsed.positionals.length > 1) throw new Error(`Unexpected positional argument: ${parsed.positionals[1]}`);
  const outputDir = path.resolve(parsed.values['--output'] ?? '.repotrial');
  const forgeMode = enumValue(parsed.values['--forgeos'] ?? 'auto', ['auto', 'off', 'cli', 'http'], '--forgeos');
  const forgeDepth = enumValue(parsed.values['--forgeos-depth'] ?? 'security', ['security', 'full'], '--forgeos-depth');
  const runtimeMode = enumValue(parsed.values['--runtime'] ?? 'off', ['off', 'auto', 'sandbox'], '--runtime');
  const experimentMode = enumValue(parsed.values['--experiments'] ?? 'off', ['off', 'plan', 'sandbox'], '--experiments');
  const causalMode = enumValue(parsed.values['--causal'] ?? 'off', ['off', 'analyze', 'discover', 'active'], '--causal');
  const causalRealmScope = enumValue(parsed.values['--causal-realm-scope'] ?? 'all', ['all', 'production'], '--causal-realm-scope');
  const supplyMode = enumValue(parsed.values['--supply-chain'] ?? 'offline', ['off', 'offline', 'osv'], '--supply-chain');
  const reasoningThreshold = parsed.values['--fail-on-reasoning'] ? normalizeReasoningThreshold(parsed.values['--fail-on-reasoning'], '--fail-on-reasoning') : null;
  const newReasoningThreshold = parsed.values['--fail-on-new-reasoning'] ? normalizeReasoningThreshold(parsed.values['--fail-on-new-reasoning'], '--fail-on-new-reasoning') : null;
  const causalThreshold = parsed.values['--fail-on-causal'] ? normalizeCausalThreshold(parsed.values['--fail-on-causal'], '--fail-on-causal') : null;
  const newCausalThreshold = parsed.values['--fail-on-new-causal'] ? normalizeCausalThreshold(parsed.values['--fail-on-new-causal'], '--fail-on-new-causal') : null;
  const signingKey = parsed.values['--signing-key'];
  const passphraseEnv = parsed.values['--signing-passphrase-env'];
  if (passphraseEnv && !signingKey) throw new Error('--signing-passphrase-env requires --signing-key.');
  const passphrase = passphraseEnv ? process.env[passphraseEnv] : undefined;
  if (passphraseEnv && passphrase === undefined) throw new Error(`Signing passphrase environment variable is not set: ${passphraseEnv}`);

  const result = await scanRepository({
    root, outputDir,
    includeAbsolutePaths: parsed.flags.has('--include-absolute-paths'),
    discovery: {
      excludedPaths: commaSeparated(parsed.values['--exclude']),
      ...(parsed.values['--max-files'] ? { maxFiles: positiveNumber(parsed.values['--max-files'], '--max-files') } : {}),
      ...(parsed.values['--max-file-bytes'] ? { maxFileBytes: positiveNumber(parsed.values['--max-file-bytes'], '--max-file-bytes') } : {}),
      ...(parsed.values['--max-total-bytes'] ? { maxTotalBytes: positiveNumber(parsed.values['--max-total-bytes'], '--max-total-bytes') } : {})
    },
    forgeos: {
      mode: forgeMode, url: parsed.values['--forgeos-url'], token: parsed.values['--forgeos-token'],
      forgeBin: parsed.values['--forgeos-bin'], forgeRoot: parsed.values['--forgeos-root'], depth: forgeDepth,
      allowInsecureRemote: parsed.flags.has('--allow-insecure-forgeos-http')
    },
    runtime: {
      mode: runtimeMode,
      scripts: parsed.values['--runtime-script'] ? parsed.values['--runtime-script'].split(',') : [],
      ...(parsed.values['--runtime-timeout'] ? { timeoutMs: positiveNumber(parsed.values['--runtime-timeout'], '--runtime-timeout') } : {}),
      ...(parsed.values['--runtime-max-runs'] ? { maxRuns: positiveNumber(parsed.values['--runtime-max-runs'], '--runtime-max-runs') } : {}),
      ...(parsed.values['--runtime-max-source-files'] ? { maxSourceFiles: positiveNumber(parsed.values['--runtime-max-source-files'], '--runtime-max-source-files') } : {}),
      ...(parsed.values['--runtime-max-source-bytes'] ? { maxSourceBytes: positiveNumber(parsed.values['--runtime-max-source-bytes'], '--runtime-max-source-bytes') } : {})
    },
    experiments: {
      mode: experimentMode,
      ...(parsed.values['--experiment-max-runs'] ? { maxRuns: positiveNumber(parsed.values['--experiment-max-runs'], '--experiment-max-runs') } : {}),
      ...(parsed.values['--experiment-max-per-candidate'] ? { maxPerCandidate: positiveNumber(parsed.values['--experiment-max-per-candidate'], '--experiment-max-per-candidate') } : {}),
      ...(parsed.values['--experiment-timeout'] ? { timeoutMs: positiveNumber(parsed.values['--experiment-timeout'], '--experiment-timeout') } : {})
    },
    causal: {
      mode: causalMode,
      realmScope: causalRealmScope,
      ...(parsed.values['--causal-max-depth'] ? { maxDepth: positiveNumber(parsed.values['--causal-max-depth'], '--causal-max-depth') } : {}),
      ...(parsed.values['--causal-max-chains'] ? { maxChains: positiveNumber(parsed.values['--causal-max-chains'], '--causal-max-chains') } : {}),
      ...(parsed.values['--causal-max-runs'] ? { maxRuns: positiveNumber(parsed.values['--causal-max-runs'], '--causal-max-runs') } : {}),
      ...(parsed.values['--causal-max-per-candidate'] ? { maxPerCandidate: positiveNumber(parsed.values['--causal-max-per-candidate'], '--causal-max-per-candidate') } : {}),
      ...(parsed.values['--causal-max-discovered'] ? { maxDiscoveredHypotheses: positiveNumber(parsed.values['--causal-max-discovered'], '--causal-max-discovered') } : {}),
      ...(parsed.values['--causal-min-novelty'] !== undefined ? { minDiscoveryNovelty: unitIntervalNumber(parsed.values['--causal-min-novelty'], '--causal-min-novelty') } : {}),
      ...(parsed.values['--causal-timeout'] ? { timeoutMs: positiveNumber(parsed.values['--causal-timeout'], '--causal-timeout') } : {})
    },
    supplyChain: {
      mode: supplyMode,
      osvUrl: parsed.values['--osv-url'],
      ...(parsed.values['--osv-timeout'] ? { timeoutMs: positiveNumber(parsed.values['--osv-timeout'], '--osv-timeout') } : {}),
      container: parsed.values['--container-scanner-command'] ? {
        command: parsed.values['--container-scanner-command'],
        args: parseJsonArray(parsed.values['--container-scanner-args'] ?? '[]', '--container-scanner-args')
      } : undefined
    },
    baselineReport: parsed.values['--baseline-report'],
    baselineRef: parsed.values['--baseline-ref'],
    signing: (signingKey || parsed.flags.has('--cosign')) ? {
      ...(signingKey ? { privateKey: signingKey, passphrase } : {}),
      ...(parsed.flags.has('--cosign') ? { cosign: true, cosignKey: parsed.values['--cosign-key'], cosignBin: parsed.values['--cosign-bin'] } : {})
    } : undefined,
    provenance: {
      builderId: parsed.values['--builder-id'], repository: parsed.values['--repository-url'], commit: parsed.values['--commit']
    }
  });

  const reasoningSummary = result.report.reasoning?.summary;
  const reasoningDelta = result.report.differential?.reasoning?.summary;
  const experimentSummary = result.report.experiments?.summary;
  const causalSummary = result.report.causal?.summary;
  const causalDelta = result.report.differential?.causal?.summary;
  const epistemicSummary = result.report.experiments?.epistemicDelta?.summary;
  const summary = {
    schemaVersion: 'repotrial.cli.summary.v2',
    verdict: result.report.verdict.label, score: result.report.verdict.score,
    provenCharges: result.report.charges.filter((charge) => charge.status === 'proven').length,
    filesInspected: result.report.scan.coverage.filesInspected, coverage: result.report.scan.coverage.ratio,
    forgeos: result.report.forgeos.status, forgeosVersion: result.report.forgeos.engine?.version ?? null,
    forgeosTechnique: result.report.forgeos.remediationRoute?.steps?.[0]?.techniqueId ?? null,
    runtime: result.report.runtime.status, supplyChain: result.report.supplyChain.status,
    experiments: result.report.experiments?.status ?? 'disabled',
    causal: result.report.causal?.mode ?? 'disabled',
    causalRealmScope: result.report.causal?.realmScope ?? causalRealmScope,
    causalChains: causalSummary?.chainCount ?? 0,
    causalActiveChains: causalSummary?.activeChainCount ?? 0,
    causalHighImpactActiveChains: causalSummary?.highImpactActiveChainCount ?? 0,
    causalProductionActiveChains: causalSummary?.productionActiveChainCount ?? 0,
    causalNonProductionActiveChains: causalSummary?.nonProductionActiveChainCount ?? 0,
    discoveredHypotheses: causalSummary?.discoveredHypothesisCount ?? 0,
    promotableHypotheses: causalSummary?.promotableHypothesisCount ?? 0,
    causalNewActiveChains: causalDelta?.newActiveChainCount ?? 0,
    experimentsPlanned: experimentSummary?.plannedExperimentCount ?? 0,
    experimentsExecuted: experimentSummary?.executedExperimentCount ?? 0,
    experimentPositive: experimentSummary?.positiveObservationCount ?? 0,
    experimentCharges: experimentSummary?.experimentChargeCount ?? 0,
    epistemicTransitions: (epistemicSummary?.hypothesisTransitionCount ?? 0) + (epistemicSummary?.attackPathTransitionCount ?? 0),
    newFindings: result.report.differential?.summary?.new ?? null,
    viableAttackPaths: reasoningSummary?.attackPathCounts?.VIABLE ?? 0,
    invariantViolations: reasoningSummary?.invariantViolationCount ?? 0,
    newReasoning: reasoningDelta ? {
      newCapabilities: reasoningDelta.newCapabilityCount,
      resolvedCapabilities: reasoningDelta.resolvedCapabilityCount,
      newViableAttackPaths: reasoningDelta.newViableAttackPathCount,
      resolvedViableAttackPaths: reasoningDelta.resolvedViableAttackPathCount,
      regressedHypotheses: reasoningDelta.regressedHypothesisCount,
      improvedHypotheses: reasoningDelta.improvedHypothesisCount,
      newInvariantViolations: reasoningDelta.newInvariantViolationCount,
      resolvedInvariantViolations: reasoningDelta.resolvedInvariantViolationCount
    } : null,
    outputDir, report: result.artifacts.report, badge: result.artifacts.badge, sarif: result.artifacts.sarif,
    experimentsArtifact: result.artifacts.experiments ?? null,
    causalArtifact: result.artifacts.causal ?? null,
    hypothesesArtifact: result.artifacts.hypotheses ?? null,
    sbom: result.artifacts.sbom ?? null, proof: result.artifacts.proof, provenance: result.artifacts.provenance,
    attestation: result.artifacts.attestation ?? null, sigstore: result.artifacts.sigstore ?? null, receipt: result.report.receipt.sha256
  };
  if (parsed.flags.has('--json')) io.log(JSON.stringify(summary));
  else if (!parsed.flags.has('--quiet')) printHumanSummary(summary, io);

  if (parsed.values['--fail-on']) {
    const threshold = normalizeThreshold(parsed.values['--fail-on']);
    if (verdictMeetsThreshold(result.report.verdict.label, threshold)) return 2;
  }
  if (parsed.values['--fail-on-new'] && result.report.differential) {
    const threshold = normalizeThreshold(parsed.values['--fail-on-new']);
    const newVerdict = calculateVerdict(result.report.differential.new, { ratio: 1, complete: true, omitted: 0, filesInspected: result.report.scan.coverage.filesInspected });
    if (verdictMeetsThreshold(newVerdict.label, threshold)) return 3;
  }
  if (reasoningThreshold && reasoningMeetsSeverity(result.report.reasoning, reasoningThreshold)) return 4;
  if (newReasoningThreshold && reasoningDifferentialMeetsSeverity(result.report.differential?.reasoning, newReasoningThreshold)) return 5;
  if (causalThreshold && causalMeetsSeverity(result.report.causal, causalThreshold)) return 6;
  if (newCausalThreshold && causalDifferentialMeetsSeverity(result.report.differential?.causal, newCausalThreshold)) return 7;
  return 0;
}

async function diffCommand(args, io) {
  const parsed = parseOptions(args, new Set(['--output', '--json']));
  if (parsed.positionals.length !== 2) throw new Error('diff requires <baseline-verdict.json> <current-verdict.json>.');
  const result = compareReports(await readReport(parsed.positionals[0]), await readReport(parsed.positionals[1]));
  if (parsed.values['--output']) await writeFile(path.resolve(parsed.values['--output']), `${JSON.stringify(result, null, 2)}\n`, { mode: 0o644 });
  io.log(parsed.flags.has('--json') ? JSON.stringify(result) : `${JSON.stringify(result.summary, null, 2)}${result.reasoning ? `\nReasoning: ${JSON.stringify(result.reasoning.summary)}` : ''}\nReceipt: ${result.receipt.sha256}`);
  return 0;
}

async function keygenCommand(args, io) {
  const parsed = parseOptions(args, new Set(['--output', '--passphrase-env', '--json']));
  if (parsed.positionals.length) throw new Error(`Unexpected positional argument: ${parsed.positionals[0]}`);
  const passphraseName = parsed.values['--passphrase-env'];
  const passphrase = passphraseName ? process.env[passphraseName] : undefined;
  if (passphraseName && passphrase === undefined) throw new Error(`Key passphrase environment variable is not set: ${passphraseName}`);
  const result = await generateSigningKeyPair(parsed.values['--output'] ?? '.', { passphrase });
  io.log(parsed.flags.has('--json') ? JSON.stringify(result) : `Private key: ${result.privateKey}\nPublic key: ${result.publicKey}\nKey ID: ${result.keyId}`);
  return 0;
}

async function verifyCommand(args, io) {
  const parsed = parseOptions(args, new Set(['--public-key', '--cosign', '--cosign-key', '--cosign-bin', '--certificate-identity', '--certificate-oidc-issuer', '--json']));
  const directory = path.resolve(parsed.positionals[0] ?? '.repotrial');
  if (parsed.positionals.length > 1) throw new Error(`Unexpected positional argument: ${parsed.positionals[1]}`);
  const proof = JSON.parse(await readFile(path.join(directory, 'artifact-proof.json'), 'utf8'));
  const provenanceStatement = JSON.parse(await readFile(path.join(directory, 'provenance.intoto.json'), 'utf8'));
  const artifactProof = await verifyArtifactProof(directory, proof);
  const provenance = verifyProvenanceBinding(provenanceStatement, proof);
  let signature = { valid: null, reason: 'not-requested' };
  if (parsed.values['--public-key']) {
    const envelope = JSON.parse(await readFile(path.join(directory, 'provenance.dsse.json'), 'utf8'));
    const verified = await verifyEnvelope(envelope, parsed.values['--public-key']);
    const statementMatchesProvenance = verified.valid === true && stableStringify(verified.statement) === stableStringify(provenanceStatement);
    signature = {
      valid: verified.valid === true && statementMatchesProvenance,
      keyId: verified.keyId ?? null,
      statementMatchesProvenance,
      ...((verified.valid === true && statementMatchesProvenance) ? {} : { error: verified.error ?? 'signed-statement-mismatch' })
    };
  }
  let sigstore = { valid: null, reason: 'not-requested' };
  if (parsed.flags.has('--cosign')) {
    sigstore = await verifyWithCosign(path.join(directory, 'provenance.intoto.json'), path.join(directory, 'provenance.sigstore.json'), {
      cosignBin: parsed.values['--cosign-bin'], key: parsed.values['--cosign-key'],
      certificateIdentity: parsed.values['--certificate-identity'], certificateOidcIssuer: parsed.values['--certificate-oidc-issuer']
    });
  }
  const result = { schemaVersion: 'repotrial.verify.v2', valid: artifactProof.valid && provenance.valid && signature.valid !== false && sigstore.valid !== false, artifactProof, provenance, signature, sigstore };
  io.log(parsed.flags.has('--json') ? JSON.stringify(result) : `${result.valid ? 'VALID' : 'INVALID'}
Artifact proof: ${artifactProof.valid}
Provenance binding: ${provenance.valid}
DSSE signature: ${signature.valid ?? 'not checked'}
Sigstore: ${sigstore.valid ?? 'not checked'}`);
  return result.valid ? 0 : 2;
}

async function manifestCommand(args, io) {
  const parsed = parseOptions(args, new Set(['--output', '--json']));
  const root = parsed.positionals[0] ?? '.';
  const manifest = buildForgeOsManifest(await discoverRepository(root));
  const serialized = `${JSON.stringify(manifest, null, 2)}\n`;
  if (parsed.values['--output']) {
    await writeFile(path.resolve(parsed.values['--output']), serialized, { mode: 0o600 });
    if (!parsed.flags.has('--json')) io.log(`ForgeOS agent-surface manifest written to ${path.resolve(parsed.values['--output'])}`);
  } else io.log(parsed.flags.has('--json') ? JSON.stringify(manifest) : serialized.trimEnd());
  return 0;
}

async function forgeOsDoctorCommand(args, io) {
  const parsed = parseOptions(args, new Set(['--forgeos-bin', '--forgeos-root', '--json']));
  if (parsed.positionals.length) throw new Error(`Unexpected positional argument: ${parsed.positionals[0]}`);
  const result = await probeForgeOsCli({ forgeBin: parsed.values['--forgeos-bin'], forgeRoot: parsed.values['--forgeos-root'] });
  if (parsed.flags.has('--json')) io.log(JSON.stringify(result));
  else if (result.status === 'ready') {
    io.log(`ForgeOS ready: v${result.engine.version}`);
    io.log(`Kernel techniques: ${result.engine.kernelTechniqueCount ?? 'unknown'}`);
    io.log(`Agent-surface corpus: ${result.engine.agentSurfaceAdversarial?.passed ?? '?'} / ${result.engine.agentSurfaceAdversarial?.cases ?? '?'}`);
  } else io.error(`ForgeOS ${result.status}: ${result.error ?? 'unknown error'}`);
  return result.status === 'ready' ? 0 : 1;
}

async function serveCommand(args, io) {
  const parsed = parseOptions(args, new Set(['--port', '--host']));
  const directory = path.resolve(parsed.positionals[0] ?? '.repotrial');
  const port = parsed.values['--port'] ? positiveNumber(parsed.values['--port'], '--port') : 4177;
  if (port > 65535) throw new Error('--port must be at most 65535.');
  const host = parsed.values['--host'] ?? '127.0.0.1';
  const server = createReportServer(directory);
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  const address = server.address();
  io.log(`RepoTrial report: http://${host}:${typeof address === 'object' && address ? address.port : port}`);
  await new Promise((resolve) => { const stop = () => server.close(resolve); process.once('SIGINT', stop); process.once('SIGTERM', stop); });
  return 0;
}

function parseOptions(args, allowed) {
  const positionals = []; const values = {}; const flags = new Set();
  const booleanFlags = new Set(['--json', '--quiet', '--include-absolute-paths', '--allow-insecure-forgeos-http', '--cosign']);
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg.startsWith('--')) { positionals.push(arg); continue; }
    const [name, inlineValue] = arg.split('=', 2);
    if (!allowed.has(name)) throw new Error(`Unknown option: ${name}`);
    if (booleanFlags.has(name)) { if (inlineValue !== undefined) throw new Error(`${name} does not accept a value.`); flags.add(name); continue; }
    const value = inlineValue ?? args[++index];
    if (value === undefined || value.startsWith('--')) throw new Error(`${name} requires a value.`);
    values[name] = value;
  }
  return { positionals, values, flags };
}
function enumValue(value, allowed, name) { const normalized = String(value).toLowerCase(); if (!allowed.includes(normalized)) throw new Error(`${name} must be ${allowed.join(', ')}.`); return normalized; }
function normalizeThreshold(value) { const label = String(value).toUpperCase(); if (!['CAUTIOUS', 'RECKLESS', 'DANGEROUS'].includes(label)) throw new Error('Threshold must be cautious, reckless, or dangerous.'); return label; }
function positiveNumber(value, name) { const number = Number(value); if (!Number.isInteger(number) || number <= 0) throw new Error(`${name} must be a positive integer.`); return number; }
function unitIntervalNumber(value, name) { const number = Number(value); if (!Number.isFinite(number) || number < 0 || number > 1) throw new Error(`${name} must be a number between 0 and 1.`); return number; }
function parseJsonArray(value, name) { let parsed; try { parsed = JSON.parse(value); } catch { throw new Error(`${name} must be a JSON array.`); } if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== 'string')) throw new Error(`${name} must be a JSON array of strings.`); return parsed; }
function commaSeparated(value) { return value ? String(value).split(',').map((item) => item.trim()).filter(Boolean) : []; }
function printHumanSummary(summary, io) {
  io.log(`\n⚖ RepoTrial verdict: ${summary.verdict}`);
  io.log(`  Risk score:      ${summary.score}/100`);
  io.log(`  Proven charges:  ${summary.provenCharges}`);
  io.log(`  Coverage:        ${Math.round(summary.coverage * 100)}% (${summary.filesInspected} files)`);
  io.log(`  Reasoning:       ${summary.viableAttackPaths} viable paths, ${summary.invariantViolations} invariant violations`);
  io.log(`  Experiments:     ${summary.experiments} (${summary.experimentsExecuted}/${summary.experimentsPlanned} executed, ${summary.experimentPositive} positive)`);
  io.log(`  Causal:          ${summary.causal} [${summary.causalRealmScope}] (${summary.causalActiveChains}/${summary.causalChains} active, ${summary.causalProductionActiveChains} production, ${summary.causalNonProductionActiveChains} non-production)`);
  if (summary.causal === 'discover' || summary.causal === 'active') io.log(`  Discovery:       ${summary.discoveredHypotheses} candidates, ${summary.promotableHypotheses} promotable`);
  io.log(`  Runtime:         ${summary.runtime}`);
  io.log(`  Supply chain:    ${summary.supplyChain}`);
  io.log(`  ForgeOS:         ${summary.forgeos}`);
  if (summary.newFindings !== null) io.log(`  New findings:    ${summary.newFindings}`);
  if (summary.newReasoning) io.log(`  Reasoning delta: +${summary.newReasoning.newCapabilities} capabilities, +${summary.newReasoning.newViableAttackPaths} viable paths, +${summary.newReasoning.newInvariantViolations} invariant violations`);
  io.log(`  Report:          ${summary.report}`);
  io.log(`  Receipt:         ${summary.receipt}\n`);
}
function helpText() {
  return `RepoTrial ${VERSION} — evidence-backed static, runtime, supply-chain, adaptive experiments, causal attack synthesis, differential, reasoning, and ForgeOS analysis

Usage:
  repotrial scan [path] [options]
  repotrial diff <baseline.json> <current.json> [--output file] [--json]
  repotrial keygen [--output keys] [--passphrase-env NAME] [--json]
  repotrial verify [report-directory] [verification options]
  repotrial serve [report-directory] [--host 127.0.0.1] [--port 4177]
  repotrial bridge-manifest [path] [--output file] [--json]
  repotrial forgeos-doctor [--forgeos-root ../forge-os] [--json]

Discovery and output:
  --output <dir>                    Artifact directory (default: .repotrial)
  --max-files <count>               Maximum inspected files
  --max-file-bytes <bytes>          Maximum bytes per inspected file
  --max-total-bytes <bytes>         Maximum total inspected bytes
  --include-absolute-paths          Persist the absolute target path
  --exclude <a,b>                  Exclude operator-declared relative paths

Runtime analysis:
  --runtime <mode>                  off | auto | sandbox
  --runtime-script <a,b>            Explicit package scripts to detonate
  --runtime-timeout <ms>            Wall-clock limit for each run
  --runtime-max-runs <count>        Maximum detonated candidates
  --runtime-max-source-files <n>    Maximum files copied into the sandbox
  --runtime-max-source-bytes <n>    Maximum source bytes copied into the sandbox

Adaptive experiments:
  --experiments <mode>              off | plan | sandbox (default: off)
  --experiment-max-runs <n>         Maximum targeted experiments (default: 6; hard cap: 32)
  --experiment-max-per-candidate <n> Maximum experiments per runtime candidate (default: 2; hard cap: 8)
  --experiment-timeout <ms>         Per-experiment wall-clock limit; reuses runtime timeout by default

Causal adversarial reasoning:
  --causal <mode>                   off | analyze | discover | active (default: off)
  --causal-max-depth <n>            Maximum causal chain depth (default: 8; hard cap: 16)
  --causal-max-chains <n>           Maximum retained causal chains (default: 64; hard cap: 256)
  --causal-max-runs <n>             Maximum active causal episodes (default: 6; hard cap: 32)
  --causal-max-per-candidate <n>     Maximum active probes per runtime candidate (default: 2; hard cap: 8)
  --causal-realm-scope <scope>       all | production (default: all)
  --causal-max-discovered <n>        Maximum autonomous hypothesis candidates (default: 32; hard cap: 128)
  --causal-min-novelty <0..1>        Minimum novelty versus registered threats (default: 0.35)
  --causal-timeout <ms>             Per-phase active causal sandbox timeout

Supply-chain analysis:
  --supply-chain <mode>             off | offline | osv
  --osv-url <url>                   OSV querybatch endpoint
  --osv-timeout <ms>                OSV request timeout
  --container-scanner-command <bin> External scanner executable
  --container-scanner-args <json>   JSON array of scanner arguments

Differential and gates:
  --baseline-report <file>          Compare against a previous verdict.json
  --baseline-ref <git-ref>          Scan a Git baseline in an isolated worktree
  --fail-on <verdict>               Exit 2 at cautious | reckless | dangerous
  --fail-on-new <verdict>           Exit 3 for newly introduced risk only
  --fail-on-reasoning <severity>    Exit 4 for active reasoning risk at info | low | medium | high | critical
  --fail-on-new-reasoning <severity> Exit 5 for newly introduced reasoning regressions
  --fail-on-causal <severity>       Exit 6 for active causal chains at or above severity
  --fail-on-new-causal <severity>   Exit 7 for newly active/regressed causal chains

Integrity and provenance:
  --signing-key <pem>               Sign provenance as an Ed25519 DSSE envelope
  --signing-passphrase-env <name>   Read the private-key passphrase from an env var
  --cosign                          Create a Cosign/Sigstore bundle
  --cosign-key <uri-or-file>        Optional Cosign key reference
  --cosign-bin <path>               Cosign executable (default: cosign)
  --builder-id <uri>                Provenance builder identity
  --repository-url <url>            Provenance source repository
  --commit <sha>                    Provenance source revision

ForgeOS Powered:
  --forgeos <mode>                  auto | off | cli | http
  --forgeos-bin <path>              Installed ForgeOS executable
  --forgeos-root <dir>              ForgeOS source checkout
  --forgeos-depth <level>           security | full
  --forgeos-url <url>               Versioned bridge sidecar URL
  --forgeos-token <token>           Bridge bearer token
  --allow-insecure-forgeos-http     Permit plaintext HTTP to non-loopback hosts

Output controls:
  --json                            Machine-readable one-line summary
  --quiet                           Suppress human summary
  --help                            Show this help text`;
}
