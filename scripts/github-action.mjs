#!/usr/bin/env node
import { appendFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { scanRepository } from '../src/core/analyze.mjs';
import { calculateVerdict, verdictMeetsThreshold } from '../src/core/verdict.mjs';
import { encodeGithubCommandValue, normalizeActionChoice, normalizeActionThreshold } from '../src/github.mjs';
import { normalizeReasoningThreshold, reasoningMeetsSeverity, reasoningDifferentialMeetsSeverity } from '../src/reasoning/gates.mjs';

const root = process.env.INPUT_PATH || '.';
const outputDir = path.resolve(process.env.INPUT_OUTPUT || '.repotrial');
const forgeMode = normalizeActionChoice(process.env.INPUT_FORGEOS_MODE, 'forgeos-mode', ['off', 'auto', 'cli', 'http'], 'off');
const forgeDepth = normalizeActionChoice(process.env.INPUT_FORGEOS_DEPTH, 'forgeos-depth', ['security', 'full'], 'security');
const runtimeMode = normalizeActionChoice(process.env.INPUT_RUNTIME_MODE, 'runtime-mode', ['off', 'auto', 'sandbox'], 'off');
const experimentMode = normalizeActionChoice(process.env.INPUT_EXPERIMENT_MODE, 'experiment-mode', ['off', 'plan', 'sandbox'], 'off');
const supplyMode = normalizeActionChoice(process.env.INPUT_SUPPLY_CHAIN_MODE, 'supply-chain-mode', ['off', 'offline', 'osv'], 'offline');
const experimentMaxRuns = positiveInteger(process.env.INPUT_EXPERIMENT_MAX_RUNS, 6, 'experiment-max-runs');
const experimentMaxPerCandidate = positiveInteger(process.env.INPUT_EXPERIMENT_MAX_PER_CANDIDATE, 2, 'experiment-max-per-candidate');
const experimentTimeout = process.env.INPUT_EXPERIMENT_TIMEOUT
  ? positiveInteger(process.env.INPUT_EXPERIMENT_TIMEOUT, 10_000, 'experiment-timeout')
  : undefined;
const failOn = normalizeActionThreshold(process.env.INPUT_FAIL_ON);
const failOnNew = process.env.INPUT_FAIL_ON_NEW ? normalizeActionThreshold(process.env.INPUT_FAIL_ON_NEW) : null;
const failOnReasoning = process.env.INPUT_FAIL_ON_REASONING ? normalizeReasoningThreshold(process.env.INPUT_FAIL_ON_REASONING, 'fail-on-reasoning') : null;
const failOnNewReasoning = process.env.INPUT_FAIL_ON_NEW_REASONING ? normalizeReasoningThreshold(process.env.INPUT_FAIL_ON_NEW_REASONING, 'fail-on-new-reasoning') : null;

await mkdir(outputDir, { recursive: true });
const result = await scanRepository({
  root,
  outputDir,
  discovery: { excludedPaths: commaSeparated(process.env.INPUT_EXCLUDE_PATHS) },
  forgeos: {
    mode: forgeMode,
    url: process.env.FORGEOS_BRIDGE_URL,
    token: process.env.REPOTRIAL_BRIDGE_TOKEN,
    forgeBin: process.env.FORGEOS_BIN,
    forgeRoot: process.env.INPUT_FORGEOS_ROOT || process.env.FORGEOS_ROOT,
    depth: forgeDepth
  },
  runtime: {
    mode: runtimeMode,
    scripts: String(process.env.INPUT_RUNTIME_SCRIPTS ?? '').split(',').map((item) => item.trim()).filter(Boolean),
    maxSourceFiles: positiveInteger(process.env.INPUT_RUNTIME_MAX_SOURCE_FILES, 20_000, 'runtime-max-source-files'),
    maxSourceBytes: positiveInteger(process.env.INPUT_RUNTIME_MAX_SOURCE_BYTES, 256 * 1024 * 1024, 'runtime-max-source-bytes')
  },
  experiments: {
    mode: experimentMode,
    maxRuns: experimentMaxRuns,
    maxPerCandidate: experimentMaxPerCandidate,
    ...(experimentTimeout ? { timeoutMs: experimentTimeout } : {})
  },
  supplyChain: { mode: supplyMode, osvUrl: process.env.OSV_QUERYBATCH_URL },
  baselineRef: process.env.INPUT_BASELINE_REF || undefined,
  signing: (process.env.INPUT_SIGNING_KEY || process.env.INPUT_SIGSTORE === 'true') ? {
    ...(process.env.INPUT_SIGNING_KEY ? { privateKey: process.env.INPUT_SIGNING_KEY } : {}),
    ...(process.env.INPUT_SIGSTORE === 'true' ? { cosign: true, cosignKey: process.env.INPUT_SIGSTORE_KEY || undefined } : {})
  } : undefined,
  provenance: {
    repository: process.env.GITHUB_SERVER_URL && process.env.GITHUB_REPOSITORY ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}` : undefined,
    commit: process.env.GITHUB_SHA,
    builderId: process.env.GITHUB_WORKFLOW_REF ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}@${process.env.GITHUB_WORKFLOW_REF}` : undefined
  }
});

const report = result.report;
const proven = report.charges.filter((charge) => charge.status === 'proven');
const viableAttackPaths = Number(report.reasoning?.summary?.attackPathCounts?.VIABLE ?? 0);
const invariantViolations = Number(report.reasoning?.summary?.invariantViolationCount ?? 0);
const reasoningDelta = report.differential?.reasoning?.summary;
const experimentSummary = report.experiments?.summary;
const epistemicSummary = report.experiments?.epistemicDelta?.summary;
const epistemicTransitions = Number(epistemicSummary?.hypothesisTransitionCount ?? 0)
  + Number(epistemicSummary?.attackPathTransitionCount ?? 0);
await writeGithubOutput({
  verdict: report.verdict.label,
  score: String(report.verdict.score),
  proven_charges: String(proven.length),
  new_findings: String(report.differential?.summary?.new ?? 0),
  viable_attack_paths: String(viableAttackPaths),
  invariant_violations: String(invariantViolations),
  new_viable_attack_paths: String(reasoningDelta?.newViableAttackPathCount ?? 0),
  new_invariant_violations: String(reasoningDelta?.newInvariantViolationCount ?? 0),
  experiments_status: report.experiments?.status ?? 'disabled',
  experiments_planned: String(experimentSummary?.plannedExperimentCount ?? 0),
  experiments_executed: String(experimentSummary?.executedExperimentCount ?? 0),
  experiments_positive: String(experimentSummary?.positiveObservationCount ?? 0),
  epistemic_transitions: String(epistemicTransitions),
  experiments_path: result.artifacts.experiments ?? '',
  report_path: result.artifacts.report,
  sarif_path: result.artifacts.sarif,
  sbom_path: result.artifacts.sbom ?? '',
  proof_path: result.artifacts.proof,
  attestation_path: result.artifacts.attestation ?? '',
  sigstore_path: result.artifacts.sigstore ?? '',
  receipt: report.receipt.sha256,
  forgeos_version: report.forgeos.engine?.version ?? '',
  forgeos_technique: report.forgeos.remediationRoute?.steps?.[0]?.techniqueId ?? ''
});
await writeStepSummary(report, result.artifacts);

console.log(`RepoTrial verdict: ${report.verdict.label} (${report.verdict.score}/100)`);
if (verdictMeetsThreshold(report.verdict.label, failOn)) process.exitCode = 2;
if (failOnNew && report.differential) {
  const verdict = calculateVerdict(report.differential.new, { ratio: 1, complete: true, omitted: 0, filesInspected: report.scan.coverage.filesInspected });
  if (verdictMeetsThreshold(verdict.label, failOnNew)) process.exitCode = 3;
}
if (!process.exitCode && failOnReasoning && reasoningMeetsSeverity(report.reasoning, failOnReasoning)) process.exitCode = 4;
if (!process.exitCode && failOnNewReasoning && reasoningDifferentialMeetsSeverity(report.differential?.reasoning, failOnNewReasoning)) process.exitCode = 5;

async function writeGithubOutput(values) {
  const filename = process.env.GITHUB_OUTPUT;
  if (!filename) return;
  const lines = Object.entries(values).map(([key, value]) => `${key}=${encodeGithubCommandValue(value)}`).join('\n');
  await appendFile(filename, `${lines}\n`);
}

async function writeStepSummary(report, artifacts) {
  const filename = process.env.GITHUB_STEP_SUMMARY;
  if (!filename) return;
  const counts = report.verdict.severityCounts;
  const reasoning = report.reasoning?.summary;
  const delta = report.differential?.reasoning?.summary;
  const experiments = report.experiments?.summary;
  const epistemic = report.experiments?.epistemicDelta?.summary;
  const epistemicTransitions = Number(epistemic?.hypothesisTransitionCount ?? 0) + Number(epistemic?.attackPathTransitionCount ?? 0);
  const markdown = `## ⚖ RepoTrial: ${report.verdict.label}\n\n` +
    `| Metric | Result |\n|---|---:|\n` +
    `| Risk score | ${report.verdict.score}/100 |\n` +
    `| Critical | ${counts.critical} |\n` +
    `| High | ${counts.high} |\n` +
    `| Coverage | ${Math.round(report.scan.coverage.ratio * 100)}% |\n` +
    `| Viable attack paths | ${reasoning?.attackPathCounts?.VIABLE ?? 0} |\n` +
    `| Invariant violations | ${reasoning?.invariantViolationCount ?? 0} |\n` +
    `| Explicit negative evidence | ${reasoning?.negativeEvidenceCount ?? 0} |\n` +
    `| Adaptive experiments | ${report.experiments?.status ?? 'disabled'} |\n` +
    `| Experiments planned | ${experiments?.plannedExperimentCount ?? 0} |\n` +
    `| Experiments executed | ${experiments?.executedExperimentCount ?? 0} |\n` +
    `| Positive experiment observations | ${experiments?.positiveObservationCount ?? 0} |\n` +
    `| Epistemic transitions | ${epistemicTransitions} |\n` +
    `| New findings | ${report.differential?.summary?.new ?? 'not compared'} |\n` +
    `| New viable attack paths | ${delta?.newViableAttackPathCount ?? 'not compared'} |\n` +
    `| New invariant violations | ${delta?.newInvariantViolationCount ?? 'not compared'} |\n` +
    `| Runtime sandbox | ${report.runtime.status} |\n` +
    `| Dependencies | ${report.supplyChain.componentCount} |\n` +
    `| Vulnerabilities | ${report.supplyChain.vulnerabilityCount} |\n` +
    `| ForgeOS bridge | ${report.forgeos.status} |\n` +
    `| ForgeOS version | ${report.forgeos.engine?.version ?? 'not connected'} |\n\n` +
    `Portable report: \`${artifacts.report}\`\n\n` +
    `${artifacts.experiments ? `Adaptive experiments: \`${artifacts.experiments}\`\n\n` : ''}` +
    `SARIF: \`${artifacts.sarif}\`\n\n` +
    `Artifact proof: \`${artifacts.proof}\`\n\n` +
    `Receipt: \`${report.receipt.sha256}\`\n`;
  await appendFile(filename, markdown);
}

function positiveInteger(value, fallback, name) {
  if (value == null || value === '') return fallback;
  const number = Number(value);
  if (!Number.isInteger(number) || number <= 0) throw new Error(`${name} must be a positive integer.`);
  return number;
}

function commaSeparated(value) { return value ? String(value).split(',').map((item) => item.trim()).filter(Boolean) : []; }
