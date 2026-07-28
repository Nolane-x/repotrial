#!/usr/bin/env node
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanRepository } from '../src/core/analyze.mjs';
import { probeForgeOsCli } from '../src/bridge/forgeos.mjs';

const args = process.argv.slice(2);
const forgeRoot = valueOf('--forge-root') ?? process.env.FORGEOS_ROOT;
if (!forgeRoot) {
  console.error('Usage: npm run verify:forgeos -- --forge-root ../forge-os');
  process.exit(1);
}

const engine = await probeForgeOsCli({ forgeRoot });
if (engine.status !== 'ready') throw new Error(`ForgeOS is not ready: ${engine.error ?? engine.status}`);

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.resolve(here, '../tests/fixtures/reckless-agent');
const outputDir = await mkdtemp(path.join(tmpdir(), 'repotrial-forgeos-acceptance-'));
try {
  const result = await scanRepository({
    root: fixture,
    outputDir,
    forgeos: { mode: 'cli', forgeRoot, depth: 'full' },
    now: '2026-07-27T00:00:00.000Z',
    scanId: 'forgeos-acceptance-v061'
  });
  const bridge = result.report.forgeos;
  if (bridge.status !== 'ok') throw new Error(`Bridge status is ${bridge.status}: ${bridge.error ?? ''}`);
  if (bridge.security?.status !== 'blocked') throw new Error(`Expected blocked security report, got ${bridge.security?.status}`);
  if (!bridge.security?.reportSha256) throw new Error('ForgeOS security receipt is missing.');
  if (!bridge.engine?.version) throw new Error('ForgeOS runtime evidence is missing.');
  if (!bridge.remediationRoute?.steps?.length) throw new Error('ForgeOS remediation RoutePlan is missing.');
  if (!bridge.findings.some((finding) => finding.code === 'pipe-to-shell')) throw new Error('Expected pipe-to-shell finding was not imported.');

  console.log(JSON.stringify({
    status: 'pass',
    forgeosVersion: bridge.engine.version,
    securityStatus: bridge.security.status,
    findings: bridge.findings.length,
    securityReceipt: bridge.security.reportSha256,
    technique: bridge.remediationRoute.steps[0].techniqueId,
    reportReceipt: result.report.receipt.sha256
  }, null, 2));
} finally {
  await rm(outputDir, { recursive: true, force: true });
}

function valueOf(name) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}
