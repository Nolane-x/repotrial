import { chmod, mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

export async function createFakeForgeRoot() {
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-fake-forge-'));
  const cliDir = path.join(root, 'src', 'cli');
  await mkdir(cliDir, { recursive: true });
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ name: 'forge-os', version: '0.6.1', type: 'module' }));
  const cliPath = path.join(cliDir, 'forge.mjs');
  await writeFile(cliPath, `#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
const [command, subcommand] = process.argv.slice(2);
const args = process.argv.slice(2);
const value = (name) => args[args.indexOf(name) + 1];
if (command === 'security' && subcommand === 'scan') {
  const surface = JSON.parse(await readFile(value('--file'), 'utf8'));
  if (!Array.isArray(surface.instructions) || !Array.isArray(surface.mcpServers)) process.exit(9);
  console.log(JSON.stringify({ report: {
    schemaVersion: 1,
    status: 'blocked',
    findings: [
      { id: 'prompt-injection-1', code: 'prompt-injection', severity: 'critical', location: 'AGENTS.md', message: 'Instruction attempts to cross the trust boundary' },
      { id: 'package-lifecycle-script-2', code: 'package-lifecycle-script', severity: 'high', location: 'package:reckless-agent:postinstall', message: 'Package executes code during installation' }
    ],
    summary: { critical: 1, high: 1, medium: 0 },
    reportSha256: '${'a'.repeat(64)}'
  }}));
  process.exit(2);
}
if (command === 'v06' && subcommand === 'status') {
  console.log(JSON.stringify({ status: { version: '0.6.1', executionGraphVersion: 2, kernelTechniqueCount: 128, l0TechniqueCount: 32, l1TechniqueCount: 96, outcomeCount: 1024, evaluatorCount: 128, agentSurfaceAdversarial: { cases: 20, passed: 20, missed: 0 } } }));
  process.exit(0);
}
if (command === 'route') {
  console.log(JSON.stringify({ routePlan: { schemaVersion: 2, intent: { targetOutcomeIds: ['outcome.ai-agent-engineering.test-security'] }, steps: [{ stepId: 'step-1', techniqueId: 'technique.testing-agent-tool-abuse', providerId: 'local-skill.testing-agent-tool-abuse', outcomeIds: ['outcome.ai-agent-engineering.test-security'], evidenceObligations: ['security-evidence'] }], blockers: [], executionGroups: [{ mode: 'sequential', stepIds: ['step-1'] }] } }));
  process.exit(0);
}
process.exit(1);
`);
  await chmod(cliPath, 0o755);
  return root;
}
