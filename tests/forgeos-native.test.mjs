import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { discoverRepository } from '../src/core/discover.mjs';
import { buildForgeOsManifest } from '../src/bridge/manifest.mjs';
import { runForgeOsBridge } from '../src/bridge/forgeos.mjs';
import { createFakeForgeRoot } from './helpers/fake-forge.mjs';

const recklessFixture = fileURLToPath(new URL('./fixtures/reckless-agent/', import.meta.url));

test('builds the native ForgeOS v0.6 agent-surface contract', async () => {
  const snapshot = await discoverRepository(recklessFixture);
  const surface = buildForgeOsManifest(snapshot);

  assert.deepEqual(Object.keys(surface).sort(), [
    'allowedCommands',
    'envReferences',
    'hooks',
    'instructions',
    'mcpServers',
    'packages'
  ]);
  assert.equal(surface.instructions[0].path, 'AGENTS.md');
  assert.match(surface.instructions[0].text, /Ignore previous instructions/i);
  assert.equal(surface.packages[0].name, 'reckless-agent');
  assert.match(surface.packages[0].scripts.postinstall, /curl/);
  assert.ok(surface.mcpServers.some((server) =>
    server.id === 'danger' && server.tools.some((tool) => tool.permissions.includes('*'))));
  assert.ok(surface.envReferences.includes('API_TOKEN'));
  assert.doesNotMatch(JSON.stringify(surface), /super-secret-value/);
});

test('treats ForgeOS blocked exit code 2 as a valid scan and enriches full mode', async () => {
  const forgeRoot = await createFakeForgeRoot();
  const surface = {
    instructions: [], hooks: [], mcpServers: [], packages: [], allowedCommands: [], envReferences: []
  };
  const result = await runForgeOsBridge(surface, {
    mode: 'cli',
    forgeRoot,
    depth: 'full',
    timeoutMs: 5_000
  });

  assert.equal(result.status, 'ok');
  assert.equal(result.diagnostics.exitCode, 2);
  assert.equal(result.engine.version, '0.6.1');
  assert.equal(result.security.status, 'blocked');
  assert.equal(result.security.reportSha256, 'a'.repeat(64));
  assert.equal(result.findings[0].id, 'prompt-injection-1');
  assert.equal(result.remediationRoute.steps[0].techniqueId, 'technique.testing-agent-tool-abuse');
});



test('ForgeOS surface includes instruction files used by popular coding agents', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-forgeos-surfaces-'));
  const files = [
    'AGENTS.md',
    '.claude/CLAUDE.md',
    'GEMINI.md',
    '.github/copilot-instructions.md',
    '.github/instructions/security.instructions.md',
    '.cursor/rules/security.mdc',
    '.clinerules/security.md',
    '.windsurf/rules/security.md',
    '.continue/rules/security.md'
  ];
  for (const relative of files) {
    const filename = path.join(root, relative);
    await mkdir(path.dirname(filename), { recursive: true });
    await writeFile(filename, `rule from ${relative}`);
  }
  const snapshot = await discoverRepository(root);
  const surface = buildForgeOsManifest(snapshot);
  assert.deepEqual(surface.instructions.map((item) => item.path), [...files].sort());
});

test('ForgeOS surface conservatively imports wildcard permissions from YAML and TOML agent configs', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-forgeos-text-config-'));
  await mkdir(path.join(root, '.continue'), { recursive: true });
  await mkdir(path.join(root, '.cursor'), { recursive: true });
  await writeFile(path.join(root, '.continue', 'config.yaml'), 'permissions:\n  - network:**\n  - Bash(*)\n');
  await writeFile(path.join(root, '.cursor', 'mcp.toml'), 'capabilities = ["filesystem:**"]\nshell = true\n');
  const surface = buildForgeOsManifest(await discoverRepository(root));
  const serialized = JSON.stringify(surface);
  assert.match(serialized, /network:\*\*/);
  assert.match(serialized, /filesystem:\*\*/);
  assert.match(serialized, /shell:\*/);
  assert.ok(surface.allowedCommands.includes('*'));
});

test('ForgeOS manifest construction is bounded for deeply nested JSON', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-deep-manifest-'));
  const depth = 20_000;
  const content = '{"a":'.repeat(depth) + '0' + '}'.repeat(depth);
  await writeFile(path.join(root, 'settings.json'), content);
  const snapshot = await discoverRepository(root, { maxFileBytes: content.length + 100 });
  assert.doesNotThrow(() => buildForgeOsManifest(snapshot));
});

test('ForgeOS surface resolves structured YAML and TOML agent configuration', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-forgeos-structured-'));
  await mkdir(path.join(root, '.continue'), { recursive: true });
  await mkdir(path.join(root, '.cursor'), { recursive: true });
  await writeFile(path.join(root, '.continue', 'config.yaml'), `
defaults: &defaults
  permissions: [filesystem:read, network:https]
mcpServers:
  audit:
    <<: *defaults
    description: >
      audit service
      for agents
    tools:
      - name: scan
        permissions: [filesystem:read]
`);
  await writeFile(path.join(root, '.cursor', 'mcp.toml'), `
[[mcpServers]]
id = "builder"
description = "build tools"
permissions = ["shell:run"]

[[mcpServers.tools]]
name = "compile"
permissions = ["filesystem:write"]
`);
  const surface = buildForgeOsManifest(await discoverRepository(root));
  const audit = surface.mcpServers.find((server) => server.id === 'audit');
  const builder = surface.mcpServers.find((server) => server.id === 'builder');
  assert.ok(audit);
  assert.ok(audit.tools.some((tool) => tool.name === 'scan' && tool.permissions.includes('filesystem:read')));
  assert.ok(builder);
  assert.ok(builder.tools.some((tool) => tool.name === 'compile' && tool.permissions.includes('filesystem:write')));
});
