import test from 'node:test';
import assert from 'node:assert/strict';
import { parseStructuredConfig } from '../src/core/structured.mjs';

test('parses YAML anchors, merge keys, block scalars, tags, and inline collections', () => {
  const text = `
defaults: &defaults
  permissions:
    - filesystem:read
    - shell:*
  description: |
    first line
    second line
server:
  <<: *defaults
  enabled: true
  tagged: !secret "opaque"
  tools: [read, { name: shell, permissions: ["*"] }]
`;
  const parsed = parseStructuredConfig(text, 'config.yaml');
  assert.equal(parsed.format, 'yaml');
  assert.equal(parsed.diagnostics.length, 0);
  assert.deepEqual(parsed.value.server.permissions, ['filesystem:read', 'shell:*']);
  assert.equal(parsed.value.defaults.description, 'first line\nsecond line\n');
  assert.equal(parsed.value.server.tagged, 'opaque');
  assert.equal(parsed.value.server.tools[1].name, 'shell');
});

test('parses TOML dotted tables, arrays of tables, multiline strings, dates, and inline tables', () => {
  const text = `
title = "agent"
message = """line one
line two"""
[server]
enabled = true
permissions = ["filesystem:read", "shell:*"]
metadata = { owner = "security", retries = 3 }
released = 2026-07-27T00:00:00Z
[[server.tools]]
name = "read"
[[server.tools]]
name = "shell"
permissions = ["*"]
`;
  const parsed = parseStructuredConfig(text, 'config.toml');
  assert.equal(parsed.format, 'toml');
  assert.equal(parsed.diagnostics.length, 0);
  assert.equal(parsed.value.message, 'line one\nline two');
  assert.deepEqual(parsed.value.server.permissions, ['filesystem:read', 'shell:*']);
  assert.equal(parsed.value.server.tools[1].name, 'shell');
  assert.equal(parsed.value.server.metadata.retries, 3);
  assert.equal(parsed.value.server.released, '2026-07-27T00:00:00Z');
});

test('rejects YAML alias cycles and enforces alias limits without crashing', () => {
  const cycle = parseStructuredConfig('a: &a\n  self: *a\n', 'cycle.yml');
  assert.equal(cycle.value, null);
  assert.ok(cycle.diagnostics.some((item) => item.code === 'alias-cycle'));

  const aliases = ['base: &base { value: 1 }'];
  for (let index = 0; index < 20; index += 1) aliases.push(`v${index}: *base`);
  const limited = parseStructuredConfig(`${aliases.join('\n')}\n`, 'many.yml', { maxAliases: 5 });
  assert.equal(limited.value, null);
  assert.ok(limited.diagnostics.some((item) => item.code === 'alias-limit'));
});

test('rejects duplicate TOML keys and depth bombs deterministically', () => {
  const duplicate = parseStructuredConfig('a = 1\na = 2\n', 'dup.toml');
  assert.equal(duplicate.value, null);
  assert.ok(duplicate.diagnostics.some((item) => item.code === 'duplicate-key'));

  const deep = `a = ${'{ b = '.repeat(80)}1${' }'.repeat(80)}`;
  const bounded = parseStructuredConfig(deep, 'deep.toml', { maxDepth: 32 });
  assert.equal(bounded.value, null);
  assert.ok(bounded.diagnostics.some((item) => item.code === 'depth-limit'));
});

test('parses JSON with bounded depth and reports syntax diagnostics', () => {
  const valid = parseStructuredConfig('{"mcpServers":{"x":{"permissions":["*"]}}}', 'mcp.json');
  assert.equal(valid.format, 'json');
  assert.equal(valid.value.mcpServers.x.permissions[0], '*');

  const invalid = parseStructuredConfig('{oops', 'mcp.json');
  assert.equal(invalid.value, null);
  assert.equal(invalid.diagnostics[0].code, 'syntax-error');
});

test('parses JSONC comments and trailing commas without changing string literals', () => {
  const source = `{
    // repository agent configuration
    "url": "https://example.invalid/a//b",
    "permissions": ["read", "write",],
    /* block comment */
    "nested": { "enabled": true, },
  }`;
  const result = parseStructuredConfig(source, '.vscode/settings.jsonc');
  assert.deepEqual(result.diagnostics, []);
  assert.equal(result.value.url, 'https://example.invalid/a//b');
  assert.deepEqual(result.value.permissions, ['read', 'write']);
  assert.equal(result.value.nested.enabled, true);
});
