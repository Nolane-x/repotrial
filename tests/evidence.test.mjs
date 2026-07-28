import test from 'node:test';
import assert from 'node:assert/strict';
import { findEvidence } from '../src/core/evidence.mjs';
import { sha256 } from '../src/core/hash.mjs';

test('bounds evidence matches and preserves correct line numbers', () => {
  const content = Array.from({ length: 250 }, (_, index) => `line ${index + 1}: danger`).join('\n');
  const file = {
    path: 'AGENTS.md',
    content,
    lines: content.split('\n'),
    sha256: sha256(content)
  };
  const evidence = findEvidence(file, /danger/g, { ruleId: 'bounded', maxMatches: 40 });
  assert.equal(evidence.length, 40);
  assert.equal(evidence[0].startLine, 1);
  assert.equal(evidence[39].startLine, 40);
});

test('redacts secret literals from evidence snippets while preserving the anchor fingerprint', () => {
  const content = 'permissions = ["network:**"] API_TOKEN="super-secret-value"';
  const file = {
    path: '.cursor/mcp.toml', content, lines: [content], sha256: 'd'.repeat(64)
  };
  const evidence = findEvidence(file, /network:\*\*/i, { ruleId: 'broad-mcp-permissions', severity: 'high' });
  assert.equal(evidence.length, 1);
  assert.match(evidence[0].snippet, /\[REDACTED\]/);
  assert.doesNotMatch(evidence[0].snippet, /super-secret-value/);
  assert.match(evidence[0].fingerprint, /^[a-f0-9]{64}$/);
});
