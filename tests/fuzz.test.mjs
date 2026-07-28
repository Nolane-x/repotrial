import test from 'node:test';
import assert from 'node:assert/strict';
import { parseStructuredConfig } from '../src/core/structured.mjs';
import { redactSensitiveText, redactSensitiveValues } from '../src/core/redact.mjs';
import { normalizeForgeOsFindings } from '../src/bridge/forgeos.mjs';

function generator(seed = 0x51f15e) {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
    return state >>> 0;
  };
}

function randomText(next, length) {
  const alphabet = '{}[]:=&*!|>\n\r\t"\' abcXYZ019_-./\\$';
  let value = '';
  for (let index = 0; index < length; index += 1) value += alphabet[next() % alphabet.length];
  return value;
}

test('deterministic fuzz corpus cannot crash structured parsing, redaction, or ForgeOS normalization', () => {
  const next = generator();
  for (let index = 0; index < 1_000; index += 1) {
    const text = randomText(next, next() % 2048);
    for (const filename of ['input.json', 'input.yaml', 'input.toml', 'poetry.lock']) {
      const parsed = parseStructuredConfig(text, filename, { maxDepth: 16, maxNodes: 2_000, maxAliases: 16, maxScalarBytes: 16 * 1024 });
      assert.ok(parsed && typeof parsed === 'object');
      assert.ok(JSON.stringify(parsed).length < 256 * 1024);
    }
    const redacted = redactSensitiveText(text);
    assert.equal(typeof redacted, 'string');
    assert.ok(redacted.length <= text.length + 1024);
    const nested = { finding: { title: text, severity: ['high'], path: text }, values: [text, { token: text }] };
    assert.doesNotThrow(() => redactSensitiveValues(nested, { maxDepth: 16, maxNodes: 2_000 }));
    assert.doesNotThrow(() => normalizeForgeOsFindings(nested));
  }
});
