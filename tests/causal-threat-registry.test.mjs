import test from 'node:test';
import assert from 'node:assert/strict';
import { getThreatRegistry, validateThreatDefinitions } from '../src/reasoning/threat-registry.mjs';

const REQUIRED = [
  'credential-exfiltration',
  'arbitrary-code-execution',
  'unapproved-destructive-action',
  'prompt-to-tool-escalation',
  'supply-chain-compromise',
  'persistent-goal-hijacking',
  'memory-context-poisoning',
  'identity-privilege-abuse',
  'unauthorized-tool-use',
  'lifecycle-ci-credential-abuse',
  'cross-agent-delegation-escalation',
  'verification-bypass-unsafe-action'
];

test('registry preserves legacy threats and seeds agentic causal families', () => {
  const registry = getThreatRegistry();
  const ids = registry.definitions.map((item) => item.id);
  for (const id of REQUIRED) assert.equal(ids.includes(id), true, `missing threat ${id}`);
  assert.deepEqual(ids, [...ids].sort());
  assert.equal(registry.schemaVersion, 'repotrial.threat-registry.v1');
  assert.match(registry.receipt, /^[a-f0-9]{64}$/);
});

test('registry definitions have non-empty deterministic stage contracts', () => {
  const { definitions } = getThreatRegistry();
  for (const definition of definitions) {
    assert.match(definition.id, /^[a-z0-9][a-z0-9-]+$/);
    assert.ok(['info', 'low', 'medium', 'high', 'critical'].includes(definition.severity));
    assert.ok(definition.stages.length > 0);
    assert.deepEqual(definition.stages.map((stage) => stage.id), [...definition.stages.map((stage) => stage.id)].sort());
    for (const stage of definition.stages) {
      assert.ok(stage.anyOf.length > 0);
      assert.deepEqual(stage.anyOf, [...stage.anyOf].sort());
    }
  }
});

test('registry returns isolated immutable-by-copy values', () => {
  const first = getThreatRegistry();
  first.definitions[0].title = 'mutated';
  first.definitions[0].stages[0].anyOf.push('invented-capability');
  const second = getThreatRegistry();
  assert.notEqual(second.definitions[0].title, 'mutated');
  assert.equal(second.definitions[0].stages[0].anyOf.includes('invented-capability'), false);
  assert.equal(first.receipt, second.receipt);
});

test('validator rejects duplicate IDs', () => {
  const sample = {
    id: 'duplicate-threat',
    title: 'Duplicate',
    severity: 'high',
    category: 'test',
    stages: [{ id: 'stage-a', label: 'A', anyOf: ['shell-exec'] }],
    mitigatedBy: [],
    experimentHints: []
  };
  assert.throws(() => validateThreatDefinitions([sample, structuredClone(sample)]), /duplicate/i);
});

test('validator rejects malformed stages, severity, and experiment hints', () => {
  const base = {
    id: 'valid-threat',
    title: 'Valid threat',
    severity: 'high',
    category: 'test',
    stages: [{ id: 'stage-a', label: 'A', anyOf: ['shell-exec'] }],
    mitigatedBy: [],
    experimentHints: []
  };
  assert.throws(() => validateThreatDefinitions([{ ...base, severity: 'catastrophic' }]), /severity/i);
  assert.throws(() => validateThreatDefinitions([{ ...base, stages: [] }]), /stage/i);
  assert.throws(() => validateThreatDefinitions([{ ...base, stages: [{ id: 'stage-a', label: 'A', anyOf: [] }] }]), /capabil/i);
  assert.throws(() => validateThreatDefinitions([{ ...base, experimentHints: [{ stageId: 'missing', templateId: 'x' }] }]), /experiment|stage/i);
});

test('validation canonicalizes order and produces the same receipt', () => {
  const input = [
    {
      id: 'z-threat', title: 'Z', severity: 'low', category: 'test', mitigatedBy: ['z', 'a'],
      stages: [
        { id: 'z-stage', label: 'Z', anyOf: ['z-cap', 'a-cap'] },
        { id: 'a-stage', label: 'A', anyOf: ['shell-exec'] }
      ],
      experimentHints: [{ stageId: 'z-stage', templateId: 'ci-context-trigger-v1', strength: 'contextual' }]
    },
    {
      id: 'a-threat', title: 'A', severity: 'critical', category: 'test', mitigatedBy: [],
      stages: [{ id: 'a-stage', label: 'A', anyOf: ['network-egress'] }], experimentHints: []
    }
  ];
  const a = validateThreatDefinitions(input);
  const b = validateThreatDefinitions([...input].reverse().map((item) => structuredClone(item)));
  assert.deepEqual(a, b);
  assert.deepEqual(a.definitions.map((item) => item.id), ['a-threat', 'z-threat']);
});
