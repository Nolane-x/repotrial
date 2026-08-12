import { sha256, stableStringify } from '../core/hash.mjs';

const SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical']);
const HINT_STRENGTHS = new Set(['contextual', 'strong', 'direct']);
const ID_RE = /^[a-z0-9][a-z0-9-]+$/;

const BUILTIN_DEFINITIONS = [
  {
    id: 'credential-exfiltration', title: 'Credential or secret exfiltration', severity: 'critical', category: 'data-exfiltration',
    stages: [
      { id: 'secret-source', label: 'Secret access', anyOf: ['secret-access'], order: 0 },
      { id: 'execution-control', label: 'Execution or tool-control primitive', anyOf: ['broad-tool-access', 'dependency-execution', 'instruction-control', 'shell-exec'], order: 1 },
      { id: 'network-egress', label: 'Network egress', anyOf: ['network-egress'], order: 2 }
    ],
    mitigatedBy: ['secret-protection'],
    experimentHints: [
      { stageId: 'secret-source', templateId: 'secret-egress-canary-v1', strength: 'direct' },
      { stageId: 'network-egress', templateId: 'secret-egress-canary-v1', strength: 'direct' }
    ]
  },
  {
    id: 'arbitrary-code-execution', title: 'Arbitrary or attacker-influenced code execution', severity: 'critical', category: 'code-execution',
    stages: [{ id: 'execution-surface', label: 'Execution surface', anyOf: ['dependency-execution', 'shell-exec'], order: 0 }],
    mitigatedBy: [], experimentHints: [{ stageId: 'execution-surface', templateId: 'ci-context-trigger-v1', strength: 'contextual' }]
  },
  {
    id: 'unapproved-destructive-action', title: 'Destructive action without effective human approval', severity: 'high', category: 'unsafe-action',
    stages: [
      { id: 'destructive-capability', label: 'Destructive capability', anyOf: ['destructive-action'], order: 0 },
      { id: 'execution-control', label: 'Execution or tool-control primitive', anyOf: ['broad-tool-access', 'dependency-execution', 'shell-exec'], order: 1 }
    ],
    mitigatedBy: ['human-approval'], experimentHints: [{ stageId: 'destructive-capability', templateId: 'filesystem-sentinel-v1', strength: 'direct' }]
  },
  {
    id: 'prompt-to-tool-escalation', title: 'Instruction boundary override escalates into powerful tools', severity: 'high', category: 'goal-hijacking',
    stages: [
      { id: 'instruction-control', label: 'Instruction control', anyOf: ['instruction-control'], order: 0 },
      { id: 'tool-power', label: 'Broad tool power', anyOf: ['broad-tool-access', 'shell-exec'], order: 1 }
    ],
    mitigatedBy: ['least-privilege'], experimentHints: [{ stageId: 'tool-power', templateId: 'ci-context-trigger-v1', strength: 'contextual' }]
  },
  {
    id: 'supply-chain-compromise', title: 'High-impact supply-chain exposure reaches an execution surface', severity: 'critical', category: 'supply-chain',
    stages: [
      { id: 'supply-chain-exposure', label: 'High-impact supply-chain exposure', anyOf: ['supply-chain-exposure'], order: 0 },
      { id: 'execution-surface', label: 'Execution surface', anyOf: ['dependency-execution', 'shell-exec'], order: 1 }
    ],
    mitigatedBy: [], experimentHints: [{ stageId: 'execution-surface', templateId: 'ci-context-trigger-v1', strength: 'contextual' }]
  },
  {
    id: 'persistent-goal-hijacking', title: 'Untrusted control persists and later steers privileged agent behavior', severity: 'critical', category: 'goal-hijacking',
    stages: [
      { id: 'untrusted-control', label: 'Untrusted instruction or control influence', anyOf: ['instruction-control'], order: 0 },
      { id: 'persistent-state', label: 'Influence persists across a later decision', anyOf: ['persistent-state', 'memory-write'], order: 1 },
      { id: 'privileged-effect', label: 'Persisted influence reaches a powerful tool or execution primitive', anyOf: ['broad-tool-access', 'shell-exec', 'destructive-action'], order: 2 }
    ],
    mitigatedBy: ['memory-isolation', 'least-privilege'], experimentHints: [{ stageId: 'persistent-state', templateId: 'memory-persistence-v1', strength: 'direct' }]
  },
  {
    id: 'memory-context-poisoning', title: 'Untrusted data persists in memory/context and influences later execution', severity: 'high', category: 'memory-context',
    stages: [
      { id: 'memory-write', label: 'Untrusted state can be written to persistent context', anyOf: ['memory-write', 'persistent-state'], order: 0 },
      { id: 'later-influence', label: 'Persisted state influences a later decision', anyOf: ['instruction-control', 'memory-influence'], order: 1 },
      { id: 'effect', label: 'Influence reaches an observable tool or execution effect', anyOf: ['broad-tool-access', 'shell-exec', 'filesystem-write'], order: 2 }
    ],
    mitigatedBy: ['memory-isolation'], experimentHints: [{ stageId: 'memory-write', templateId: 'memory-persistence-v1', strength: 'direct' }]
  },
  {
    id: 'identity-privilege-abuse', title: 'Agent-controlled execution abuses a higher-privilege identity or credential', severity: 'critical', category: 'identity-privilege',
    stages: [
      { id: 'identity-source', label: 'Privileged identity or credential becomes reachable', anyOf: ['ci-identity-access', 'identity-access', 'secret-access'], order: 0 },
      { id: 'control', label: 'Execution or tool control can act with that identity', anyOf: ['broad-tool-access', 'dependency-execution', 'shell-exec'], order: 1 },
      { id: 'privileged-sink', label: 'A privileged action sink is reachable', anyOf: ['destructive-action', 'privileged-action'], order: 2 }
    ],
    mitigatedBy: ['least-privilege', 'secret-protection'], experimentHints: [{ stageId: 'identity-source', templateId: 'ci-context-trigger-v1', strength: 'contextual' }]
  },
  {
    id: 'unauthorized-tool-use', title: 'Untrusted or weakly authorized control reaches a powerful tool', severity: 'high', category: 'tool-misuse',
    stages: [
      { id: 'control-source', label: 'Untrusted instruction or weak authorization controls the decision', anyOf: ['instruction-control', 'approval-bypass'], order: 0 },
      { id: 'tool-power', label: 'Powerful tool capability is reachable', anyOf: ['broad-tool-access', 'shell-exec', 'destructive-action'], order: 1 }
    ],
    mitigatedBy: ['human-approval', 'least-privilege'], experimentHints: [{ stageId: 'tool-power', templateId: 'ci-context-trigger-v1', strength: 'contextual' }]
  },
  {
    id: 'lifecycle-ci-credential-abuse', title: 'Lifecycle execution under CI context reaches synthetic credential material or a privileged effect', severity: 'critical', category: 'ci-lifecycle',
    stages: [
      { id: 'lifecycle-execution', label: 'Dependency or lifecycle execution occurs', anyOf: ['dependency-execution'], order: 0 },
      { id: 'ci-context', label: 'Execution is conditional on CI/automation context', anyOf: ['ci-context-control', 'ci-identity-access'], order: 1 },
      { id: 'credential-or-sink', label: 'CI context reaches credential material or a privileged effect', anyOf: ['secret-access', 'network-egress', 'privileged-action'], order: 2 }
    ],
    mitigatedBy: ['secret-protection', 'least-privilege'], experimentHints: [
      { stageId: 'ci-context', templateId: 'ci-context-trigger-v1', strength: 'direct' },
      { stageId: 'credential-or-sink', templateId: 'secret-egress-canary-v1', strength: 'direct' }
    ]
  },
  {
    id: 'cross-agent-delegation-escalation', title: 'Delegated agent authority expands beyond the initiating agent boundary', severity: 'high', category: 'multi-agent',
    stages: [
      { id: 'delegation-control', label: 'Agent can delegate or route work to another execution context', anyOf: ['agent-delegation', 'instruction-control'], order: 0 },
      { id: 'authority-expansion', label: 'Delegated context exposes broader authority', anyOf: ['broad-tool-access', 'privileged-action', 'shell-exec'], order: 1 }
    ],
    mitigatedBy: ['least-privilege', 'delegation-boundary'], experimentHints: [{ stageId: 'authority-expansion', templateId: 'ci-context-trigger-v1', strength: 'contextual' }]
  },
  {
    id: 'verification-bypass-unsafe-action', title: 'Verification bypass allows an unsafe or destructive action to be treated as completed', severity: 'high', category: 'verification-integrity',
    stages: [
      { id: 'verification-bypass', label: 'Verification or completion evidence can be bypassed', anyOf: ['verification-bypass'], order: 0 },
      { id: 'unsafe-effect', label: 'A powerful or destructive effect is reachable', anyOf: ['destructive-action', 'shell-exec', 'privileged-action'], order: 1 }
    ],
    mitigatedBy: ['human-approval', 'independent-verification'], experimentHints: [{ stageId: 'unsafe-effect', templateId: 'filesystem-sentinel-v1', strength: 'contextual' }]
  }
];

const BUILTIN = validateThreatDefinitions(BUILTIN_DEFINITIONS);

export function getThreatRegistry() {
  return structuredClone(BUILTIN);
}

export function validateThreatDefinitions(input) {
  if (!Array.isArray(input)) throw new TypeError('Threat definitions must be an array.');
  const seen = new Set();
  const definitions = input.map((definition, index) => normalizeDefinition(definition, index));
  for (const definition of definitions) {
    if (seen.has(definition.id)) throw new TypeError(`Duplicate threat id: ${definition.id}`);
    seen.add(definition.id);
  }
  definitions.sort((a, b) => a.id.localeCompare(b.id));
  const receipt = sha256(stableStringify(definitions));
  return { schemaVersion: 'repotrial.threat-registry.v1', definitions, receipt };
}

function normalizeDefinition(value, index) {
  if (!value || typeof value !== 'object') throw new TypeError(`Threat definition ${index} must be an object.`);
  const id = requiredId(value.id, `threat definition ${index}`);
  const title = requiredString(value.title, `Threat ${id} title`);
  const severity = String(value.severity ?? '').toLowerCase();
  if (!SEVERITIES.has(severity)) throw new TypeError(`Threat ${id} has invalid severity.`);
  const category = requiredId(value.category, `Threat ${id} category`);
  if (!Array.isArray(value.stages) || value.stages.length === 0) throw new TypeError(`Threat ${id} must define at least one stage.`);
  const stageIds = new Set();
  const stages = value.stages.map((stage, stageIndex) => {
    if (!stage || typeof stage !== 'object') throw new TypeError(`Threat ${id} stage ${stageIndex} must be an object.`);
    const stageId = requiredId(stage.id, `Threat ${id} stage ${stageIndex}`);
    if (stageIds.has(stageId)) throw new TypeError(`Threat ${id} has duplicate stage ${stageId}.`);
    stageIds.add(stageId);
    const anyOf = uniqueSorted(stage.anyOf);
    if (anyOf.length === 0) throw new TypeError(`Threat ${id} stage ${stageId} must define at least one capability.`);
    for (const capability of anyOf) requiredId(capability, `Threat ${id} stage ${stageId} capability`);
    const order = Number.isInteger(stage.order) && stage.order >= 0 ? stage.order : stageIndex;
    return { id: stageId, label: requiredString(stage.label, `Threat ${id} stage ${stageId} label`), anyOf, order };
  }).sort((a, b) => a.id.localeCompare(b.id));

  const mitigatedBy = uniqueSorted(value.mitigatedBy);
  for (const safeguard of mitigatedBy) requiredId(safeguard, `Threat ${id} safeguard`);
  const experimentHints = Array.isArray(value.experimentHints) ? value.experimentHints.map((hint, hintIndex) => {
    if (!hint || typeof hint !== 'object') throw new TypeError(`Threat ${id} experiment hint ${hintIndex} must be an object.`);
    const stageId = requiredId(hint.stageId, `Threat ${id} experiment hint stage`);
    if (!stageIds.has(stageId)) throw new TypeError(`Threat ${id} experiment hint references unknown stage ${stageId}.`);
    const templateId = requiredId(hint.templateId, `Threat ${id} experiment template`);
    const strength = String(hint.strength ?? 'contextual');
    if (!HINT_STRENGTHS.has(strength)) throw new TypeError(`Threat ${id} experiment hint has invalid strength.`);
    return { stageId, templateId, strength };
  }).sort((a, b) => a.stageId.localeCompare(b.stageId) || a.templateId.localeCompare(b.templateId)) : [];

  return { id, title, severity, category, stages, mitigatedBy, experimentHints };
}

function requiredId(value, label) {
  const text = String(value ?? '');
  if (!ID_RE.test(text)) throw new TypeError(`${label} must be a lowercase kebab-case id.`);
  return text;
}

function requiredString(value, label) {
  const text = typeof value === 'string' ? value.trim() : '';
  if (!text) throw new TypeError(`${label} must be a non-empty string.`);
  return text;
}

function uniqueSorted(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((item) => String(item)))].sort();
}
