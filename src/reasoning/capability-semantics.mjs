const DEFINITIONS = Object.freeze({
  'secret-access': freeze(['SOURCE'], ['sensitive']),
  'shell-exec': freeze(['EXECUTION'], ['code-execution']),
  'dependency-execution': freeze(['EXECUTION'], ['code-execution', 'supply-chain']),
  'broad-tool-access': freeze(['CONTROL', 'TOOL'], ['powerful']),
  'network-egress': freeze(['SINK'], ['external']),
  'destructive-action': freeze(['SINK'], ['destructive']),
  'filesystem-write': freeze(['SINK'], ['persistent', 'stateful']),
  'instruction-control': freeze(['CONTROL'], ['untrusted-control']),
  'supply-chain-exposure': freeze(['SOURCE'], ['supply-chain']),
  'verification-bypass': freeze(['CONTROL'], ['verification-integrity']),
  'persistent-state': freeze(['PERSISTENCE'], ['persistent', 'stateful']),
  'memory-write': freeze(['PERSISTENCE'], ['persistent', 'stateful']),
  'memory-influence': freeze(['CONTROL'], ['persistent', 'stateful']),
  'ci-identity-access': freeze(['AUTHORITY', 'SOURCE'], ['privileged', 'ci']),
  'identity-access': freeze(['AUTHORITY', 'SOURCE'], ['privileged']),
  'privileged-action': freeze(['SINK'], ['privileged']),
  'approval-bypass': freeze(['CONTROL'], ['authorization-bypass']),
  'agent-delegation': freeze(['CONTROL'], ['delegation-boundary']),
  'ci-context-control': freeze(['CONTROL'], ['ci'])
});

export function getCapabilitySemantics() {
  return structuredClone(DEFINITIONS);
}

export function semanticsForCapability(capability) {
  const value = DEFINITIONS[String(capability ?? '')];
  return value ? structuredClone(value) : null;
}

function freeze(roles, properties) {
  return Object.freeze({ roles: Object.freeze([...roles].sort()), properties: Object.freeze([...properties].sort()) });
}
