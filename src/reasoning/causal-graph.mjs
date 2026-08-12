import { sha256, stableStringify } from '../core/hash.mjs';

const NODE_ORDER = Object.freeze({
  EVIDENCE: 0,
  SAFEGUARD: 1,
  CAPABILITY: 2,
  CLAIM: 3,
  IDENTITY: 4,
  SECRET: 5,
  MEMORY: 6,
  TOOL: 7,
  EXECUTION_SURFACE: 8,
  DATA_SOURCE: 9,
  STATE: 10,
  SINK: 11,
  TRUST_DOMAIN: 12
});

const ROLE_PROJECTIONS = Object.freeze({
  'secret-access': [
    { type: 'SECRET', role: 'credential-material', relation: 'READS_FROM', label: 'Credential or secret material' }
  ],
  'shell-exec': [
    { type: 'EXECUTION_SURFACE', role: 'shell-execution', relation: 'EXECUTES', label: 'Shell execution surface' }
  ],
  'dependency-execution': [
    { type: 'EXECUTION_SURFACE', role: 'dependency-lifecycle-execution', relation: 'EXECUTES', label: 'Dependency lifecycle execution surface' }
  ],
  'broad-tool-access': [
    { type: 'TOOL', role: 'broad-tool-surface', relation: 'CONTROLS', label: 'Broad tool surface' }
  ],
  'network-egress': [
    { type: 'SINK', role: 'external-network', relation: 'ENABLES', label: 'External network sink' }
  ],
  'destructive-action': [
    { type: 'SINK', role: 'destructive-effect', relation: 'ENABLES', label: 'Destructive action sink' }
  ],
  'filesystem-write': [
    { type: 'STATE', role: 'repository-filesystem', relation: 'WRITES_TO', label: 'Mutable repository filesystem state' }
  ],
  'instruction-control': [
    { type: 'DATA_SOURCE', role: 'instruction-control-plane', relation: 'CONTROLS', label: 'Instruction control plane' }
  ],
  'supply-chain-exposure': [
    { type: 'DATA_SOURCE', role: 'supply-chain-input', relation: 'READS_FROM', label: 'Supply-chain input' }
  ],
  'verification-bypass': [
    { type: 'STATE', role: 'verification-state', relation: 'CONTROLS', label: 'Verification/completion state' }
  ],
  'persistent-state': [
    { type: 'MEMORY', role: 'persistent-agent-state', relation: 'WRITES_TO', label: 'Persistent agent state' }
  ],
  'memory-write': [
    { type: 'MEMORY', role: 'persistent-agent-state', relation: 'WRITES_TO', label: 'Persistent agent state' }
  ],
  'ci-identity-access': [
    { type: 'IDENTITY', role: 'ci-automation-identity', relation: 'AUTHORIZES', label: 'CI automation identity' }
  ],
  'identity-access': [
    { type: 'IDENTITY', role: 'reachable-identity', relation: 'AUTHORIZES', label: 'Reachable execution identity' }
  ],
  'privileged-action': [
    { type: 'SINK', role: 'privileged-action', relation: 'ENABLES', label: 'Privileged action sink' }
  ]
});

export function buildCausalSecurityGraph(input = {}) {
  const reasoning = input.reasoning && typeof input.reasoning === 'object' ? input.reasoning : {};
  const coreGraph = reasoning.graph && typeof reasoning.graph === 'object' ? reasoning.graph : { nodes: [], edges: [] };
  const nodes = new Map();
  const edges = new Map();

  for (const source of Array.isArray(coreGraph.nodes) ? coreGraph.nodes : []) addNode(nodes, canonicalCoreNode(source));
  for (const source of Array.isArray(coreGraph.edges) ? coreGraph.edges : []) addEdge(edges, canonicalCoreEdge(source));

  const observedCapabilities = [...nodes.values()]
    .filter((node) => node.type === 'CAPABILITY' && node.observed === true && typeof node.capability === 'string')
    .map((node) => node.capability)
    .sort();

  for (const capability of observedCapabilities) {
    const capabilityId = findCapabilityId(nodes, capability);
    if (!capabilityId) continue;
    for (const projection of ROLE_PROJECTIONS[capability] ?? []) {
      const roleNode = buildRoleNode(projection.type, projection.role, projection.label, capability);
      addNode(nodes, roleNode);
      addEdge(edges, buildEdge(capabilityId, roleNode.id, projection.relation, { basis: 'observed-capability', capability }));
    }
  }

  for (const crossing of explicitTrustCrossings(input.charges)) {
    const source = buildTrustDomainNode(crossing.source);
    const target = buildTrustDomainNode(crossing.target);
    addNode(nodes, source);
    addNode(nodes, target);
    addEdge(edges, buildEdge(source.id, target.id, 'CROSSES_TRUST_BOUNDARY', {
      basis: 'explicit-evidence-anchor',
      evidenceFingerprint: crossing.evidenceFingerprint
    }));
  }

  const orderedNodes = [...nodes.values()].sort(compareNodes);
  const orderedEdges = [...edges.values()].sort(compareEdges);
  const graphBody = {
    schemaVersion: 'repotrial.causal-graph.v1',
    nodes: orderedNodes,
    edges: orderedEdges
  };
  const receipt = sha256(stableStringify(graphBody));
  return {
    ...graphBody,
    receipt,
    summary: {
      nodeCount: orderedNodes.length,
      edgeCount: orderedEdges.length,
      observedCapabilityCount: observedCapabilities.length,
      trustBoundaryCrossingCount: orderedEdges.filter((edge) => edge.relation === 'CROSSES_TRUST_BOUNDARY').length,
      roleNodeCount: orderedNodes.filter((node) => !['EVIDENCE', 'SAFEGUARD', 'CAPABILITY', 'CLAIM'].includes(node.type)).length
    }
  };
}

function canonicalCoreNode(value) {
  if (!value || typeof value !== 'object' || typeof value.id !== 'string' || typeof value.type !== 'string') return null;
  return canonicalObject(value);
}

function canonicalCoreEdge(value) {
  if (!value || typeof value !== 'object' || typeof value.from !== 'string' || typeof value.to !== 'string' || typeof value.relation !== 'string') return null;
  const edge = canonicalObject(value);
  if (!edge.id) edge.id = edgeId(edge.from, edge.to, edge.relation, edge.basis ?? null);
  return edge;
}

function buildRoleNode(type, role, label, capability) {
  const semantic = stableStringify({ type, role });
  return {
    id: `causal:${type.toLowerCase()}:${digest(semantic)}`,
    type,
    role,
    label,
    observed: true,
    derivedFromCapability: capability
  };
}

function buildTrustDomainNode(domain) {
  return {
    id: `causal:trust-domain:${digest(domain)}`,
    type: 'TRUST_DOMAIN',
    domain,
    label: domain
  };
}

function explicitTrustCrossings(charges) {
  const map = new Map();
  for (const charge of Array.isArray(charges) ? charges : []) {
    for (const evidence of Array.isArray(charge?.evidence) ? charge.evidence : []) {
      const source = trustDomain(evidence?.sourceTrustDomain);
      const target = trustDomain(evidence?.targetTrustDomain);
      if (!source || !target || source === target) continue;
      const evidenceFingerprint = stringValue(evidence?.stableFingerprint ?? evidence?.fingerprint, '') || fallbackEvidenceFingerprint(evidence);
      const key = stableStringify({ source, target, evidenceFingerprint });
      map.set(key, { source, target, evidenceFingerprint });
    }
  }
  return [...map.values()].sort((a, b) => a.source.localeCompare(b.source) || a.target.localeCompare(b.target) || a.evidenceFingerprint.localeCompare(b.evidenceFingerprint));
}

function trustDomain(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toLowerCase();
  return /^[a-z0-9][a-z0-9._:/-]{0,127}$/.test(normalized) ? normalized : null;
}

function fallbackEvidenceFingerprint(evidence) {
  return sha256(stableStringify({
    path: stringValue(evidence?.path, ''),
    startLine: finiteInteger(evidence?.startLine),
    endLine: finiteInteger(evidence?.endLine)
  }));
}

function findCapabilityId(nodes, capability) {
  for (const node of nodes.values()) if (node.type === 'CAPABILITY' && node.capability === capability) return node.id;
  return null;
}

function buildEdge(from, to, relation, metadata = {}) {
  const basis = canonicalObject(metadata);
  return {
    id: edgeId(from, to, relation, basis),
    from,
    to,
    relation,
    ...(Object.keys(basis).length ? { basis } : {})
  };
}

function edgeId(from, to, relation, basis) {
  return `causal-edge:${digest(stableStringify({ from, to, relation, basis }))}`;
}

function addNode(map, node) {
  if (!node?.id) return;
  if (!map.has(node.id)) map.set(node.id, node);
}

function addEdge(map, edge) {
  if (!edge?.id) return;
  if (!map.has(edge.id)) map.set(edge.id, edge);
}

function canonicalObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  return Object.fromEntries(Object.entries(value)
    .filter(([, item]) => item !== undefined)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, item]) => [key, canonicalValue(item)]));
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === 'object') return canonicalObject(value);
  return value;
}

function compareNodes(a, b) {
  return (NODE_ORDER[a.type] ?? 99) - (NODE_ORDER[b.type] ?? 99) || a.id.localeCompare(b.id);
}

function compareEdges(a, b) {
  return a.from.localeCompare(b.from) || a.relation.localeCompare(b.relation) || a.to.localeCompare(b.to) || a.id.localeCompare(b.id);
}

function finiteInteger(value) {
  const number = Number(value ?? 0);
  return Number.isInteger(number) && number >= 0 ? number : 0;
}

function stringValue(value, fallback) {
  return typeof value === 'string' ? value : fallback;
}

function digest(value) {
  return sha256(String(value)).slice(0, 24);
}
