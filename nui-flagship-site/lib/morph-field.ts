import { FIELD_EDGES, FIELD_NODES, type FieldDomain, type FieldNode } from './field-model';
import type { CinematicSceneState } from './scene-state';

export type MorphedFieldNode = FieldNode & { position: [number, number, number] };

type MorphScene = Pick<CinematicSceneState, 'morph' | 'fold' | 'portal' | 'typeDepth'>;

const DOMAIN_ORDER: FieldDomain[] = ['product', 'routing', 'craft', 'verification', 'research', 'evidence', 'critic'];
const DOMAIN_INDEX = new Map(DOMAIN_ORDER.map((domain, index) => [domain, index]));

function clamp01(value: number) {
  return Math.min(1, Math.max(0, Number.isFinite(value) ? value : 0));
}

function lerp(a: number, b: number, t: number) {
  return a + (b - a) * t;
}

export function morphNodePosition(node: FieldNode, scene: MorphScene): MorphedFieldNode {
  const morph = clamp01(scene.morph);
  const fold = clamp01(scene.fold);
  const portal = clamp01(scene.portal);
  const typeDepth = clamp01(scene.typeDepth);
  const domainIndex = DOMAIN_INDEX.get(node.domain) ?? 0;
  const domainAngle = -Math.PI / 2 + (domainIndex / DOMAIN_ORDER.length) * Math.PI * 2;
  const [baseX, baseY, baseZ] = node.position;
  const anchorX = Math.cos(domainAngle) * 2.95;
  const anchorY = Math.sin(domainAngle) * 2.15;
  const anchorZ = Math.sin(domainAngle * 2) * 0.72;
  const territoryBlend = morph * 0.34;
  let x = lerp(baseX, baseX * 0.72 + anchorX * 0.28, territoryBlend);
  let y = lerp(baseY, baseY * 0.76 + anchorY * 0.24, territoryBlend);
  let z = lerp(baseZ, baseZ * 0.72 + anchorZ * 0.28, territoryBlend);
  const radius = Math.hypot(x, y);
  const centerAffinity = 1 - clamp01(radius / 3.9);
  z += portal * (centerAffinity * 1.72 - (1 - centerAffinity) * 0.48);
  x *= 1 + typeDepth * 0.14;
  y *= 1 + typeDepth * 0.08;
  const side = Math.tanh(x * 3.2);
  const radialX = Math.hypot(x, 0.10);
  const theta = Math.PI * 0.61;
  const localZ = z + 0.32;
  const foldedX = side * (Math.cos(theta) * radialX - Math.sin(theta) * localZ);
  const foldedZ = Math.sin(theta) * radialX + Math.cos(theta) * localZ - 0.32;
  x = lerp(x, foldedX, fold);
  z = lerp(z, foldedZ, fold);
  y += Math.sin(domainAngle * 2 + radius * 0.55) * fold * 0.46;
  return { ...node, position: [x, y, z] };
}

export function morphFieldNodes(nodes: FieldNode[], scene: MorphScene): MorphedFieldNode[] {
  return nodes.map((node) => morphNodePosition(node, scene));
}

export function semanticNeighborhood(nodeId: string): string[] {
  if (!FIELD_NODES.some((node) => node.id === nodeId)) return [];
  const neighbors: string[] = [];
  for (const [a, b] of FIELD_EDGES) {
    if (a === nodeId && !neighbors.includes(b)) neighbors.push(b);
    if (b === nodeId && !neighbors.includes(a)) neighbors.push(a);
  }
  return [nodeId, ...neighbors];
}
