export type FieldDomain = 'product' | 'craft' | 'research' | 'routing' | 'evidence' | 'critic' | 'verification';
export type FieldNode = {
  id: string;
  label: string;
  domain: FieldDomain;
  position: [number, number, number];
  weight: number;
};

export const FIELD_NODES: FieldNode[] = [
  { id: 'intent', label: 'Experiential intent', domain: 'product', position: [-2.7, 1.8, 0.2], weight: 1.15 },
  { id: 'product-truth', label: 'Product truth', domain: 'product', position: [-2.2, 0.45, -0.5], weight: 1 },
  { id: 'routing', label: 'Skill routing', domain: 'routing', position: [-0.85, 1.2, 0.75], weight: 1.2 },
  { id: 'graph', label: 'Parent-child graph', domain: 'routing', position: [-0.3, -0.1, 0.15], weight: 0.9 },
  { id: 'type', label: 'Typography', domain: 'craft', position: [1.1, 1.85, -0.25], weight: 0.92 },
  { id: 'motion', label: 'Motion semantics', domain: 'craft', position: [2.45, 0.95, 0.45], weight: 1.08 },
  { id: 'space', label: 'Spatial dramaturgy', domain: 'craft', position: [2.6, -0.65, -0.4], weight: 1.18 },
  { id: 'source', label: 'Source archaeology', domain: 'research', position: [1.2, -2.05, 0.75], weight: 1.08 },
  { id: 'synthesis', label: 'Cross-source synthesis', domain: 'research', position: [-0.3, -2.35, -0.1], weight: 1.15 },
  { id: 'evidence', label: 'Evidence', domain: 'evidence', position: [-1.8, -1.3, 0.55], weight: 1.2 },
  { id: 'unknown', label: 'UNKNOWN / BLOCKED', domain: 'evidence', position: [-2.65, -0.25, -0.85], weight: 0.82 },
  { id: 'critic', label: 'Independent critic', domain: 'critic', position: [0.3, 2.55, -0.8], weight: 1.22 },
  { id: 'adequacy', label: 'Aesthetic adequacy', domain: 'critic', position: [1.65, 2.35, 0.55], weight: 1.12 },
  { id: 'verify', label: 'Runtime verification', domain: 'verification', position: [2.35, -1.85, 0.25], weight: 1.18 },
  { id: 'release', label: 'Release gate', domain: 'verification', position: [0.1, 0.25, 1.35], weight: 1.35 },
];

export const FIELD_EDGES: Array<[string, string]> = [
  ['intent', 'product-truth'], ['product-truth', 'routing'], ['routing', 'graph'], ['graph', 'type'],
  ['graph', 'motion'], ['graph', 'space'], ['routing', 'source'], ['source', 'synthesis'], ['synthesis', 'evidence'],
  ['evidence', 'critic'], ['unknown', 'critic'], ['critic', 'adequacy'], ['adequacy', 'routing'], ['space', 'verify'],
  ['motion', 'verify'], ['type', 'verify'], ['verify', 'release'], ['evidence', 'release'], ['critic', 'release'],
];

export type FieldStage = 'seed' | 'relation' | 'architecture' | 'routing' | 'synthesis' | 'climax' | 'resolution';

const RESOLUTION_REPRESENTATIVE_IDS = ['product-truth', 'motion', 'source', 'routing', 'evidence', 'critic', 'release'] as const;
const FIELD_ENVELOPE_KEYS: Array<[number, number]> = [
  [0, 0.18],
  [0.08, 0.30],
  [0.20, 0.58],
  [0.50, 0.92],
  [0.65, 1.16],
  [0.78, 1.42],
  [0.84, 1.62],
  [0.90, 1.34],
  [1, 0.58],
];

function clamp01(value: number) {
  return Math.min(1, Math.max(0, Number.isFinite(value) ? value : 0));
}

export function getFieldStage(progress: number): FieldStage {
  const p = clamp01(progress);
  if (p < 0.08) return 'seed';
  if (p < 0.20) return 'relation';
  if (p < 0.50) return 'architecture';
  if (p < 0.65) return 'routing';
  if (p < 0.78) return 'synthesis';
  if (p < 0.90) return 'climax';
  return 'resolution';
}

export function visibleFieldNodes(progress: number) {
  const stage = getFieldStage(progress);
  if (stage === 'resolution') {
    return RESOLUTION_REPRESENTATIVE_IDS.map((id) => FIELD_NODES.find((node) => node.id === id)!).filter(Boolean);
  }
  const countByStage: Partial<Record<FieldStage, number>> = {
    seed: 1,
    relation: 3,
    architecture: 8,
    routing: 11,
    synthesis: 14,
    climax: FIELD_NODES.length,
  };
  return FIELD_NODES.slice(0, countByStage[stage] ?? FIELD_NODES.length);
}

export function fieldEnvelope(progress: number) {
  const p = clamp01(progress);
  if (p <= FIELD_ENVELOPE_KEYS[0][0]) return FIELD_ENVELOPE_KEYS[0][1];
  for (let index = 1; index < FIELD_ENVELOPE_KEYS.length; index += 1) {
    const [x1, y1] = FIELD_ENVELOPE_KEYS[index];
    const [x0, y0] = FIELD_ENVELOPE_KEYS[index - 1];
    if (p <= x1) {
      const t = (p - x0) / Math.max(0.0001, x1 - x0);
      const eased = t * t * (3 - 2 * t);
      return y0 + (y1 - y0) * eased;
    }
  }
  return FIELD_ENVELOPE_KEYS.at(-1)![1];
}
