export type BeatId =
  | 'silence'
  | 'awakening'
  | 'architecture'
  | 'scale-break'
  | 'motion'
  | 'world-opens'
  | 'climax'
  | 'resolution';

export type ExperienceBeat = {
  id: BeatId;
  index: number;
  start: number;
  end: number;
  eyebrow: string;
  title: string;
  body: string;
  intent: string;
};

export const EXPERIENCE_BEATS: ExperienceBeat[] = [
  {
    id: 'silence', index: 1, start: 0, end: 0.08, eyebrow: 'NOLANE / UI INTELLIGENCE',
    title: 'Intelligence is not a model. It is a system.',
    body: 'One seed. Almost no interface. The experience begins before the architecture is explained.',
    intent: 'quiet authority',
  },
  {
    id: 'awakening', index: 2, start: 0.08, end: 0.20, eyebrow: '01 / AWAKENING',
    title: 'A decision becomes a relation.',
    body: 'The field does not decorate the page. It exposes how intent becomes routes, evidence, craft and critique.',
    intent: 'discovery',
  },
  {
    id: 'architecture', index: 3, start: 0.20, end: 0.35, eyebrow: '02 / COGNITIVE ARCHITECTURE',
    title: 'Specialists, coordinated as one mind.',
    body: 'Product truth, visual craft, research, routing, evidence, critics and verification occupy distinct territories — connected, not collapsed.',
    intent: 'scope',
  },
  {
    id: 'scale-break', index: 4, start: 0.35, end: 0.50, eyebrow: '03 / SCALE BREAK',
    title: 'The visible layer was only the entrance.',
    body: 'A compressed system releases into a deeper field. What looked like a set of skills becomes an operating architecture.',
    intent: 'magnitude',
  },
  {
    id: 'motion', index: 5, start: 0.50, end: 0.65, eyebrow: '04 / INTELLIGENCE IN MOTION',
    title: 'Routes can branch. Critics can send them back.',
    body: 'Motion carries causal meaning: propagation, uncertainty, failure, correction and resolution. Nothing moves just to prove that it can.',
    intent: 'causality',
  },
  {
    id: 'world-opens', index: 6, start: 0.65, end: 0.78, eyebrow: '05 / WORLD OPENS',
    title: 'The page gives way to the system.',
    body: 'Typography, depth and computation stop behaving like separate layers. The viewport becomes a single authored environment.',
    intent: 'immersion',
  },
  {
    id: 'climax', index: 7, start: 0.78, end: 0.90, eyebrow: '06 / ONE ARCHITECTURE',
    title: 'Every specialist. One intelligence architecture.',
    body: 'The full system resolves at once: product reasoning, craft, sources, routing, evidence, criticism and verification working in concert.',
    intent: 'awe',
  },
  {
    id: 'resolution', index: 8, start: 0.90, end: 1, eyebrow: '07 / RESOLUTION',
    title: 'Build intelligence, not interfaces.',
    body: 'Complexity collapses into a clear proposition. The final moment is quieter because the journey already carried the proof.',
    intent: 'resolve',
  },
];

const ENERGY_POINTS: Array<[number, number]> = [
  [0, 10], [0.08, 16], [0.20, 27], [0.35, 43], [0.50, 58],
  [0.65, 72], [0.78, 86], [0.84, 100], [1, 45],
];

export function clamp01(value: number) {
  return Math.min(1, Math.max(0, Number.isFinite(value) ? value : 0));
}

export function getExperienceState(progress: number) {
  const p = clamp01(progress);
  const beat = EXPERIENCE_BEATS.find((candidate) => p < candidate.end) ?? EXPERIENCE_BEATS.at(-1)!;
  const span = Math.max(0.0001, beat.end - beat.start);
  return { beat, localProgress: clamp01((p - beat.start) / span), progress: p };
}

export function energyAt(progress: number) {
  const p = clamp01(progress);
  if (p === 0) return ENERGY_POINTS[0][1];
  if (p === 1) return ENERGY_POINTS.at(-1)![1];
  for (let i = 1; i < ENERGY_POINTS.length; i += 1) {
    const [x1, y1] = ENERGY_POINTS[i];
    const [x0, y0] = ENERGY_POINTS[i - 1];
    if (p <= x1) {
      const t = (p - x0) / (x1 - x0);
      return y0 + (y1 - y0) * t;
    }
  }
  return 45;
}
