export type CapabilityTier = 'high' | 'medium' | 'low';

export type CapabilityEvidence = {
  deviceMemory: number;
  hardwareConcurrency: number;
  dpr: number;
  reducedMotion: boolean;
};

export function chooseCapabilityTier(evidence: CapabilityEvidence): CapabilityTier {
  if (evidence.reducedMotion) return 'low';
  if (evidence.deviceMemory >= 12 && evidence.hardwareConcurrency >= 8 && evidence.dpr <= 2) return 'high';
  if (evidence.deviceMemory >= 4 && evidence.hardwareConcurrency >= 4) return 'medium';
  return 'low';
}

export function reducedMotionProfile() {
  return {
    continuousAmbient: false,
    cameraTravel: false,
    parallax: false,
    semanticStateProgression: true,
    discreteTransitions: true,
  } as const;
}

export const TIER_BUDGETS = {
  high: { particles: 1400, dpr: 1.8, lineOpacity: 0.48 },
  medium: { particles: 720, dpr: 1.35, lineOpacity: 0.36 },
  low: { particles: 240, dpr: 1, lineOpacity: 0.24 },
} as const;
