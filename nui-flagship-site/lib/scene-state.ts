import { fieldEnvelope } from './field-model';

export type CinematicMode =
  | 'seed'
  | 'relation'
  | 'territories'
  | 'portal'
  | 'signals'
  | 'environment'
  | 'cathedral'
  | 'sigil';

export type CameraPose = {
  position: [number, number, number];
  lookAt: [number, number, number];
  fov: number;
};

export type CinematicSceneState = {
  mode: CinematicMode;
  envelope: number;
  core: number;
  network: number;
  orbit: number;
  portal: number;
  signal: number;
  atmosphere: number;
  sigil: number;
  morph: number;
  fold: number;
  light: number;
  typeDepth: number;
  pulse: number;
  camera: CameraPose;
};

const CAMERA_KEYS: Array<[number, CameraPose]> = [
  [0, { position: [0, 0, 9.4], lookAt: [0, 0, 0], fov: 46 }],
  [0.20, { position: [-0.18, 0.08, 9.05], lookAt: [0.05, 0, 0], fov: 45.5 }],
  [0.35, { position: [-0.42, 0.12, 8.62], lookAt: [0.08, 0.02, 0], fov: 45 }],
  [0.50, { position: [0.18, -0.08, 7.72], lookAt: [0, 0, 0], fov: 44 }],
  [0.65, { position: [0.42, 0.14, 8.02], lookAt: [-0.08, 0, 0], fov: 44.5 }],
  [0.78, { position: [-0.52, 0.18, 7.42], lookAt: [0.08, 0, 0], fov: 43.5 }],
  [0.84, { position: [0, 0.04, 6.55], lookAt: [0, 0, 0], fov: 42.5 }],
  [0.90, { position: [0.12, 0.04, 7.15], lookAt: [0, 0, 0], fov: 43.5 }],
  [1, { position: [0, 0, 8.85], lookAt: [0, 0, 0], fov: 46 }],
];

const NEUTRAL_CAMERA: CameraPose = {
  position: [0, 0, 9.4],
  lookAt: [0, 0, 0],
  fov: 46,
};

function clamp01(value: number) {
  return Math.min(1, Math.max(0, Number.isFinite(value) ? value : 0));
}

function smoothstep(edge0: number, edge1: number, value: number) {
  const t = clamp01((value - edge0) / Math.max(0.0001, edge1 - edge0));
  return t * t * (3 - 2 * t);
}

function lerp(a: number, b: number, t: number) {
  return a + (b - a) * t;
}

function lerp3(a: [number, number, number], b: [number, number, number], t: number): [number, number, number] {
  return [lerp(a[0], b[0], t), lerp(a[1], b[1], t), lerp(a[2], b[2], t)];
}

export function cameraPoseAt(progress: number, reducedMotion: boolean): CameraPose {
  if (reducedMotion) return { ...NEUTRAL_CAMERA, position: [...NEUTRAL_CAMERA.position], lookAt: [...NEUTRAL_CAMERA.lookAt] };
  const p = clamp01(progress);
  for (let index = 1; index < CAMERA_KEYS.length; index += 1) {
    const [x1, pose1] = CAMERA_KEYS[index];
    const [x0, pose0] = CAMERA_KEYS[index - 1];
    if (p <= x1) {
      const raw = (p - x0) / Math.max(0.0001, x1 - x0);
      const t = raw * raw * (3 - 2 * raw);
      return {
        position: lerp3(pose0.position, pose1.position, t),
        lookAt: lerp3(pose0.lookAt, pose1.lookAt, t),
        fov: lerp(pose0.fov, pose1.fov, t),
      };
    }
  }
  const last = CAMERA_KEYS.at(-1)![1];
  return { ...last, position: [...last.position], lookAt: [...last.lookAt] };
}

export function portalIntensityAt(progress: number) {
  const p = clamp01(progress);
  const rise = smoothstep(0.34, 0.46, p);
  const fall = 1 - smoothstep(0.73, 0.90, p);
  return clamp01(rise * fall);
}

function modeAt(progress: number): CinematicMode {
  const p = clamp01(progress);
  if (p < 0.08) return 'seed';
  if (p < 0.20) return 'relation';
  if (p < 0.35) return 'territories';
  if (p < 0.50) return 'portal';
  if (p < 0.65) return 'signals';
  if (p < 0.78) return 'environment';
  if (p < 0.90) return 'cathedral';
  return 'sigil';
}

export function getCinematicSceneState(progress: number, reducedMotion: boolean): CinematicSceneState {
  const p = clamp01(progress);
  const sigil = smoothstep(0.90, 0.985, p);
  const orbitRise = smoothstep(0.17, 0.35, p);
  const signalRise = smoothstep(0.47, 0.59, p);
  const cathedral = smoothstep(0.74, 0.84, p) * (1 - smoothstep(0.90, 0.99, p));
  const networkRelease = smoothstep(0.895, 0.975, p);
  const network = clamp01(1 - networkRelease * 0.975);
  const orbit = clamp01(orbitRise * (1 - sigil * 0.90));
  const signal = clamp01(signalRise * (1 - sigil * 0.97));
  const atmosphereRaw = clamp01(0.14 + smoothstep(0.08, 0.78, p) * 0.62 + cathedral * 0.24);
  const atmosphere = clamp01(atmosphereRaw * (1 - sigil * 0.55));
  const release = 1 - smoothstep(0.895, 0.985, p);
  const morphBase =
    smoothstep(0.16, 0.32, p) * 0.20 +
    smoothstep(0.31, 0.49, p) * 0.44 +
    smoothstep(0.60, 0.78, p) * 0.36;
  const morph = clamp01(morphBase * release * (reducedMotion ? 0.58 : 1));
  const foldFull = clamp01(smoothstep(0.700, 0.845, p) * (1 - smoothstep(0.855, 0.975, p)));
  const fold = reducedMotion ? foldFull * 0.22 : foldFull;
  const lightRaw = clamp01(
    portalIntensityAt(p) * 0.34 +
    smoothstep(0.58, 0.80, p) * 0.26 +
    foldFull * 0.58
  );
  const light = clamp01(lightRaw * (1 - sigil * 0.94) * (reducedMotion ? 0.68 : 1));
  const typeDepthRaw = clamp01(smoothstep(0.28, 0.69, p) * 0.68 + foldFull * 0.20);
  const typeDepth = clamp01(typeDepthRaw * release * (reducedMotion ? 0.16 : 1));
  const pulseWindow = smoothstep(0.45, 0.58, p) * (1 - smoothstep(0.78, 0.94, p));
  const pulse = clamp01((pulseWindow * 0.92 + foldFull * 0.12) * release * (reducedMotion ? 0.34 : 1));

  return {
    mode: modeAt(p),
    envelope: fieldEnvelope(p),
    core: 0.16 + smoothstep(0.04, 0.82, p) * 0.84,
    network,
    orbit,
    portal: portalIntensityAt(p),
    signal,
    atmosphere,
    sigil,
    morph,
    fold,
    light,
    typeDepth,
    pulse,
    camera: cameraPoseAt(p, reducedMotion),
  };
}
