# NUI Flagship M2 Cinematic Depth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Evolve the M1 Living Intelligence website into a chapter-authored cinematic experience with deterministic scene state, semantic signal flow, domain orbits, depth portals, stronger shader material evolution, a single cognitive-cathedral climax, and a seven-domain Nolane resolution sigil.

**Architecture:** Raw scroll progress is converted once into a deterministic `CinematicSceneState`. All WebGL mechanisms consume that state so camera, portal, orbit, signal, core, and resolution systems cannot drift independently. Existing semantic DOM remains authoritative and readable without WebGL; capability and reduced-motion profiles alter density/movement but never remove chapters or domains.

**Tech Stack:** Next.js 16, React, TypeScript, React Three Fiber, Drei, Three.js, GSAP ScrollTrigger, Motion, custom GLSL, Vitest, Playwright, GitHub Actions.

## Global Constraints

- `Nolane-UI-Intelligence` remains read-only; implementation stays in `Nolane-x/repotrial` branch `build/nui-flagship-ci`.
- No audio, scroll hijacking, video assets, external 3D models, backend, CMS, or heavy post-processing dependency stack.
- Lower capability tiers may reduce geometry/pulse density but may not remove a semantic domain or story beat.
- Reduced motion must disable large camera travel and continuous ambient rotation while preserving complete semantic scene state and copy opacity >= 0.95.
- Completion requires green unit tests, production build, green Playwright gates, and manual review of CI screenshots.

---

### Task 1: Deterministic cinematic scene state

**Files:**
- Create: `nui-flagship-site/lib/scene-state.ts`
- Modify: `nui-flagship-site/tests/contracts.test.ts`

**Interfaces:**
- Consumes: `getExperienceState(progress)`, `getFieldStage(progress)`.
- Produces: `getCinematicSceneState(progress, reducedMotion): CinematicSceneState`, `cameraPoseAt(progress, reducedMotion): CameraPose`, `portalIntensityAt(progress): number`.

- [ ] **Step 1: Write failing deterministic scene tests**

Add tests asserting:

```ts
const silence = getCinematicSceneState(0.03, false);
expect(silence.mode).toBe('seed');
expect(silence.portal).toBeLessThan(0.05);

const scaleBreak = getCinematicSceneState(0.43, false);
expect(scaleBreak.mode).toBe('portal');
expect(scaleBreak.portal).toBeGreaterThan(0.55);

const climax = getCinematicSceneState(0.84, false);
expect(climax.mode).toBe('cathedral');
expect(climax.orbit).toBeGreaterThan(0.9);
expect(climax.signal).toBeGreaterThan(0.85);

const resolved = getCinematicSceneState(0.98, false);
expect(resolved.mode).toBe('sigil');
expect(resolved.portal).toBeLessThan(0.1);
expect(resolved.envelope).toBeLessThan(climax.envelope);

const reduced = cameraPoseAt(0.84, true);
expect(reduced.position).toEqual([0, 0, 9.4]);
expect(reduced.lookAt).toEqual([0, 0, 0]);
```

- [ ] **Step 2: Push RED commit and verify CI fails because scene-state exports do not exist**

Expected Vitest failure: module/export resolution for `scene-state`.

- [ ] **Step 3: Implement `scene-state.ts`**

Define:

```ts
export type CinematicMode = 'seed' | 'relation' | 'territories' | 'portal' | 'signals' | 'environment' | 'cathedral' | 'sigil';
export type CameraPose = { position: [number, number, number]; lookAt: [number, number, number]; fov: number };
export type CinematicSceneState = {
  mode: CinematicMode;
  envelope: number;
  core: number;
  orbit: number;
  portal: number;
  signal: number;
  atmosphere: number;
  sigil: number;
  camera: CameraPose;
};
```

Use piecewise smooth interpolation. Portal must peak across scale-break/world-open and decline before resolution. `cameraPoseAt(..., true)` returns the fixed neutral camera.

- [ ] **Step 4: Run CI until unit contracts and production build pass**

- [ ] **Step 5: Commit**

Commit message: `feat: add deterministic cinematic scene state`.

---

### Task 2: Semantic signal-flow model and seven-domain resolution geometry

**Files:**
- Modify: `nui-flagship-site/lib/field-model.ts`
- Modify: `nui-flagship-site/tests/contracts.test.ts`

**Interfaces:**
- Produces: `SIGNAL_ROUTES`, `getSignalRoute(index)`, `resolutionSigilNodes()`.
- `SIGNAL_ROUTES` entries must reference only node ids that exist in `FIELD_NODES` and edges that exist in `FIELD_EDGES`.

- [ ] **Step 1: Write failing semantic tests**

```ts
expect(SIGNAL_ROUTES.length).toBeGreaterThanOrEqual(6);
for (const route of SIGNAL_ROUTES) {
  expect(route.length).toBeGreaterThanOrEqual(2);
  for (let i = 1; i < route.length; i++) {
    const pair = [route[i - 1], route[i]];
    const reverse = [route[i], route[i - 1]];
    expect(FIELD_EDGES.some((edge) => edge.join('|') === pair.join('|') || edge.join('|') === reverse.join('|'))).toBe(true);
  }
}
const sigil = resolutionSigilNodes();
expect(new Set(sigil.map((node) => node.domain)).size).toBe(7);
```

- [ ] **Step 2: Push RED and verify route/sigil exports are missing**

- [ ] **Step 3: Implement valid routes and deterministic sigil positions**

`resolutionSigilNodes()` returns seven representatives with a `sigilPosition` arranged around a compact heptagonal form, preserving one representative for every domain.

- [ ] **Step 4: Run unit contracts**

- [ ] **Step 5: Commit**

Commit message: `feat: model semantic signal routes and resolution sigil`.

---

### Task 3: Split and upgrade WebGL scene mechanisms

**Files:**
- Create: `nui-flagship-site/components/field/SignalFlow.tsx`
- Create: `nui-flagship-site/components/field/DomainOrbits.tsx`
- Create: `nui-flagship-site/components/field/PortalField.tsx`
- Create: `nui-flagship-site/components/field/ResolutionSigil.tsx`
- Modify: `nui-flagship-site/components/field/IntelligenceField.tsx`

**Interfaces:**
- Each component consumes `scene: CinematicSceneState` plus `tier` and `reducedMotion` only when needed.
- `SignalFlow` consumes `FIELD_NODES` and `SIGNAL_ROUTES`; pulses travel on real route segments.
- `DomainOrbits` renders seven domain-grouped orbit rings.
- `PortalField` renders nested perspective rings only when `scene.portal > 0.02`.
- `ResolutionSigil` blends representative nodes toward deterministic sigil positions when `scene.sigil > 0`.

- [ ] **Step 1: Add browser contract markers before implementation**

Render hidden/nonvisual state markers from the scene root:

```tsx
<group userData={{ cinematicMode: scene.mode }} />
```

and expose DOM attributes from the parent experience root:

```tsx
<div data-cinematic-mode={scene.mode} data-cinematic-portal={scene.portal.toFixed(2)} ...>
```

Update Playwright to require `portal` for Scale Break, `signals` for Motion, `cathedral` for Climax, and `sigil` for Resolution.

- [ ] **Step 2: Push RED browser contract commit**

Expected failure: missing `data-cinematic-mode` values.

- [ ] **Step 3: Implement `DomainOrbits`**

Use `THREE.TorusGeometry` or line circles with one ring per domain. Scale/opacity is driven by `scene.orbit`; reduced motion freezes rotation.

- [ ] **Step 4: Implement `PortalField`**

Render 8/6/3 rings for high/medium/low tiers. Rings use additive line material, depth offsets, and scene-driven scale. No camera-facing flashing.

- [ ] **Step 5: Implement `SignalFlow`**

Use small additive spheres or point sprites. For each route, compute segment interpolation from `clock.elapsedTime`, map signal position onto valid node positions, and reverse critic/recovery route phases where defined. Low tier uses fewer active routes but still demonstrates causal flow.

- [ ] **Step 6: Implement `ResolutionSigil`**

Blend seven representatives from their field coordinates into compact sigil coordinates. At full resolution, the geometry must visibly contract.

- [ ] **Step 7: Refactor `IntelligenceField.tsx` to compose the mechanisms**

Keep `Canvas` ownership and base lighting in `IntelligenceField`. Move mechanism-specific logic out so each file has one responsibility.

- [ ] **Step 8: Run unit/build/browser gates**

- [ ] **Step 9: Commit**

Commit message: `feat: add semantic orbits signals portals and sigil`.

---

### Task 4: Core shader material evolution and camera choreography

**Files:**
- Create: `nui-flagship-site/components/field/IntelligenceCore.tsx`
- Modify: `nui-flagship-site/components/field/IntelligenceField.tsx`
- Modify: `nui-flagship-site/lib/scene-state.ts`

**Interfaces:**
- `IntelligenceCore({ scene, energy, reducedMotion })`.
- Camera uses `scene.camera.position`, `scene.camera.lookAt`, `scene.camera.fov` and `THREE.MathUtils.damp`.

- [ ] **Step 1: Add unit assertions for camera peak/recede and fixed reduced-motion pose**

```ts
expect(cameraPoseAt(0.84, false).position[2]).toBeLessThan(cameraPoseAt(0.15, false).position[2]);
expect(cameraPoseAt(0.98, false).position[2]).toBeGreaterThan(cameraPoseAt(0.84, false).position[2]);
expect(cameraPoseAt(0.84, true).position).toEqual([0, 0, 9.4]);
```

- [ ] **Step 2: Push RED if current camera state does not meet the authored poses**

- [ ] **Step 3: Extract `IntelligenceCore` and add nested shells**

Core layers:

```text
inner spectral seed -> membrane shell -> sparse wire/lattice shell -> climax spectral shell
```

Shader uniforms include `uTime`, `uEnergy`, `uCore`, `uCathedral`, `uSigil`. Deformation amplitude is capped and disabled under reduced motion.

- [ ] **Step 4: Replace raw progress camera logic with `scene.camera`**

Use a fixed `lookAt` interpolation target. Pointer parallax is capped at <= 0.3 world units and disabled for reduced motion.

- [ ] **Step 5: Run build and Playwright; inspect climax and resolution screenshots**

- [ ] **Step 6: Commit**

Commit message: `feat: deepen core material and camera choreography`.

---

### Task 5: Chapter-specific DOM visual mechanisms

**Files:**
- Modify: `nui-flagship-site/components/experience/ExperienceShell.tsx`
- Create: `nui-flagship-site/app/cinematic-m2.css`
- Modify: `nui-flagship-site/app/layout.tsx`

**Interfaces:**
- Experience root consumes `getCinematicSceneState` and exposes scene data attributes.
- DOM content remains semantically complete without Canvas.

- [ ] **Step 1: Add Playwright assertions for scene state and chapter-specific visual anchors**

Require:

```ts
await expect(page.locator('[data-beat="scale-break"] .depth-aperture-copy')).toBeVisible();
await expect(page.locator('[data-beat="motion"] .route-trace')).toBeVisible();
await expect(page.locator('[data-beat="climax"] .climax-statement')).toBeVisible();
await expect(page.locator('[data-beat="resolution"] .resolution-domain-mark')).toHaveCount(7);
```

- [ ] **Step 2: Push RED**

Expected failure on missing M2 anchors/data attributes.

- [ ] **Step 3: Add chapter-specific DOM mechanisms**

- Scale Break: depth-aperture copy layer around the `158` statement.
- Motion: animated semantic active route, not random shimmer.
- World Opens: depth-frame rails and stacked phrase masks.
- Climax: ghost-scale `ONE` plus sharper cathedral title relationship.
- Resolution: seven small domain marks visually paired to the compact CTA proposition.

- [ ] **Step 4: Add `cinematic-m2.css`**

Use CSS custom properties from scene state. Avoid new generic glass cards or gradient blobs. Mobile overrides must preserve distinct silhouettes.

- [ ] **Step 5: Run browser gates at desktop 1440×1000 and mobile 390×844**

- [ ] **Step 6: Commit**

Commit message: `feat: author M2 chapter-specific visual language`.

---

### Task 6: Expand CI rendered evidence and final quality gate

**Files:**
- Modify: `nui-flagship-site/e2e/experience.spec.ts`
- Modify: `.github/workflows/nui-flagship-ci.yml`
- Modify: `nui-flagship-site/README.md`

**Interfaces:**
- CI artifact `nui-flagship-m2` contains source ZIP, Playwright report, and all evidence screenshots.

- [ ] **Step 1: Expand screenshot evidence**

Capture:

```text
desktop-silence.png
desktop-architecture.png
desktop-scale-break.png
desktop-motion.png
desktop-world-opens.png
desktop-climax.png
desktop-resolution.png
mobile-world-opens.png
mobile-climax.png
reduced-motion-climax.png
```

- [ ] **Step 2: Add runtime and layout gates**

Retain `pageerror`/console error collection, mobile horizontal overflow check, reduced-motion opacity >= 0.95, and chapter/scene-state sync checks.

- [ ] **Step 3: Update CI package name to `NUI-Flagship-Website-M2.zip` and artifact name to `nui-flagship-m2`**

- [ ] **Step 4: Push and require complete green workflow**

Expected final evidence:

```text
Vitest: all tests pass
Next production build: success
Playwright: all browser scenarios pass
Artifact upload: success
```

- [ ] **Step 5: Manually inspect CI screenshots**

Reject and iterate if:

- architecture and climax have similar spatial scale;
- portal reads as decorative circles rather than depth release;
- resolution remains visually as energetic as climax;
- mobile loses chapter identity;
- reduced-motion loses contrast/legibility.

- [ ] **Step 6: Download final green CI artifact, extract source ZIP and rendered-evidence ZIP, and persist the source ZIP to ChatGPT Library**

- [ ] **Step 7: Final commit state**

Record the final green commit SHA and workflow run ID in the delivery summary.
