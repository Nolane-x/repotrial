# NUI Flagship Website M2 — Cinematic Depth Design

## Purpose

M2 evolves the existing Living Intelligence flagship from a coherent premium prototype into a more memorable, chapter-authored cinematic experience. The objective is not to increase animation count. The objective is to make every major beat feel materially different while preserving one continuous Nolane-specific intelligence system.

The NUI skill repository remains read-only design authority. All implementation work stays in `Nolane-x/repotrial` on the isolated `build/nui-flagship-ci` branch.

## Experiential Thesis

The site begins as a nearly silent seed, discovers relations, becomes an architecture, breaks scale, demonstrates causality, opens into a world, reaches one spatial climax, then resolves into a compact seven-domain Nolane signature.

The progression must feel like one object gaining dimensions rather than eight unrelated sections receiving different effects.

## Chosen Direction

### Recommended: Cinematic Chapter Identity

Each chapter receives one dominant spatial/visual mechanism derived from the same semantic graph. WebGL carries depth and causal motion; typography and layout carry hierarchy and restraint. No chapter may add an effect without a semantic or dramaturgical role.

Rejected alternatives:

- **Maximum procedural WebGL everywhere:** visually intense but likely to become a technology demo, weaken quiet fields, and increase mobile/performance risk.
- **Luxury editorial only:** improves sophistication but does not satisfy the requested escalating scroll spectacle.

## Chapter Mechanisms

### 1. Silence — Seed / Observation

- One glass-membrane intelligence core with a restrained spectral halo.
- Sparse star/dust field.
- Pointer response remains sub-degree and low amplitude.
- Hero typography stays dominant.
- No portal, orbit, or signal system yet.

### 2. Awakening — Relation / Duplication

- First semantic nodes materialize from the seed rather than fading independently.
- Thin filament relations emerge.
- The core shifts from opaque-matte to translucent/luminous.
- Subtle ripple rings express the first propagation event.

### 3. Cognitive Architecture — Territories / Orbits

- Seven NUI domains gain distinct orbital territories.
- Domain rings are semantic grouping devices, not decorative circles.
- Architecture rows in DOM remain the textual authority; WebGL echoes the same seven-domain model.
- Camera moves slightly off-axis to expose depth without creating vestibular travel.

### 4. Scale Break — Depth Portal

- A sequence of perspective rings/lattice apertures creates a genuine scale-release moment.
- The network passes through a compressed aperture and expands behind it.
- One short forward camera dolly occurs here; this is the first large camera event.
- No rapid rotation.

### 5. Intelligence in Motion — Causal Signals

- Signal particles travel along real `FIELD_EDGES`.
- Pulses may reverse direction around critic/recovery relationships.
- Different pulse phases visually distinguish propagation from correction.
- The route lifecycle DOM remains readable and controls the explanatory narrative.

### 6. World Opens — Environmental Field

- Portal/lattice transforms from an object in the page into an environmental depth frame.
- Background shader gains broader spatial gradients and topology traces.
- Typography appears embedded in the field through depth-aware masks/lighting, without harming legibility.
- Camera position widens laterally instead of simply zooming.

### 7. Climax — Cognitive Cathedral

- All seven domain territories are simultaneously visible.
- Multiple semantic rings align into a large structured spatial composition.
- The central core becomes a nested spectral shell rather than one amorphous blob.
- Signal activity, topology, light, scale, and typography peak together once.
- The climax must remain recognizably NUI even with the wordmark hidden.

### 8. Resolution — Seven-Domain Nolane Sigil

- Network contracts decisively.
- Exactly one representative from product, craft, research, routing, evidence, critic, and verification remains.
- Representatives converge into a stable compact sigil / heptagonal intelligence mark around the core.
- Motion energy drops; semantic completeness remains.
- CTA is deliberately quieter than the climax.

## Scene Architecture

The WebGL system is split into bounded modules:

- `scene-state.ts`: deterministic chapter-aware scene values and camera poses.
- `IntelligenceCore`: nested shader shells and material progression.
- `SemanticNetwork`: semantic nodes/edges and domain grouping.
- `SignalFlow`: pulses that travel along real semantic edges.
- `DomainOrbits`: seven-domain territorial rings.
- `PortalField`: scale-break/world-open depth geometry.
- `AmbientField`: low-cost procedural atmosphere.
- `ResolutionSigil`: final seven-domain convergence geometry.

Components receive derived scene state instead of individually interpreting raw scroll thresholds. This prevents visual systems from drifting out of sync.

## Camera Choreography

Camera motion is authored as deterministic poses interpolated by progress:

- Silence: centered, far, nearly static.
- Architecture: slight x/y offset and modest yaw.
- Scale Break: controlled forward dolly.
- Motion: small lateral track.
- World Opens: wider off-axis reveal.
- Climax: closest and most centered large-scale composition.
- Resolution: retreat and recenter.

Pointer parallax is additive and capped. Reduced-motion disables camera travel and continuous ambient rotation while preserving discrete semantic scene states.

## Shader / Material Evolution

The core uses a material progression rather than a single shader with only stronger opacity:

1. matte spectral seed,
2. translucent membrane,
3. layered lattice shell,
4. luminous refractive-like climax shell,
5. compact resolved sigil core.

Implementation should use custom GLSL and additive shell geometry rather than requiring a heavyweight post-processing pipeline in M2. This keeps CI/headless rendering predictable and limits dependency growth.

## Typography and DOM Visual Language

The existing large grotesk/editorial language remains. M2 adds controlled chapter-specific mechanisms:

- architecture: index rails / domain alignment;
- scale break: enormous outlined metric with depth cut;
- motion: route trace with traveling active-state line;
- world opens: stacked phrase with depth masks;
- climax: oversized ghost word + sharp foreground title;
- resolution: compact proposition and sigil relationship.

No split-letter animation may reduce copy accessibility or cause layout instability. DOM content remains complete without WebGL.

## Performance / Capability Tiers

Existing high/medium/low tiers remain mandatory.

- High: full pulse count, all portal rings, nested core shells, richer ambient topology.
- Medium: reduced signal/portal density, same semantic states.
- Low: static or low-frequency orbits, limited signals, no expensive continuous deformation.
- Reduced motion: no large camera travel or continuous rotation; semantic chapter progression and legible geometry remain.

No semantic domain or chapter is removed by a lower rendering tier.

## Testing Strategy

### Unit contracts

Add deterministic tests for:

- camera pose progression and climax/recede behavior;
- chapter scene modes;
- signal routes only using valid `FIELD_EDGES`;
- exactly seven distinct domains in resolution sigil;
- portal intensity peaking only in scale-break/world-open/climax window;
- reduced-motion scene profile disabling travel while retaining semantic state.

### Browser gates

Playwright must verify:

- scene `data-*` state matches visible chapter;
- no page/console errors;
- no horizontal overflow at mobile width;
- reduced-motion key copy opacity remains >= 0.95;
- screenshots for silence, architecture, scale-break, motion, world-opens, climax, resolution, mobile world-opens, reduced-motion climax.

### Aesthetic evidence review

CI screenshots are manually reviewed after every green implementation run. Completion requires visible escalation, one dominant climax, and visible contraction at resolution. A green build alone is insufficient.

## Non-Goals

M2 does not add audio, scroll hijacking, video assets, external 3D models, user accounts, backend services, CMS, or a large post-processing dependency stack.

## Success Criteria

M2 succeeds when:

1. each major chapter is recognizable from silhouette/geometry without reading its heading;
2. climax is visibly larger and richer than architecture/motion;
3. resolution is visibly calmer and more compact than climax;
4. signal motion communicates causal graph relationships rather than random particle movement;
5. mobile remains authored rather than merely clipped desktop;
6. reduced-motion remains complete and legible;
7. all CI contracts and browser evidence gates pass;
8. final source ZIP and rendered-evidence ZIP are produced from the last green CI run.
