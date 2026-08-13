# NUI Flagship Experiential Website — M1

A standalone CI-sandbox implementation of the **Living Intelligence** direction. This code intentionally lives outside `Nolane-UI-Intelligence`; that repository is read-only design/skill authority for this build.

## Stack

Next.js + TypeScript + React Three Fiber/Three.js + GSAP ScrollTrigger + Motion + custom GLSL.

## Run

```bash
npm install
npm test
npm run build
npx playwright install chromium
npm run test:e2e
```

## Evidence gates

- 8 semantic story beats exist in DOM independently of WebGL.
- One persistent Intelligence Field evolves from seed to architecture to resolution.
- Capability tiers reduce GPU density without deleting semantic content.
- `prefers-reduced-motion` removes large camera/ambient movement while keeping semantic progression.
- Playwright captures desktop, mobile and reduced-motion evidence at multiple scroll positions.

This milestone is an authored first implementation, not a claim that aesthetic adequacy is complete until rendered evidence has been reviewed.
