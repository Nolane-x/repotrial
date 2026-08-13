const assert = require('node:assert/strict');
const fs = require('node:fs');
function read(path) { return fs.readFileSync(path, 'utf8'); }
for (const path of [
  'components/field/MorphingField.tsx',
  'components/field/LightRibbons.tsx',
  'components/field/EnvironmentalLattice.tsx',
  'components/field/FoldShells.tsx',
  'app/cinematic-m3.css',
  'app/cinematic-m3-depth.css',
  'app/cinematic-m3-flow.css',
  'app/cinematic-m3-climax.css',
]) assert.ok(fs.existsSync(path), `missing ${path}`);
const field = read('components/field/IntelligenceField.tsx');
for (const token of ['MorphingField', 'LightRibbons', 'EnvironmentalLattice', 'FoldShells']) assert.ok(field.includes(token), `IntelligenceField missing ${token}`);
const shell = read('components/experience/ExperienceShell.tsx');
for (const token of ['data-m3-morph','data-m3-fold','data-m3-light','data-m3-type-depth','data-m3-pulse','impossible-fold','m3-aperture-spine','m3-semantic-pulse','m3-world-horizon']) assert.ok(shell.includes(token), `ExperienceShell missing ${token}`);
const layout = read('app/layout.tsx');
assert.ok(layout.includes("./cinematic-m3.css"), 'M3 CSS must be imported');
const e2e = read('e2e/m3.spec.ts');
assert.ok(e2e.includes('M3 climax reaches the Impossible Fold'), 'M3 Playwright gate missing');
console.log('M3 source contract PASS');
