import { expect, test, type Page } from '@playwright/test';

async function enterBeat(page: Page, id: string, local = 0.45) {
  await page.evaluate(({ beatId, t }) => {
    const element = document.querySelector<HTMLElement>(`[data-beat="${beatId}"]`);
    if (!element) throw new Error(`missing beat ${beatId}`);
    const available = Math.max(0, element.offsetHeight - window.innerHeight);
    window.scrollTo({ top: element.offsetTop + available * t, behavior: 'instant' });
  }, { beatId: id, t: local });
  await page.waitForTimeout(650);
}

test('M3 exposes spatial metamorphosis channels and authored chapter anchors', async ({ page }) => {
  await page.goto('/');
  const root = page.locator('.experience-root');
  for (const attribute of ['data-m3-morph', 'data-m3-fold', 'data-m3-light', 'data-m3-type-depth', 'data-m3-pulse']) {
    await expect(root).toHaveAttribute(attribute, /^\d+\.\d{2}$/);
  }
  await expect(page.locator('.m3-depth-grid')).toBeVisible();
  await expect(page.locator('[data-beat="scale-break"] .m3-aperture-spine')).toBeVisible();
  await expect(page.locator('[data-beat="motion"] .m3-semantic-pulse')).toBeVisible();
  await expect(page.locator('[data-beat="world-opens"] .m3-world-horizon')).toBeVisible();
  await expect(page.locator('[data-beat="climax"] .impossible-fold')).toBeVisible();
  await expect(page.locator('[data-beat="resolution"] .m3-resolution-lock')).toBeVisible();
});

test('M3 climax reaches the Impossible Fold and produces rendered evidence', async ({ page }) => {
  await page.goto('/');
  await enterBeat(page, 'climax', 0.50);
  const root = page.locator('.experience-root');
  await expect(root).toHaveAttribute('data-cinematic-mode', 'cathedral');
  const fold = Number.parseFloat(await root.getAttribute('data-m3-fold') ?? '0');
  const light = Number.parseFloat(await root.getAttribute('data-m3-light') ?? '0');
  expect(fold).toBeGreaterThan(0.9);
  expect(light).toBeGreaterThan(0.8);
  await page.screenshot({ path: 'test-results/evidence/m3-climax.png', fullPage: false });
});

test('M3 resolution settles deformation before final evidence', async ({ page }) => {
  await page.goto('/');
  await enterBeat(page, 'resolution', 1);
  const root = page.locator('.experience-root');
  await expect(root).toHaveAttribute('data-cinematic-mode', 'sigil');
  await expect(root).toHaveAttribute('data-cinematic-sigil', /^(0\.9[5-9]|1\.00)$/, { timeout: 6_000 });
  await expect(root).toHaveAttribute('data-m3-fold', /^(0\.0[0-7])$/, { timeout: 6_000 });
  await page.screenshot({ path: 'test-results/evidence/m3-resolution.png', fullPage: false });
});

test('M3 reduced motion preserves the climax while clamping fold', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/');
  await enterBeat(page, 'climax', 0.5);
  const root = page.locator('.experience-root');
  expect(Number.parseFloat(await root.getAttribute('data-m3-fold') ?? '1')).toBeLessThanOrEqual(0.24);
  await expect(page.locator('.beat--climax .beat-copy')).toHaveCSS('opacity', '1');
  await page.screenshot({ path: 'test-results/evidence/m3-reduced-motion-climax.png', fullPage: false });
});
