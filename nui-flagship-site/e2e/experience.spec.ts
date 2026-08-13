import { expect, test, type Page } from '@playwright/test';

const evidenceBeats = [
  ['silence', 'quiet authority', 0.35],
  ['architecture', 'scope', 0.35],
  ['scale-break', 'magnitude', 0.45],
  ['motion', 'causality', 0.40],
  ['world-opens', 'immersion', 0.42],
  ['climax', 'awe', 0.48],
  ['resolution', 'resolve', 1.0],
] as const;

async function scrollIntoBeat(page: Page, id: string, local = 0.35) {
  await page.evaluate(({ beatId, t }) => {
    const element = document.querySelector<HTMLElement>(`[data-beat="${beatId}"]`);
    if (!element) throw new Error(`missing beat ${beatId}`);
    const available = Math.max(0, element.offsetHeight - window.innerHeight);
    window.scrollTo({ top: element.offsetTop + available * t, behavior: 'instant' });
  }, { beatId: id, t: local });
  await page.waitForTimeout(520);
}

test('renders the complete semantic story and captures M2 authored beat evidence', async ({ page }) => {
  test.setTimeout(75_000);
  const runtimeErrors: string[] = [];
  page.on('pageerror', (error) => runtimeErrors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') runtimeErrors.push(message.text());
  });

  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('INTELLIGENCE');
  await expect(page.locator('main')).toBeVisible();
  await expect(page.locator('[data-beat]')).toHaveCount(8);
  await expect(page.getByRole('navigation')).toBeVisible();

  for (const [id, intent, local] of evidenceBeats) {
    await scrollIntoBeat(page, id, local);
    await expect(page.locator('.nav-state-title')).toHaveText(intent);
    await page.screenshot({ path: `test-results/evidence/desktop-${id}.png`, fullPage: false });
  }

  expect(runtimeErrors).toEqual([]);
});

test('cinematic scene mode follows the materially visible chapter', async ({ page }) => {
  await page.goto('/');
  const root = page.locator('.experience-root');
  const cases = [
    ['architecture', 'territories'],
    ['scale-break', 'portal'],
    ['motion', 'signals'],
    ['world-opens', 'environment'],
    ['climax', 'cathedral'],
    ['resolution', 'sigil'],
  ] as const;

  for (const [beat, mode] of cases) {
    await scrollIntoBeat(page, beat, beat === 'resolution' ? 0.84 : 0.42);
    await expect(root).toHaveAttribute('data-cinematic-mode', mode);
  }
});

test('M2 chapters expose distinct authored visual anchors', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('[data-beat="scale-break"] .depth-aperture-copy')).toBeVisible();
  await expect(page.locator('[data-beat="motion"] .route-trace')).toBeVisible();
  await expect(page.locator('[data-beat="world-opens"] .world-depth-frame')).toBeVisible();
  await expect(page.locator('[data-beat="climax"] .climax-statement')).toBeVisible();
  await expect(page.locator('[data-beat="resolution"] .resolution-domain-mark')).toHaveCount(7);
});

test('preserves semantic progression and legibility under reduced motion', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/');
  await expect(page.locator('html')).toHaveAttribute('data-motion', 'reduce');
  await expect(page.locator('[data-beat="climax"]')).toContainText(/architecture|system|intelligence/i);
  await scrollIntoBeat(page, 'climax', 0.48);
  const opacity = await page.locator('.beat--climax .beat-copy').evaluate((element) => Number.parseFloat(getComputedStyle(element).opacity));
  expect(opacity).toBeGreaterThanOrEqual(0.95);
  await expect(page.locator('.experience-root')).toHaveAttribute('data-cinematic-mode', 'cathedral');
  await page.screenshot({ path: 'test-results/evidence/reduced-motion-climax.png' });
});

test('mobile keeps authored depth without horizontal overflow', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  const layout = await page.evaluate(() => {
    const viewport = document.documentElement.clientWidth;
    const offenders = [...document.querySelectorAll<HTMLElement>('body *')]
      .map((element) => {
        const rect = element.getBoundingClientRect();
        return { tag: element.tagName, className: element.className, text: element.textContent?.trim().slice(0, 42) ?? '', left: Math.round(rect.left), right: Math.round(rect.right) };
      })
      .filter((item) => item.right > viewport + 1 || item.left < -1)
      .slice(0, 8);
    return { overflow: document.documentElement.scrollWidth - viewport, offenders };
  });
  expect(layout, JSON.stringify(layout.offenders, null, 2)).toEqual({ overflow: 0, offenders: [] });

  await scrollIntoBeat(page, 'world-opens', 0.42);
  await page.screenshot({ path: 'test-results/evidence/mobile-world-opens.png' });
  await scrollIntoBeat(page, 'climax', 0.48);
  await page.screenshot({ path: 'test-results/evidence/mobile-climax.png' });
});
