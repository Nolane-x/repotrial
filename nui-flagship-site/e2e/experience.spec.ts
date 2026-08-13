import { expect, test, type Page } from '@playwright/test';

const evidenceBeats = ['silence', 'architecture', 'motion', 'climax', 'resolution'] as const;

async function scrollIntoBeat(page: Page, id: string, local = 0.35) {
  await page.evaluate(({ beatId, t }) => {
    const element = document.querySelector<HTMLElement>(`[data-beat="${beatId}"]`);
    if (!element) throw new Error(`missing beat ${beatId}`);
    const available = Math.max(0, element.offsetHeight - window.innerHeight);
    window.scrollTo({ top: element.offsetTop + available * t, behavior: 'instant' });
  }, { beatId: id, t: local });
  await page.waitForTimeout(420);
}

test('renders the complete semantic story and captures authored beat evidence', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('INTELLIGENCE');
  await expect(page.locator('main')).toBeVisible();
  await expect(page.locator('[data-beat]')).toHaveCount(8);
  await expect(page.getByRole('navigation')).toBeVisible();

  for (const id of evidenceBeats) {
    await scrollIntoBeat(page, id);
    await page.screenshot({ path: `test-results/evidence/desktop-${id}.png`, fullPage: false });
  }
});

test('semantic state follows every materially visible story beat', async ({ page }) => {
  await page.goto('/');
  const cases = [
    ['architecture', 'scope'],
    ['scale-break', 'magnitude'],
    ['motion', 'causality'],
    ['world-opens', 'immersion'],
    ['climax', 'awe'],
    ['resolution', 'resolve'],
  ] as const;

  for (const [beat, intent] of cases) {
    await scrollIntoBeat(page, beat, 0.35);
    await expect(page.locator('.nav-state-title')).toHaveText(intent);
  }
});

test('preserves semantic progression under reduced motion', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/');
  await expect(page.locator('html')).toHaveAttribute('data-motion', 'reduce');
  await expect(page.locator('[data-beat="climax"]')).toContainText(/architecture|system|intelligence/i);
  await scrollIntoBeat(page, 'climax', 0.45);
  await page.screenshot({ path: 'test-results/evidence/reduced-motion-climax.png' });
});

test('mobile keeps the authored story without horizontal overflow', async ({ page }) => {
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
  await scrollIntoBeat(page, 'world-opens', 0.4);
  await page.screenshot({ path: 'test-results/evidence/mobile-world-opens.png' });
});
