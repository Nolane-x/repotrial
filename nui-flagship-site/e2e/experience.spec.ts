import { expect, test } from '@playwright/test';

const shots = [
  ['00-silence', 0],
  ['35-architecture', 0.35],
  ['58-motion', 0.58],
  ['84-climax', 0.84],
  ['98-resolution', 0.98],
] as const;

test('renders the complete semantic story and captures scroll evidence', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('INTELLIGENCE');
  await expect(page.locator('main')).toBeVisible();
  await expect(page.locator('[data-beat]')).toHaveCount(8);
  await expect(page.getByRole('navigation')).toBeVisible();

  for (const [name, progress] of shots) {
    await page.evaluate((p) => window.scrollTo({ top: (document.documentElement.scrollHeight - innerHeight) * p, behavior: 'instant' }), progress);
    await page.waitForTimeout(350);
    await page.screenshot({ path: `test-results/evidence/desktop-${name}.png`, fullPage: false });
  }
});

test('preserves semantic progression under reduced motion', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/');
  await expect(page.locator('html')).toHaveAttribute('data-motion', 'reduce');
  await expect(page.locator('[data-beat="climax"]')).toContainText(/architecture|system|intelligence/i);
  await page.evaluate(() => window.scrollTo({ top: document.documentElement.scrollHeight * 0.84, behavior: 'instant' }));
  await page.waitForTimeout(200);
  await page.screenshot({ path: 'test-results/evidence/reduced-motion-climax.png' });
});

test('mobile keeps the authored story without horizontal overflow', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  await page.evaluate(() => window.scrollTo({ top: document.documentElement.scrollHeight * 0.78, behavior: 'instant' }));
  await page.waitForTimeout(250);
  await page.screenshot({ path: 'test-results/evidence/mobile-world-opens.png' });
});
