import { test, expect } from '@playwright/test';

test('toc top aligns with first prose h2', async ({ page }) => {
  await page.setViewportSize({ width: 1300, height: 900 });
  await page.goto('/blog/01-heap-overflow-linux');
  await page.waitForLoadState('load');

  const h2Top = await page.locator('.prose h2').first().evaluate((el) => {
    return el.getBoundingClientRect().top;
  });

  const tocTop = await page.locator('#toc').evaluate((el) => {
    return el.getBoundingClientRect().top;
  });

  // Allow ±4px tolerance for rounding/border
  expect(Math.abs(tocTop - h2Top)).toBeLessThanOrEqual(4);
});
