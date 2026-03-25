import { test, expect } from '@playwright/test';

// Returns how far left and right a bounding box is from the viewport edges
async function getMargins(page: import('@playwright/test').Page, selector: string) {
  return page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) throw new Error(`Element not found: ${sel}`);
    const rect = el.getBoundingClientRect();
    const viewportWidth = document.documentElement.clientWidth;
    return {
      left: Math.round(rect.left),
      right: Math.round(viewportWidth - rect.right),
    };
  }, selector);
}

// Centered = left margin ≈ right margin, within 20px
function expectCentered(margins: { left: number; right: number }, label: string) {
  const diff = Math.abs(margins.left - margins.right);
  expect(diff, `${label}: left=${margins.left} right=${margins.right}, diff=${diff}`).toBeLessThanOrEqual(20);
}

test('home page inner content is centered', async ({ page }) => {
  await page.goto('/');
  const margins = await getMargins(page, '.home-inner');
  expectCentered(margins, 'home .home-inner');
});

test('blog index inner content is centered', async ({ page }) => {
  await page.goto('/blog');
  const margins = await getMargins(page, '.blog-inner');
  expectCentered(margins, 'blog index .blog-inner');
});

test('blog post is centered on wide screen', async ({ page }) => {
  await page.goto('/blog/01-heap-overflow-linux');
  const dimensions = await page.evaluate(() => {
    const post = document.querySelector('article.post') as HTMLElement;
    if (!post) throw new Error('article.post not found');
    const vw = document.documentElement.clientWidth;
    const rect = post.getBoundingClientRect();
    return {
      viewportWidth: vw,
      postWidth: Math.round(rect.width),
      postLeft: Math.round(rect.left),
      postRight: Math.round(vw - rect.right),
    };
  });

  // Post wrapper should NOT fill more than 85% of a 1440px viewport
  // Bug: 1400px / 1440px ≈ 97% — FAILS
  // Fix: calc(...) ≈ 1130px / 1440px ≈ 78% — PASSES
  expect(
    dimensions.postWidth / dimensions.viewportWidth,
    `Post fills ${((dimensions.postWidth / dimensions.viewportWidth) * 100).toFixed(1)}% of viewport — should be ≤85%`
  ).toBeLessThanOrEqual(0.85);

  // Also verify it remains horizontally centered
  const diff = Math.abs(dimensions.postLeft - dimensions.postRight);
  expect(diff, `Post left=${dimensions.postLeft} right=${dimensions.postRight}`).toBeLessThanOrEqual(20);
});

test('toc is visible immediately on page load (no fade delay)', async ({ page }) => {
  await page.goto('/blog/01-heap-overflow-linux');
  // Check computed opacity immediately — no waiting for fonts/animations
  const opacity = await page.evaluate(() => {
    const toc = document.getElementById('toc');
    if (!toc) throw new Error('#toc not found');
    return parseFloat(getComputedStyle(toc).opacity);
  });
  expect(opacity, `#toc opacity should be 1 immediately, got ${opacity}`).toBe(1);
});

test('search results support arrow key navigation', async ({ page }) => {
  await page.goto('/');
  // Open search
  await page.keyboard.press('/');
  await page.waitForSelector('#search-overlay:not([hidden])');
  // Type something that returns results
  await page.fill('#search-input', 'heap');
  await page.waitForSelector('.sr-card');
  // Press ArrowDown — first card should become active
  await page.keyboard.press('ArrowDown');
  const activeCards = await page.locator('.sr-card--active').count();
  expect(activeCards, 'one card should be highlighted after ArrowDown').toBe(1);
  // Confirm the active card has a navigable href
  const href = await page.locator('.sr-card--active .sr-title a').getAttribute('href');
  expect(href).toBeTruthy();
});
