import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. This lab is a tabbed single-page app: only the active
 * <section role="tabpanel"> is visible; the rest carry [hidden], as do most
 * async result regions. Axe skips hidden content, so before every scan we
 * reveal ALL panels, un-hide every [hidden] region, expand any <details>,
 * neutralize animations, and drive the live demos so dynamically-injected
 * output is scanned too. Scans run in both dark (default) and light themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function revealEverything(page: Page): Promise<void> {
  // Kill animations/transitions so nothing is mid-fade when axe reads colors.
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}`,
  });

  await page.evaluate(() => {
    // Activate every tab panel: mark selected, drop the `hidden` + `active` gate.
    document.querySelectorAll<HTMLElement>('[role="tabpanel"]').forEach((p) => {
      p.hidden = false;
      p.removeAttribute('hidden');
      p.classList.add('active');
    });
    document.querySelectorAll<HTMLElement>('.tab-btn').forEach((t) => {
      t.setAttribute('aria-selected', 'true');
      t.removeAttribute('tabindex');
    });
    // Un-hide every hidden result/output region across all panels.
    document.querySelectorAll<HTMLElement>('[hidden]').forEach((el) => {
      el.hidden = false;
      el.removeAttribute('hidden');
    });
    // Expand any native disclosure widgets.
    document.querySelectorAll('details').forEach((d) => {
      (d as HTMLDetailsElement).open = true;
    });
    // Enable disabled demo buttons so they can be driven.
    document
      .querySelectorAll<HTMLButtonElement>('button[disabled]')
      .forEach((b) => (b.disabled = false));
  });
}

async function driveDemos(page: Page): Promise<void> {
  // Fire the primary demo actions to inject the result markup axe should see.
  // Keep it resilient: click if present, ignore if a run errors on fake keys.
  const ids = [
    '#tb-gen-small',
    '#tb-encrypt',
    '#tb-decrypt',
    '#tb-determinism',
    '#det-run',
    '#oaep-gen-2048',
    '#oaep-encrypt-2048',
    '#oaep-randomize',
    '#pss-gen',
    '#pss-sign',
    '#pss-verify-ok',
    '#pss-verify-tampered',
    '#cfg-vulnerable',
    '#cfg-safe',
    '#hastad-setup',
  ];
  for (const id of ids) {
    const el = page.locator(id).first();
    if (await el.count()) {
      await el.click({ trial: false, timeout: 2000 }).catch(() => {});
    }
  }
  // Let async handlers settle, then reveal anything they un-hid/added.
  await page.waitForTimeout(400);
  await revealEverything(page);
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await page.waitForSelector('#main-content');
  await revealEverything(page);
  await driveDemos(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.waitForSelector('#main-content');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealEverything(page);
  await driveDemos(page);
  await scan(page);
});
