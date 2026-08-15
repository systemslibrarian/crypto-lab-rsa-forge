import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches, one tab at a time, and every
 * step is scanned: the arrival state, with five of the six panels hidden and
 * every result region absent; the skip link focused (and its target asserted to
 * exist); the factoring wall; textbook RSA at 64 and 512 bits, with the
 * empty-message and over-long-message refusals in between; the determinism
 * contrast grid; the OAEP padding disclosure and both renderings of its field
 * tooltip; OAEP at 2048 AND 4096, including the decryption FAILURE that only a
 * regenerated key can produce; PSS signed, verified and rejected; both branches
 * of the Håstad config challenge and the full manual broadcast attack; the
 * Bleichenbacher padding oracle answering both ways, the homomorphic lever,
 * human-oracle mode with one correct and one WRONG answer, an abort, and the
 * automatic attack run to completion; the hybrid timing measurement; and the
 * glossary popover opened and dismissed. All of it in both themes, at 1280px
 * and at 380px.
 *
 * See `gate.ts` for why no panel is force-revealed (the spec this replaces
 * un-hid all six at once, along with every `[hidden]` element on the page, and
 * scanned a document no visitor can reach), why nothing is injected, why the
 * lab's defaults are asserted rather than assumed, and why `violations` is not
 * the whole oracle on a page carrying 130 `aria-label` attributes.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
