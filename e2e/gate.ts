import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate on RSA Forge.
 *
 * The gate this replaces could not fail on almost anything this lab renders,
 * and every rule below is a correction of something it did.
 *
 *  1. IT BUILT A DOCUMENT NO VISITOR CAN REACH, AND SCANNED THAT.
 *     `revealEverything()` walked `[role="tabpanel"]` and set `hidden = false`
 *     plus `classList.add('active')` on ALL SIX panels, then cleared the
 *     `hidden` attribute from EVERY element on the page, opened every
 *     `<details>`, set `aria-selected="true"` on every tab at once, and
 *     re-enabled every `disabled` button. The result is six stacked panels, six
 *     simultaneously-selected tabs in one tablist, and roughly two dozen result
 *     cards showing their `—` placeholders for results nobody has run. No axe
 *     finding against that document describes the page a reader loads, and no
 *     clean result about it says anything about the page a reader loads. This
 *     gate never touches `hidden`, `open`, `disabled` or `aria-selected`: every
 *     panel is reached by clicking its tab, and every card by the button that
 *     reveals it.
 *
 *  2. IT SUPPRESSED MOTION BY INJECTION. `addStyleTag` pushed
 *     `animation:none!important; transition:none!important` into the page,
 *     which BYPASSES `@media (prefers-reduced-motion: reduce)` rather than
 *     exercising it. `boot` asks for the preference and asserts it took effect,
 *     so what is measured is the rendering a reader with that preference gets.
 *
 *  3. IT SWALLOWED EVERY INTERACTION. `driveDemos` clicked fifteen ids behind
 *     `if (await el.count())` and `.catch(() => {})`. A control that had moved,
 *     been renamed, or thrown was skipped in silence, and the scan that followed
 *     still reported green — for a page where the exhibit had not run. Nothing
 *     here is optional or caught: every click is followed by an assertion on the
 *     completion signal the code itself produces.
 *
 *  4. IT SCANNED ONCE, AT ONE VIEWPORT, AT THE END. Every state the drive built
 *     was overwritten before anything measured it, and the 380px column had
 *     never been scanned at all. This drive scans after every single step, in
 *     {dark, light} x {1280, 380}.
 *
 *  5. `violations` WAS THE WHOLE ORACLE, and on this page that leaves the
 *     largest defect class invisible: `index.html` carries 130 `aria-label`
 *     attributes, many on bare `<span>` and `<div>`, and an `aria-label` on a
 *     role-less element is PROHIBITED and silently discarded — axe files it
 *     under `incomplete`, never under `violations`. See `scan`.
 *
 *  6. IT HAD NO REFLOW ORACLE, AND COULD NOT HAVE HAD ONE. `body` carried
 *     `overflow-x: hidden`, which propagates to the viewport, so
 *     `scrollWidth === clientWidth` unconditionally. That declaration is now
 *     gone and `expectNoHorizontalOverflow` asks the question for real.
 */

/**
 * Every result region that ships behind the `hidden` attribute, in panel order.
 *
 * This is the list the gate this replaces cleared wholesale before its only
 * scan. Here it is used the other way round: to assert every one is genuinely
 * absent on arrival, so that each later reveal is a state the drive built
 * through the UI rather than one it asserted into existence.
 *
 * `#tb-factor-card` is deliberately NOT in this list: it carries the `hidden`
 * attribute in the markup but `initTextbookPanel()` reveals it during mount, so
 * it is visible at first paint and `boot` asserts that instead.
 */
export const HIDDEN_REGIONS = [
  // Panel 1 — Textbook RSA
  '#tb-params',
  '#tb-crypto-card',
  '#tb-factor-result',
  '#tb-encrypt-result',
  '#tb-decrypt-section',
  '#tb-determinism-result',
  '#det-contrast-grid',
  // Panel 2 — RSA-OAEP
  '#oaep-2048-timing',
  '#oaep-4096-timing',
  '#oaep-encrypt-card',
  '#oaep-encrypt-result',
  '#oaep-randomize-card',
  '#oaep-randomize-result',
  '#oaep-decrypt-card',
  '#oaep-decrypt-output',
  // Panel 3 — RSA-PSS
  '#pss-sign-section',
  '#pss-signature-result',
  '#pss-verify-card',
  '#pss-verify-output',
  // Panel 4 — Hastad
  '#cfg-result',
  '#hastad-recipients',
  '#hastad-broadcast-card',
  '#hastad-ciphertexts',
  '#hastad-attack-card',
  '#hastad-attack-steps',
  '#hastad-final-reveal',
  // Panel 5 — Bleichenbacher
  '#bb-setup-display',
  '#bb-oracle-card',
  '#bb-attack-card',
  '#bb-oracle-mode',
  '#bb-progress',
  '#bb-recovered',
  // Panel 6 — comparison
  '#hybrid-results',
  '#hybrid-takeaway',
] as const;

/** The five controls that ship DISABLED until a prerequisite has been run. */
export const LOCKED_CONTROLS = [
  '#oaep-encrypt-2048',
  '#oaep-encrypt-4096',
  '#oaep-decrypt-2048',
  '#oaep-decrypt-4096',
  '#bb-abort',
] as const;

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * `styles/main.css` declares `opacity` twice (`.btn:disabled` .5 and
 * `.stage-skipped`-style de-emphasis), neither of them zero, and its two
 * `@keyframes` are `spin` (transform only) and `pulse-reveal`. The second one
 * was checked specifically: it ENDS on `background: var(--c-safe-bg);
 * border-color: var(--c-safe)`, and its only user, `.byte-cell.just-revealed`,
 * always carries `.known` as well — which declares exactly those two values. So
 * cancelling the animation lands on the same rendering it would have animated
 * to, and the reduced-motion block (which clamps durations rather than setting
 * `animation: none`) strands nothing. This assertion is what makes that a
 * measurement rather than a reading.
 *
 * `aria-hidden` subtrees are excluded here, matching axe — but this page hides
 * four elements that carry real WORDS (`EASY`, `IMPOSSIBLE`, `THE LEVER`,
 * `→ scramble →`), so `scan` measures every `aria-hidden` subtree separately
 * with that exemption lifted. See `contrast.ts`.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * An explicit `role` on a `<ul>`/`<ol>` REPLACES its implicit `list` role and
 * orphans every `<li>` inside it (axe then fires `listitem` once per child).
 *
 * This is checked at RUNTIME because a role assigned as a JS property in an
 * element-creation helper is invisible to a markup grep. It is also checked
 * with a CHILD TEST rather than on the role alone, because the naive form is
 * wrong on this page: `<ul class="tab-list" role="tablist">` is the ARIA
 * Authoring Practices tab pattern and it is CORRECT — every `<li>` inside it
 * carries `role="none"`, so no list item is orphaned by the override. The
 * defect is a list whose role has been replaced while its `<li>` children were
 * left to be orphaned, so that is what this reports.
 */
async function expectListSemantics(page: Page, label: string): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role]', (els) =>
    els
      .filter((e) => e.getAttribute('role') !== 'list')
      .filter((e) =>
        Array.from(e.children).some(
          (c) =>
            c.tagName === 'LI' &&
            !['none', 'presentation'].includes(c.getAttribute('role') ?? '')
        )
      )
      .map(
        (e) =>
          `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] orphans ` +
          `${Array.from(e.children).filter((c) => c.tagName === 'LI' && !['none', 'presentation'].includes(c.getAttribute('role') ?? '')).length} <li> children`
      )
  );
  expect(
    broken,
    `an explicit role on a list deletes its list semantics, in state: ${label}`
  ).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * This page declares TWO `role="banner"` elements in its markup — the shared
 * `.cl-topbar` and its own `<header class="site-header" role="banner">`, which
 * sits at top level and is NOT scoped by any sectioning element. Nothing in the
 * static HTML resolves that; it is resolved at runtime by `dedupeBanner()` in
 * `index.html`, which rewrites the second one to `role="group"` on
 * DOMContentLoaded. Asserting the OUTCOME rather than either mechanism means a
 * change to the markup, to the script, or to the order they run in is caught.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. The gate it replaces did not ask for the
 * preference at all — it pushed `animation:none!important` in through
 * `addStyleTag`, which BYPASSES `@media (prefers-reduced-motion: reduce)`
 * instead of exercising it. Asking for the preference is the only way to
 * measure what a reader with it set actually sees.
 *
 * The theme is seeded through `localStorage` rather than by clicking the toggle,
 * which pins down a real failure mode: `index.html`'s anti-flash script reads
 * `localStorage.getItem('theme')` and the shared header's toggle writes
 * `localStorage.setItem('theme', ...)`. If those keys drift apart the theme
 * silently stops persisting, and this boot fails on `data-theme` rather than
 * quietly scanning dark twice.
 *
 * THE DEFAULTS ARE ASSERTED AT LENGTH, and on this page that is unusually
 * load-bearing, because the gate this replaces DESTROYED them: `revealEverything`
 * un-hid every `[role=tabpanel]`, cleared the `hidden` attribute from every
 * result region on the page, opened every `<details>`, and re-enabled every
 * disabled button — assembling a document no visitor can reach, with all six
 * panels stacked and twenty-odd empty result cards showing `—` placeholders,
 * and then scanned that. So this boot pins down the real arrival state instead:
 * exactly one panel visible, the other five `hidden`; the two things that DO
 * run on mount (the factoring wall's fresh ~40-bit target, and the 24-byte
 * OAEP avalanche block) present; and every other result region absent, every
 * `disabled` button disabled, every input at its shipped value.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);

  // ── The tab machinery: one panel visible, five hidden ───────────────────
  await expect(page.locator('#panel-1')).toBeVisible();
  await expect(page.locator('#tab-1')).toHaveAttribute('aria-selected', 'true');
  for (const n of [2, 3, 4, 5, 6]) {
    await expect(page.locator(`#panel-${n}`)).toBeHidden();
    await expect(page.locator(`#tab-${n}`)).toHaveAttribute('aria-selected', 'false');
  }

  // ── The two things that DO run on mount ─────────────────────────────────
  // `initTextbookPanel` generates a fresh ~40-bit semiprime and reveals the
  // factoring wall, so `#tb-factor-card` is `hidden` in the markup and visible
  // on screen. `initOaepHighLevel` fills the avalanche block with 24 bytes even
  // though its panel is hidden.
  await expect(page.locator('#tb-factor-card')).toBeVisible();
  await expect(page.locator('#tb-factor-n')).not.toHaveText('—');
  await expect(page.locator('#oaep-hl-block .oaep-hl-byte')).toHaveCount(24);
  await expect(page.locator('#oaep-hl-block .oaep-hl-byte.changed')).toHaveCount(0);

  // ── Everything else this lab generates ships ABSENT ─────────────────────
  for (const sel of HIDDEN_REGIONS) await expect(page.locator(sel)).toBeHidden();
  for (const sel of LOCKED_CONTROLS) await expect(page.locator(sel)).toBeDisabled();

  // ── Every shipped control default ───────────────────────────────────────
  await expect(page.locator('#tb-plaintext')).toHaveValue('');
  await expect(page.locator('#oaep-plaintext')).toHaveValue('Hello, RSA-OAEP!');
  await expect(page.locator('#pss-message')).toHaveValue(
    'This message is signed with RSA-PSS-SHA-256.'
  );
  await expect(page.locator('#hastad-message')).toHaveValue('Hello!');
  await expect(page.locator('#bb-oracle-input')).toHaveValue('');

  // The one disclosure on the page, shut, and the glossary popover unopened.
  await expect(page.locator('details.oaep-details')).toHaveCount(1);
  await expect(page.locator('details[open]')).toHaveCount(0);
  await expect(page.locator('#gloss-body')).toBeHidden();
  await expect(page.locator('.gloss[aria-expanded="true"]')).toHaveCount(0);

  // The oracle log starts empty — the gate this replaces never saw it populated
  // at all, and each entry it grows carries the one dynamically-created
  // `aria-label` on this page.
  await expect(page.locator('#bb-oracle-result .oracle-log-entry')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and until this
 * commit NOTHING on this page could have one: `body` carried
 * `overflow-x: hidden`, which PROPAGATES TO THE VIEWPORT, so
 * `documentElement.scrollWidth` could never exceed `clientWidth` and the
 * question was unanswerable rather than answered. That declaration is gone; this
 * is what replaces it.
 *
 * The shapes on this page that test it are the wide ones: the comparison table
 * and bar chart in panel 6, the 32-cell byte grids in the determinism contrast
 * and the Bleichenbacher recovery row, the OAEP and PSS padding diagrams, the
 * six-tab `.tab-list`, and every `.crypto-value` holding a 344-character Base64
 * ciphertext. Each is meant to reflow or to scroll inside its own
 * `overflow-x: auto` box; the assertion here is that none of them scrolls the
 * DOCUMENT.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. Every
    // Every `.crypto-value` and every `.table-wrap` on this page is one of those
    // decoys: a 344-character Base64 run inside its own `overflow-x: auto` box.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * This is a live question on this page rather than a formality: `styles/main.css`
 * has eight `overflow-x: auto` containers — the tab list, the comparison table,
 * the byte grids, the padding diagrams — and most of them hold no focusable
 * content of their own. Whether they actually overflow depends on the viewport
 * and on how much output the drive has generated, which is why this runs at
 * every driven state at both widths rather than once at first paint.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Anything made focusable must show WHERE the focus is (WCAG 2.4.7).
 *
 * This page makes twenty elements focusable FROM JAVASCRIPT rather than from
 * markup — `oaep.ts` and `pss.ts` each set `seg.tabIndex = 0` on all ten
 * `[data-oaep-field]` / `[data-pss-field]` divs of their padding diagrams — and
 * a source grep for `tabindex` finds none of them. Anything given a tab stop
 * needs a visible focus indicator (2.4.7), so every one of them is probed here
 * at runtime.
 *
 * PRIMING IS LOAD-BEARING. Chromium only matches `:focus-visible` on a
 * programmatic `focus()` when the last user interaction was via the KEYBOARD.
 * Without a real `page.keyboard.press('Tab')` first, every element probed here
 * reports no indicator and the check invents one phantom defect per region. So
 * the active element is blurred, one real Tab is pressed to put the browser in
 * keyboard modality, and only then is each region focused and measured.
 *
 * A NOTE ON PROVING THIS ONE BITES: deleting an author `:focus-visible` rule is
 * an INVALID mutation and leaves the check green, correctly — Chromium's own
 * ring takes over, and a UA-drawn indicator satisfies 2.4.7 as well as an
 * author-drawn one. `outline: none` is the mutation that is actually a defect,
 * because it suppresses the UA ring too. A mutation the user agent silently
 * repairs proves nothing.
 */
export async function expectFocusIndicators(page: Page, label: string): Promise<void> {
  // `:visible` is load-bearing. Five of this page's six panels carry the
  // `hidden` attribute at any moment, and each of them holds ten
  // `[data-oaep-field]` / `[data-pss-field]` divs that `tabIndex = 0` made
  // focusable, plus the panel itself. `focus()` on an element inside a `hidden`
  // subtree does nothing at all — the element never becomes `document.activeElement`
  // and `:focus-visible` cannot match — so probing them reported "priming
  // failed" for thirty-four elements in every state, none of which was a defect.
  const targets = await page.locator('[tabindex="0"]:visible').all();
  if (targets.length === 0) return;

  // Put Chromium into keyboard modality with a REAL key press.
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');

  // THE FOCUSED STYLE IS READ, AND NOTHING IS READ BEFORE IT. An earlier form of
  // this check read each element's unfocused style first and asserted that
  // focusing CHANGED it, which is the more obvious statement of the requirement
  // — and it does not work in Chromium. Once an element's computed style has
  // been read, a read taken after a pseudo-class change comes back PARTIALLY
  // refreshed: the element reports the new `outline-style` with the INITIAL
  // width and `currentColor`, for a rule that resolves correctly when the same
  // element is read for the first time while focused. Splitting the two reads
  // into separate `evaluate` round-trips did not help; only never taking the
  // first read does. Found and reproduced in isolation elsewhere in this sweep,
  // where it fabricated one phantom defect per focusable region in every state.
  const missing: string[] = [];
  for (const t of targets) {
    const info = await t.evaluate((el) => {
      (el as HTMLElement).focus();
      const cs = getComputedStyle(el);
      return {
        sel:
          el.tagName.toLowerCase() +
          (el.getAttribute('class') ? `.${el.getAttribute('class')!.trim().split(/\s+/).join('.')}` : ''),
        focusVisible: el.matches(':focus-visible'),
        outlineStyle: cs.outlineStyle,
        outlineWidth: parseFloat(cs.outlineWidth) || 0,
        outline: `${cs.outlineStyle} ${cs.outlineWidth} ${cs.outlineColor}`,
        shadow: cs.boxShadow,
      };
    });
    const paints =
      (info.outlineStyle !== 'none' && info.outlineWidth > 0) || info.shadow !== 'none';
    if (!info.focusVisible) {
      missing.push(`${info.sel}: focus() did not match :focus-visible (priming failed?)`);
    } else if (!paints) {
      missing.push(`${info.sel}: focused but paints no indicator (outline ${info.outline})`);
    }
  }
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  expect(missing, `focusable regions with no focus indicator in state: ${label}`).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * FAILS at the end via `reportCollected`, so a green collection run cannot be
 * mistaken for a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    record(String(e).slice(0, 6000));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a `::before`
 * glyph, because a pseudo-element is not an element and owns no text node.
 *
 * IT IS CALLED FROM `scan()`. In the reference gate this fleet was copied from,
 * it was reachable only from inside the scroller check, AFTER that function's
 * `if (!COLLECTING) return ...` guard — so in a strict run it never executed at
 * all, `nontext.ts` was dead code, and the baseline had been "captured" by a
 * check that had never looked. Calling it here means it runs at every driven
 * state in both themes at both widths.
 *
 * It ratchets rather than blocking: anything NOT in the baseline fails, anything
 * in the baseline that got WORSE fails, and (via `expectBaselineNotStale`)
 * anything in the baseline that has been FIXED fails until its entry is deleted.
 * That last rule is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Nine assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `expectNotBlank` — the reduced-motion end state.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those ratios
 *    arithmetically — which matters more here than in most labs, since every
 *    `.status`, `.verdict`, `.trapdoor__side` and `.flow-op__box` surface is an
 *    `rgba()` tint and every accent wash is a `color-mix(in oklab, ...)` that
 *    axe declines to resolve. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less element hides, a defect that never
 *    reaches the violations array at all and which the gate this replaces
 *    therefore could not have found. This page has that shape in bulk: 130
 *    `aria-label` attributes, many of them on bare `<span>` and `<div>`, plus
 *    one created from JavaScript on every Bleichenbacher oracle query
 *    (`attacks.ts` labels a role-less `<span>` `Conformant` /
 *    `Not conformant`).
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - every `aria-hidden` subtree, measured with that exemption LIFTED. SC 1.4.3
 *    is about what a reader SEES and `aria-hidden` changes only what a reader
 *    HEARS, so painted text inside one still has to clear 4.5:1 — and BOTH the
 *    axe rule and the arithmetic walk skip it. This page hides four elements
 *    that carry words (`EASY`, `IMPOSSIBLE`, `THE LEVER`, `→ scramble →`), each
 *    painted in a semantic ink on its own tint. See `contrast.ts`.
 *  - non-text contrast — SC 1.4.11, which axe has no rule for at all.
 *  - list semantics, focus indicators, keyboard reachability of scrolling
 *    regions (2.1.1), and reflow (1.4.10) — none of which axe covers either.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);

  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe therefore runs those
  // FOUR best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions; the chained form executes 4.
  //
  // Running the two sets separately and merging is the only way to have both.
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them — and this page
  // has exactly the shape they catch: two `role="banner"` headers in the markup
  // (deduped at runtime by a script), an `<aside class="cl-hero-why">` inside
  // the second one, and a second `<aside class="why-matters">` outside `<main>`.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  // Every `aria-hidden` subtree, with the accessibility-tree exemption lifted.
  const hidden = Array.from(
    new Set(
      formatContrastFailures(
        await auditContrast(page, '[aria-hidden="true"], [aria-hidden="true"] *', true)
      )
    )
  );
  softExpect(hidden, `contrast inside aria-hidden subtrees in state: ${label}`, []);

  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectListSemantics(page, label));
  await soft(() => expectFocusIndicators(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}


// ── The drive ───────────────────────────────────────────────────────────────

/** Switch panels the way a reader does — by clicking the tab — and assert it took. */
async function openPanel(page: Page, n: number): Promise<void> {
  await page.click(`#tab-${n}`);
  await expect(page.locator(`#tab-${n}`)).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator(`#panel-${n}`)).toBeVisible();
  for (const other of [1, 2, 3, 4, 5, 6]) {
    if (other !== n) await expect(page.locator(`#panel-${other}`)).toBeHidden();
  }
}

/**
 * Drive the lab through every state it renders, scanning each.
 *
 * Six things shape this drive:
 *
 *  - EVERY PANEL IS REACHED BY ITS TAB, one at a time, and the other five are
 *    asserted hidden each time. That is the whole difference between this and
 *    the gate it replaces, which un-hid all six at once.
 *
 *  - EVERY PREREQUISITE IS SCANNED BEFORE ITS UNLOCK. Panel 2 ships four
 *    controls `disabled` and Panel 5 ships one; each is asserted disabled, then
 *    the control that unlocks it is pressed, then it is asserted enabled — so
 *    the "before" rendering, which is what a reader meets, is measured too.
 *
 *  - EVERY ERROR AND EMPTY STATE THE UI CAN REACH. This lab reports its soft
 *    errors through `#aria-live` alone, which means they change no visible
 *    markup and a violations-only scan could never have distinguished them — but
 *    they are still real states with real live-region text, and three of them
 *    reach a rendered result: OAEP's `result-box-error` decrypt failure, PSS's
 *    `result-box-error` tampered verdict, and Håstad's `result-box-error`
 *    vulnerable-config verdict. All three are driven.
 *
 *  - BOTH BRANCHES OF EVERY FORK. `#cfg-vulnerable` and `#cfg-safe` write the
 *    same `#cfg-result` nodes with opposite classes; `#pss-verify-ok` and
 *    `#pss-verify-tampered` the same; OAEP runs at 2048 AND 4096, which is the
 *    only route to the second timing block and to the 512-byte ciphertext; and
 *    the Bleichenbacher attack is run in BOTH its automatic and its
 *    human-oracle mode, the second of which is the only route to
 *    `#bb-oracle-mode`, to the `.correct` / `.wrong` feedback classes, and to
 *    an enabled `#bb-abort`.
 *
 *  - THE STATES ONLY A GENERATED VALUE REACHES. The padding-diagram tooltips
 *    render `Run an OAEP encryption above to see real bytes here.` before an
 *    encryption and a grouped hex dump after it — two different renderings of
 *    the same node, and the empty one is the one a reader meets first.
 *
 *  - NO FIXED TIMEOUTS. Every step waits on the completion signal the code
 *    itself defines: a region losing `hidden`, a button returning from
 *    `disabled`, a placeholder `—` being replaced, a child count, a class.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  // WCAG 2.4.1: the FIRST tab stop must be a working bypass link. This runs
  // before any scan, because `scan` probes focus indicators and that leaves the
  // sequential focus navigation starting point mid-document with no way to reset
  // it from script.
  //
  // The `href` is asserted against a real element, not just read: this bar
  // shipped pointing at `#app`, which does not exist on this page — the main
  // landmark here is `#main-content` — so the first tab stop was a bypass link
  // that went nowhere. axe never reported it, because its skip-link rule is
  // best-practice-tagged rather than `wcag2a` and a `withTags(WCAG A/AA)` run
  // does not include it.
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  const skipTarget = await page.locator('a.cl-skip-link').getAttribute('href');
  expect(skipTarget, 'the skip link must name a target').toBeTruthy();
  await expect(
    page.locator(skipTarget as string),
    'the skip link must point at an element that exists'
  ).toHaveCount(1);
  await scanAt('skip link focused — the first tab stop');

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await scanAt('first paint, panel 1 active and every result region absent');

  // ── Panel 1: Textbook RSA ───────────────────────────────────────────────
  // The factoring wall stands on its own and is the one exhibit already
  // revealed at first paint, so it is driven before anything is generated.
  await page.click('#tb-factor-run');
  await expect(page.locator('#tb-factor-result')).toBeVisible();
  await expect(page.locator('#tb-factor-found')).toHaveText(/^Factored! n = \d+ × \d+$/);
  await scanAt('the factoring wall, a real 40-bit modulus split by trial division');

  await page.click('#tb-gen-small');
  await expect(page.locator('#tb-gen-small')).toBeEnabled();
  await expect(page.locator('#tb-params')).toBeVisible();
  await expect(page.locator('#tb-crypto-card')).toBeVisible();
  await expect(page.locator('#tb-p')).not.toHaveText('—');
  await expect(page.locator('#tb-verify')).toContainText("d really is e's inverse");
  await scanAt('a 64-bit textbook key, every parameter on screen');

  // Empty plaintext: the encrypt handler refuses and announces, rendering
  // nothing — a state whose entire content is the live region. It is only
  // reachable AFTER a keygen, because `#tb-encrypt` lives inside
  // `#tb-crypto-card`, which ships hidden.
  await expect(page.locator('#tb-plaintext')).toHaveValue('');
  await page.click('#tb-encrypt');
  await expect(page.locator('#tb-encrypt-result')).toBeHidden();
  await scanAt('encrypt pressed with an empty message — refused, nothing rendered');

  // The over-long branch: 20 characters cannot fit under a 64-bit modulus.
  await page.fill('#tb-plaintext', 'AAAAAAAAAAAAAAAAAAAA');
  await page.click('#tb-encrypt');
  await expect(page.locator('#tb-encrypt-result')).toBeHidden();
  await scanAt('plaintext too large for the modulus — refused, nothing rendered');

  await page.fill('#tb-plaintext', 'Hi');
  await page.click('#tb-encrypt');
  await expect(page.locator('#tb-encrypt-result')).toBeVisible();
  await expect(page.locator('#tb-decrypt-section')).toBeVisible();
  await expect(page.locator('#tb-ciphertext')).not.toHaveText('—');
  await scanAt('textbook ciphertext rendered');

  await page.click('#tb-decrypt');
  await expect(page.locator('#tb-decrypted')).toHaveText('Hi');
  await scanAt('textbook round trip closed');

  await page.click('#tb-determinism');
  await expect(page.locator('#tb-determinism-result')).toBeVisible();
  await expect(page.locator('#tb-ct-match')).toHaveText('✓ YES — always identical');
  await scanAt('textbook determinism — the same ciphertext twice');

  await page.click('#det-run');
  await expect(page.locator('#det-run')).toBeEnabled();
  await expect(page.locator('#det-contrast-grid')).toBeVisible();
  await expect(page.locator('#det-tb-ct1 .det-byte')).toHaveCount(32);
  await expect(page.locator('#det-oaep-ct1 .det-byte')).toHaveCount(32);
  await scanAt('the 128-byte determinism contrast grid, textbook beside OAEP');

  // A 512-bit key REPLACES the 64-bit one without clearing the ciphertext it
  // produced, so this is also the state where a stale result sits under a key
  // that did not generate it.
  await page.click('#tb-gen-large');
  await expect(page.locator('#tb-gen-large')).toBeEnabled({ timeout: 120_000 });
  await expect(page.locator('#tb-n')).not.toHaveText('—');
  await scanAt('a 512-bit textbook key, every value an order of magnitude longer');

  // ── Panel 2: RSA-OAEP ───────────────────────────────────────────────────
  await openPanel(page, 2);
  await scanAt('OAEP panel on arrival, both encrypt buttons locked');

  // The padding diagram is behind a shut <details>; open it by its summary.
  const oaepDetails = page.locator('details.oaep-details');
  await oaepDetails.locator('summary').click();
  await expect(oaepDetails).toHaveAttribute('open', '');
  await scanAt('the OAEP padding diagram disclosure open');

  // The tooltip's EMPTY rendering — the one a reader meets before running
  // anything, and a different node content from the populated one below.
  // FOCUS, not hover. `oaep.ts` binds the tooltip to `mouseenter` AND `focus`,
  // and focus is both the keyboard route and the one that works at 380px, where
  // the diagram is partly off-screen and a hover lands on nothing.
  await page.locator('[data-oaep-field="maskedDB"]').first().focus();
  await expect(page.locator('#oaep-tooltip')).toHaveClass(/visible/);
  await expect(page.locator('#oaep-tooltip-bytes')).toContainText(
    'Run an OAEP encryption above to see real bytes here.'
  );
  await scanAt('OAEP field tooltip, before any encryption');

  await page.click('#oaep-hl-avalanche');
  await expect(page.locator('#oaep-hl-note')).toContainText(/of 24 output bytes changed/);
  await expect(page.locator('#oaep-hl-block .oaep-hl-byte.changed').first()).toBeVisible();
  await scanAt('the OAEP avalanche, changed bytes highlighted');

  await expect(page.locator('#oaep-encrypt-2048')).toBeDisabled();
  await page.click('#oaep-gen-2048');
  await expect(page.locator('#oaep-gen-2048')).toBeEnabled({ timeout: 120_000 });
  await expect(page.locator('#oaep-2048-timing')).toBeVisible();
  await expect(page.locator('#oaep-encrypt-card')).toBeVisible();
  await expect(page.locator('#oaep-encrypt-2048')).toBeEnabled();
  await scanAt('2048-bit OAEP key generated, encrypt unlocked');

  // Over-long plaintext: 200 bytes will not fit under a 2048-bit OAEP key.
  await page.fill('#oaep-plaintext', 'A'.repeat(200));
  await page.click('#oaep-encrypt-2048');
  await expect(page.locator('#oaep-encrypt-result')).toBeHidden();
  await scanAt('OAEP plaintext over the 190-byte limit — refused');

  await page.fill('#oaep-plaintext', 'Hello, RSA-OAEP!');
  await page.click('#oaep-encrypt-2048');
  await expect(page.locator('#oaep-encrypt-2048')).toBeEnabled();
  await expect(page.locator('#oaep-encrypt-result')).toBeVisible();
  await expect(page.locator('#oaep-decrypt-card')).toBeVisible();
  await expect(page.locator('#oaep-randomize-card')).toBeVisible();
  await expect(page.locator('#oaep-decrypt-2048')).toBeEnabled();
  await scanAt('OAEP ciphertext, 344 characters of Base64');

  await page.locator('[data-oaep-field="maskedDB"]').first().focus();
  await expect(page.locator('#oaep-tooltip-bytes')).toContainText(/^\d+ bytes:/);
  await scanAt('OAEP field tooltip showing real bytes');

  await page.click('#oaep-decrypt-2048');
  await expect(page.locator('#oaep-decrypt-2048')).toBeEnabled();
  await expect(page.locator('#oaep-decrypt-output')).toHaveClass(/result-box-success/);
  await expect(page.locator('#oaep-decrypt-status')).toHaveText(/^✓ Decryption successful/);
  await scanAt('OAEP decryption succeeded');

  await page.click('#oaep-randomize');
  await expect(page.locator('#oaep-randomize')).toBeEnabled();
  await expect(page.locator('#oaep-randomize-result')).toBeVisible();
  await expect(page.locator('#oaep-ct-match')).toHaveText('✓ NO — different every time');
  await scanAt('OAEP randomization — two different ciphertexts for one message');

  // Regenerating the key strands the ciphertext, which is the ONLY route to the
  // failure rendering of the decrypt output.
  await page.click('#oaep-gen-2048');
  await expect(page.locator('#oaep-gen-2048')).toBeEnabled({ timeout: 120_000 });
  await page.click('#oaep-decrypt-2048');
  await expect(page.locator('#oaep-decrypt-2048')).toBeEnabled();
  await expect(page.locator('#oaep-decrypt-output')).toHaveClass(/result-box-error/);
  await expect(page.locator('#oaep-decrypt-status')).toHaveText('✗ Decryption failed');
  await scanAt('OAEP decryption FAILED — the error rendering of the result box');

  await page.click('#oaep-gen-4096');
  await expect(page.locator('#oaep-gen-4096')).toBeEnabled({ timeout: 180_000 });
  await expect(page.locator('#oaep-4096-timing')).toBeVisible();
  await expect(page.locator('#oaep-encrypt-4096')).toBeEnabled();
  await page.click('#oaep-encrypt-4096');
  await expect(page.locator('#oaep-encrypt-4096')).toBeEnabled();
  await expect(page.locator('#oaep-decrypt-4096')).toBeEnabled();
  await expect(page.locator('#oaep-decrypt-2048')).toBeDisabled();
  await scanAt('4096-bit OAEP, a 512-byte ciphertext and the 2048 decrypt re-locked');

  // ── Panel 3: RSA-PSS ────────────────────────────────────────────────────
  await openPanel(page, 3);
  await scanAt('PSS panel on arrival, nothing signed');

  await page.locator('[data-pss-field="maskedDB"]').first().focus();
  await expect(page.locator('#pss-tooltip')).toHaveClass(/visible/);
  await expect(page.locator('#pss-tooltip-bytes')).toContainText(
    'Sign a message above to see real bytes here.'
  );
  await scanAt('PSS field tooltip, before any signature');

  await page.click('#pss-gen');
  await expect(page.locator('#pss-gen')).toBeEnabled({ timeout: 120_000 });
  await expect(page.locator('#pss-sign-section')).toBeVisible();
  await expect(page.locator('#pss-keygen-status')).toHaveText('2048-bit RSA-PSS key pair ready.');
  await scanAt('PSS signing key generated');

  // Empty message: refused, nothing rendered.
  await page.fill('#pss-message', '   ');
  await page.click('#pss-sign');
  await expect(page.locator('#pss-signature-result')).toBeHidden();
  await scanAt('PSS sign pressed with an empty message — refused');

  await page.fill('#pss-message', 'This message is signed with RSA-PSS-SHA-256.');
  await page.click('#pss-sign');
  await expect(page.locator('#pss-sign')).toBeEnabled();
  await expect(page.locator('#pss-signature-result')).toBeVisible();
  await expect(page.locator('#pss-verify-card')).toBeVisible();
  await scanAt('PSS signature produced');

  await page.locator('[data-pss-field="maskedDB"]').first().focus();
  await expect(page.locator('#pss-tooltip-bytes')).toContainText(/^\d+ bytes:/);
  await scanAt('PSS field tooltip showing real bytes');

  await page.click('#pss-verify-ok');
  await expect(page.locator('#pss-verify-ok')).toBeEnabled();
  await expect(page.locator('#pss-verify-output')).toHaveClass(/result-box-success/);
  await expect(page.locator('#pss-verify-status')).toHaveText('Signature valid');
  await scanAt('PSS signature VALID');

  await page.click('#pss-verify-tampered');
  await expect(page.locator('#pss-verify-tampered')).toBeEnabled();
  await expect(page.locator('#pss-verify-output')).toHaveClass(/result-box-error/);
  await expect(page.locator('#pss-verify-status')).toHaveText('Signature invalid');
  await scanAt('PSS signature INVALID — the tampered-message rejection');

  // ── Panel 4: Håstad broadcast ───────────────────────────────────────────
  await openPanel(page, 4);
  await scanAt('Håstad panel on arrival');

  await page.click('#cfg-vulnerable');
  await expect(page.locator('#cfg-result')).toBeVisible();
  await expect(page.locator('#cfg-result')).toHaveClass(/result-box-error/);
  await expect(page.locator('#cfg-result-title')).toHaveText(
    'Your config got broken in milliseconds.'
  );
  await scanAt('the vulnerable config challenge — broken');

  await page.click('#cfg-safe');
  await expect(page.locator('#cfg-result-title')).toHaveText(
    'Your config held. Attack math collapses.',
    { timeout: 180_000 }
  );
  await expect(page.locator('#cfg-result')).toHaveClass(/result-box-success/);
  await scanAt('the safe config challenge — held');

  await page.click('#hastad-setup');
  await expect(page.locator('#hastad-setup')).toBeEnabled({ timeout: 60_000 });
  await expect(page.locator('#hastad-recipients')).toBeVisible();
  await expect(page.locator('#hastad-broadcast-card')).toBeVisible();
  await expect(page.locator('#hastad-n1')).toHaveText(/^0x[0-9a-f]+$/);
  await scanAt('three e=3 recipients generated');

  // The over-large branch: six multibyte characters are 18 UTF-8 bytes and the
  // moduli are 64-bit, so the broadcast is refused and renders nothing.
  await page.fill('#hastad-message', '€€€€€€');
  await page.click('#hastad-broadcast');
  await expect(page.locator('#hastad-ciphertexts')).toBeHidden();
  await scanAt('Håstad broadcast refused — message wider than the modulus');

  await page.fill('#hastad-message', 'Hello!');
  await page.click('#hastad-broadcast');
  await expect(page.locator('#hastad-ciphertexts')).toBeVisible();
  await expect(page.locator('#hastad-attack-card')).toBeVisible();
  await expect(page.locator('#hastad-c1')).toHaveText(/^0x[0-9a-f]+$/);
  await scanAt('the same message broadcast to three recipients');

  await page.click('#hastad-attack');
  await expect(page.locator('#hastad-attack-steps')).toBeVisible();
  await expect(page.locator('#hastad-final-reveal')).toBeVisible();
  await expect(page.locator('#hastad-recovered-text')).toContainText('Recovered message: "Hello!"');
  await scanAt('Håstad attack complete — plaintext recovered with no private key');

  // ── Panel 5: Bleichenbacher ─────────────────────────────────────────────
  await openPanel(page, 5);
  await expect(page.locator('#bb-abort')).toBeDisabled();
  await scanAt('Bleichenbacher panel on arrival, nothing set up');

  await page.click('#bb-setup');
  await expect(page.locator('#bb-setup')).toBeEnabled({ timeout: 60_000 });
  await expect(page.locator('#bb-setup-display')).toBeVisible();
  await expect(page.locator('#bb-oracle-card')).toBeVisible();
  await expect(page.locator('#bb-attack-card')).toBeVisible();
  await expect(page.locator('#bb-target-msg')).toHaveText('"Hi!"');
  await scanAt('Bleichenbacher demo key and padded target ready');

  // An empty query is refused and adds no log entry — the live region is the
  // whole of that state.
  await page.fill('#bb-oracle-input', '');
  await page.click('#bb-oracle-query');
  await expect(page.locator('#bb-oracle-result .oracle-log-entry')).toHaveCount(0);
  await scanAt('oracle query refused, log still empty');

  // A conforming query and a non-conforming one. Each appends a log entry whose
  // verdict span carries an `aria-label` — the one such attribute this lab
  // creates from JavaScript.
  const target = (await page.locator('#bb-ciphertext').textContent()) ?? '';
  await page.fill('#bb-oracle-input', target.trim());
  await page.click('#bb-oracle-query');
  await expect(page.locator('#bb-oracle-result .oracle-log-entry')).toHaveCount(1);
  await expect(page.locator('#bb-oracle-result .oracle-log-conformant')).toHaveText('✓ CONFORMANT');
  await scanAt('padding oracle answers CONFORMANT');

  await page.fill('#bb-oracle-input', '01');
  await page.click('#bb-oracle-query');
  await expect(page.locator('#bb-oracle-result .oracle-log-entry')).toHaveCount(2);
  await expect(page.locator('#bb-oracle-result .oracle-log-non-conformant')).toHaveText(
    '✗ NOT CONFORMANT'
  );
  await scanAt('padding oracle answers NOT CONFORMANT');

  await page.click('#bb-hom-run');
  await expect(page.locator('#bb-hom-verdict')).toHaveClass(/match/);
  await expect(page.locator('#bb-hom-verdict')).toContainText('✓ Identical');
  await scanAt('the homomorphic lever — Enc(a)·Enc(b) = Enc(a·b)');

  // Human-oracle mode: the only route to `#bb-oracle-mode`, to an ENABLED
  // `#bb-abort`, and to the two feedback classes.
  await page.click('#bb-run-oracle-mode');
  await expect(page.locator('#bb-oracle-mode')).toBeVisible();
  await expect(page.locator('#bb-progress')).toBeVisible();
  await expect(page.locator('#bb-abort')).toBeEnabled();
  await expect(page.locator('#bb-byte-row .byte-cell')).toHaveCount(16);
  await expect(page.locator('#bb-om-b0')).not.toHaveText('??');
  await scanAt('you are the padding oracle — the attack paused on a query');

  // Answer truthfully, then untruthfully, so both feedback renderings are
  // scanned. The truthful answer is derivable from what the panel shows.
  const bytes = await page.evaluate(() => ({
    b0: document.getElementById('bb-om-b0')?.textContent ?? '',
    b1: document.getElementById('bb-om-b1')?.textContent ?? '',
  }));
  const conforming = bytes.b0 === '00' && bytes.b1 === '02';
  await page.click(conforming ? '#bb-om-yes' : '#bb-om-no');
  await expect(page.locator('#bb-om-feedback')).toHaveClass(/correct/);
  await expect(page.locator('#bb-om-decisions')).toHaveText('1');
  await scanAt('a correct human oracle answer');

  await expect(page.locator('#bb-om-b0')).not.toHaveText('??');
  const bytes2 = await page.evaluate(() => ({
    b0: document.getElementById('bb-om-b0')?.textContent ?? '',
    b1: document.getElementById('bb-om-b1')?.textContent ?? '',
  }));
  const conforming2 = bytes2.b0 === '00' && bytes2.b1 === '02';
  await page.click(conforming2 ? '#bb-om-no' : '#bb-om-yes');
  await expect(page.locator('#bb-om-feedback')).toHaveClass(/wrong/);
  await expect(page.locator('#bb-om-decisions')).toHaveText('2');
  await scanAt('a WRONG human oracle answer — the attack has been lied to');

  // `#bb-abort` returning to `disabled` is the completion signal the code
  // itself defines for EVERY termination path, and it is the one to wait on:
  // which final line the log gets depends on which loop the abort flag was
  // checked in, and after a lie the run can also end on "no candidate intervals
  // remain" instead. Asserting the log grew, rather than pinning one of three
  // wordings, is the assertion that is actually true.
  await page.click('#bb-abort');
  await expect(page.locator('#bb-abort')).toBeDisabled();
  await expect(page.locator('#bb-run')).toBeEnabled();
  await scanAt('the attack ended after being aborted mid-run');

  // The automatic attack, run to completion: the only route to `#bb-recovered`
  // and to all sixteen byte cells resolving to `.known`.
  await page.click('#bb-run');
  await expect(page.locator('#bb-recovered')).toBeVisible({ timeout: 300_000 });
  await expect(page.locator('#bb-recovered-text')).toContainText('Recovered plaintext: "Hi!"');
  await expect(page.locator('#bb-byte-row .byte-cell.known')).toHaveCount(16);
  await expect(page.locator('#bb-abort')).toBeDisabled();
  await scanAt('Bleichenbacher complete — every byte recovered from the oracle alone');

  // ── Panel 6: RSA vs ECC vs post-quantum ─────────────────────────────────
  await openPanel(page, 6);
  await scanAt('comparison panel on arrival — the table and bar chart');

  await page.click('#hybrid-run');
  await expect(page.locator('#hybrid-run')).toBeEnabled({ timeout: 180_000 });
  await expect(page.locator('#hybrid-results')).toBeVisible();
  await expect(page.locator('#hybrid-takeaway')).toBeVisible();
  await expect(page.locator('#hybrid-hybrid-note')).toHaveText(
    '1 RSA wrap + 1 AES-GCM bulk = constant asymmetric cost'
  );
  await scanAt('the hybrid timing measurement');

  // ── The glossary popover, which is its own state everywhere ─────────────
  const term = page.locator('.gloss[data-gloss]').first();
  await term.click();
  await expect(page.locator('#gloss-body')).toBeVisible();
  await expect(page.locator('#gloss-popover-term')).not.toBeEmpty();
  await expect(term).toHaveAttribute('aria-expanded', 'true');
  await scanAt('a glossary term opened');

  await page.keyboard.press('Escape');
  await expect(page.locator('#gloss-body')).toBeHidden();
  await scanAt('glossary popover dismissed');
}
