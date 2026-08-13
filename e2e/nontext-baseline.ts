/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 *
 * ── What the first live run of this oracle found, and where it went ─────────
 *
 * Every finding inside `<main id="main-content">` was FIXED in the source, not
 * exempted here:
 *
 *   `.btn-ghost` x3 (`#tb-determinism`, `#bb-abort`, `#bb-om-no`)  1.22–1.44:1
 *   `.config-card` x2 (`#cfg-vulnerable`, `#cfg-safe`)             1.25–1.31:1
 *     — all five drew their edge from `--c-border`, the SURFACE divider, while
 *       `--c-border-strong` — declared under a comment reading "Control
 *       boundaries only (WCAG 2.1 SC 1.4.11)" — was applied to `.form-input,
 *       .form-textarea` and to nothing else in 1,918 lines. One rule against 44
 *       uses of the decorative token. All five now use `--c-border-strong`.
 *
 * Two findings were ORACLE BUGS, fixed in `nontext.ts` rather than in the page,
 * and both are worth a fleet-wide grep:
 *   - the selected tab reported 1.12:1 because the check measured
 *     `borderTopColor` for all four sides, and `.tab-btn` is delineated by its
 *     `border-bottom` alone. It now measures each painted side and takes the
 *     best.
 *   - the five UNSELECTED tabs reported 1.00:1 because `border: 2px solid
 *     transparent` — a layout spacer — counted as a border. A side now has to be
 *     non-transparent to be treated as a delineator.
 *
 * The two entries below are the shared Crypto Lab top bar and are not this
 * repo's to change. `.cl-btn` draws its edge as
 * `1px solid color-mix(in srgb, var(--accent, #35d6bb) 38%, transparent)` over
 * the bar's fixed `#0b1512`. This lab defines no `--accent`, so the fallback
 * teal applies and the composited edge is 2.45:1 against the bar, IDENTICALLY
 * IN BOTH THEMES, because the bar is always dark and the page theme does not
 * move it. Every repo in this fleet carries a copy of that markup and CSS, and
 * `CLAUDE.md` is explicit that a change every lab should get is a reviewed
 * fleet-wide pass and never an overwrite driven from one repo.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  'control-boundary|a.cl-btn': { ratio: 2.45, required: 3, unverified: false },
  'control-boundary|button#cl-theme-toggle.cl-btn.cl-icon': {
    ratio: 2.45,
    required: 3,
    unverified: false,
  },
};
