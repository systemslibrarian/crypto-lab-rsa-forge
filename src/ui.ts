/**
 * ui.ts — Panel controller, theme toggle, shared UI utilities.
 * WCAG 2.1 AA: keyboard navigation, ARIA state, focus management.
 */

export function initUI(): void {
  initTheme();
  initTabs();
}

/* ── Theme ─────────────────────────────────────────────────── */
function initTheme(): void {
  const toggle = document.getElementById('theme-toggle') as HTMLButtonElement;
  const moonIcon = document.getElementById('theme-icon-moon') as HTMLElement;
  const sunIcon  = document.getElementById('theme-icon-sun')  as HTMLElement;

  // Restore preference from localStorage
  const saved = localStorage.getItem('rsa-forge-theme');
  if (saved === 'light') {
    applyTheme('light', toggle, moonIcon, sunIcon);
  }

  toggle.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    const next    = current === 'dark' ? 'light' : 'dark';
    applyTheme(next, toggle, moonIcon, sunIcon);
    localStorage.setItem('rsa-forge-theme', next);
    announce(`Switched to ${next} mode`);
  });
}

function applyTheme(
  theme: 'dark' | 'light',
  toggle: HTMLButtonElement,
  moonIcon: HTMLElement,
  sunIcon: HTMLElement,
): void {
  document.documentElement.setAttribute('data-theme', theme);
  if (theme === 'dark') {
    moonIcon.style.display = '';
    sunIcon.style.display  = 'none';
    toggle.setAttribute('aria-label', 'Switch to light mode');
  } else {
    moonIcon.style.display = 'none';
    sunIcon.style.display  = '';
    toggle.setAttribute('aria-label', 'Switch to dark mode');
  }
}

/* ── Tabs / Panels ─────────────────────────────────────────── */
function initTabs(): void {
  const tabList = document.querySelector('.tab-list') as HTMLElement;
  const tabs    = Array.from(tabList.querySelectorAll<HTMLButtonElement>('.tab-btn'));

  tabs.forEach((tab, idx) => {
    tab.addEventListener('click', () => activateTab(tab, tabs));

    // Arrow-key navigation (ARIA Authoring Practices Guide §3.21)
    tab.addEventListener('keydown', (e: KeyboardEvent) => {
      let target: HTMLButtonElement | null = null;
      if (e.key === 'ArrowRight') {
        target = tabs[(idx + 1) % tabs.length];
      } else if (e.key === 'ArrowLeft') {
        target = tabs[(idx - 1 + tabs.length) % tabs.length];
      } else if (e.key === 'Home') {
        target = tabs[0];
      } else if (e.key === 'End') {
        target = tabs[tabs.length - 1];
      }
      if (target) {
        e.preventDefault();
        activateTab(target, tabs);
        target.focus();
      }
    });
  });
}

function activateTab(target: HTMLButtonElement, tabs: HTMLButtonElement[]): void {
  // Deactivate all
  tabs.forEach(t => {
    t.setAttribute('aria-selected', 'false');
    t.setAttribute('tabindex', '-1');
    const panelId = t.getAttribute('aria-controls');
    if (panelId) {
      const panel = document.getElementById(panelId);
      if (panel) {
        panel.classList.remove('active');
        panel.hidden = true;
      }
    }
  });

  // Activate target
  target.setAttribute('aria-selected', 'true');
  target.removeAttribute('tabindex');
  const panelId = target.getAttribute('aria-controls');
  if (panelId) {
    const panel = document.getElementById(panelId);
    if (panel) {
      panel.classList.add('active');
      panel.hidden = false;
    }
  }
}

/* ── Shared utilities ──────────────────────────────────────── */

/** Announce a message to screen readers via aria-live polite region. */
export function announce(msg: string): void {
  const el = document.getElementById('aria-live');
  if (!el) return;
  el.textContent = '';
  requestAnimationFrame(() => { el.textContent = msg; });
}

/** Announce urgently via aria-live assertive region. */
export function announceUrgent(msg: string): void {
  const el = document.getElementById('aria-live-assertive');
  if (!el) return;
  el.textContent = '';
  requestAnimationFrame(() => { el.textContent = msg; });
}

/** Show a hidden element. */
export function show(id: string): void {
  const el = document.getElementById(id);
  if (el) { el.hidden = false; el.removeAttribute('hidden'); }
}

/** Hide an element. */
export function hide(id: string): void {
  const el = document.getElementById(id);
  if (el) { el.hidden = true; }
}

/** Set text content of an element. */
export function setText(id: string, text: string): void {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

/** Truncate a hex/base64 string for display. */
export function truncate(s: string, n = 48): string {
  return s.length > n ? s.slice(0, n) + '…' : s;
}

/** Convert bytes to hex string. */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/** Convert hex string to Uint8Array. */
export function fromHex(hex: string): Uint8Array {
  hex = hex.replace(/\s/g, '');
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Convert bytes to Base64. */
export function toBase64(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Convert ArrayBuffer to Uint8Array. */
export function bufToBytes(buf: ArrayBuffer): Uint8Array {
  return new Uint8Array(buf);
}

/** Set button loading state. */
export function setLoading(btn: HTMLButtonElement, loading: boolean, originalLabel?: string): void {
  if (loading) {
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    const spinner = document.createElement('span');
    spinner.className = 'loading-spinner';
    spinner.setAttribute('aria-hidden', 'true');
    spinner.id = `${btn.id}-spinner`;
    btn.prepend(spinner);
  } else {
    btn.disabled = false;
    btn.removeAttribute('aria-busy');
    const spinner = document.getElementById(`${btn.id}-spinner`);
    if (spinner) spinner.remove();
    if (originalLabel) btn.setAttribute('aria-label', originalLabel);
  }
}

/** Format a bigint as hex string (even number of chars). */
export function bigintToHex(n: bigint): string {
  const h = n.toString(16);
  return h.length % 2 === 0 ? h : '0' + h;
}

/** Convert bigint to fixed-length Uint8Array (big-endian). */
export function bigintToBytes(n: bigint, byteLen: number): Uint8Array {
  const hex = n.toString(16).padStart(byteLen * 2, '0');
  const arr = new Uint8Array(byteLen);
  for (let i = 0; i < byteLen; i++) {
    arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return arr;
}

/** Convert Uint8Array to bigint (big-endian). */
export function bytesToBigint(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const b of bytes) {
    result = (result << 8n) | BigInt(b);
  }
  return result;
}

/** Ceiling integer division. */
export function ceilDiv(a: bigint, b: bigint): bigint {
  return (a + b - 1n) / b;
}
