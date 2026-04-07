/**
 * main.ts — Entry point.
 * Imports all panel modules and the UI controller, then initializes.
 */

import { initUI } from './ui.js';
import { initTextbookPanel } from './textbook.js';
import { initOaepPanel } from './oaep.js';
import { initPssPanel } from './pss.js';
import { initHastadPanel, initBleichenbacherPanel } from './attacks.js';
import { initComparePanel } from './compare.js';

// Initialize once the DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  initUI();
  initTextbookPanel();
  initOaepPanel();
  initPssPanel();
  initHastadPanel();
  initBleichenbacherPanel();
  initComparePanel();
});
