import { initPitfallsPanel } from './pitfalls-panel.js';
import { initParityPanel } from './parity-panel.js';
import { mountExtensionPanels } from './extension-panels.js';
/**
 * main.ts — Entry point.
 * Imports all panel modules and the UI controller, then initializes.
 */

import { initUI } from './ui.js';
import { initTextbookPanel } from './textbook.js';
import { initOaepPanel } from './oaep.js';
import { initPssPanel } from './pss.js';
import { initHastadPanel, initBleichenbacherPanel, initOracleWithoutFactoringPanel } from './attacks.js';
import { initComparePanel } from './compare.js';
import { initDeterminismPanel } from './determinism.js';
import { initHybridPanel } from './hybrid.js';
import { initGlossary } from './glossary.js';

// Initialize once the DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  mountExtensionPanels();
  initUI();
  initGlossary();
  initPitfallsPanel();
  initParityPanel();
  initTextbookPanel();
  initOaepPanel();
  initPssPanel();
  initHastadPanel();
  initBleichenbacherPanel();
  initOracleWithoutFactoringPanel();
  initComparePanel();
  initDeterminismPanel();
  initHybridPanel();
});
