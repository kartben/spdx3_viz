/**
 * Browser entry point: loads styles and libraries, registers the Alpine
 * component, and starts Alpine.
 *
 * @module main
 */

import './styles.css';

import Alpine from 'alpinejs';
import collapse from '@alpinejs/collapse';

import { spdxApp } from './app.js';

Alpine.plugin(collapse);

// Exposed for debugging; not required by the app itself.
window.Alpine = Alpine;

Alpine.data('spdxApp', spdxApp);
Alpine.start();
