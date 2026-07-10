/* ⌘K command palette: a single overlay that fuzzy-searches every element in the
   loaded document *and* the app's own actions (jump to a view, copy a share
   link, load a different SBOM…). It reuses the header search's corpus and
   scoring, but is reachable from anywhere via the keyboard, including the Graph
   view where the inline header search is hidden. */

const PALETTE_ELEMENT_LIMIT = 7; // element rows shown alongside command matches

// Small stroke icons for the action commands, matching the header's icon style.
const ACTION_ICONS = {
  share:
    '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>',
  home: '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/></svg>',
  sparkle:
    '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 3v4M3 5h4M17 15v4m-2-2h4M11 4l1.9 5.1L18 11l-5.1 1.9L11 18l-1.9-5.1L4 11l5.1-1.9L11 4z"/></svg>',
  zoom: '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M11 8v6M8 11h6M18 11a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>',
  plus: '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>'
};

export const paletteMixin = {
  // Whether a view is reachable for the current document. Single source of truth
  // for both the sidebar's nav items and the palette's "Go to view" commands, so
  // the palette never offers a view the sidebar hides.
  isViewAvailable(id) {
    switch (id) {
      case 'security':
        return this.vulnerabilities.length > 0;
      case 'packages':
        return this.plainPackages.length > 0;
      case 'ai':
        return this.aiPackages.length > 0;
      case 'dataset':
        return this.datasetPackages.length > 0;
      case 'files':
        return this.files.length > 0;
      case 'hardware':
        return this.hardware.length > 0;
      case 'requirements':
        return this.requirements.length > 0;
      case 'licenses':
        return this.licenses.length > 0;
      case 'configs':
        return this.buildConfigs.length > 0;
      case 'build':
        return this.builds.length > 0 || this.tools.length > 0;
      case 'remediation':
        return this.remediationFindings.length > 0;
      case 'impact':
        return this.hasImpactData;
      case 'agents':
        return this.agents.length > 0;
      case 'supplychain':
        return this.supplyChain.length > 0;
      default:
        return true; // dashboard, graph, statistics, raw are always available
    }
  },

  // The command entries: view jumps plus a few global actions. Rebuilt each read
  // (cheap: ~16 views), so availability and the share button stay in sync.
  get paletteCommands() {
    const cmds = [];
    for (const v of this.views) {
      if (v.id === this.currentView || !this.isViewAvailable(v.id)) continue;
      cmds.push({
        kind: 'command',
        id: 'view:' + v.id,
        group: 'Go to view',
        name: v.label,
        icon: v.icon,
        _hay: ('go to view ' + v.label + ' ' + v.id).toLowerCase(),
        run: () => this.switchView(v.id)
      });
    }
    const action = (id, name, icon, run, hay) =>
      cmds.push({
        kind: 'command',
        id: 'action:' + id,
        group: 'Actions',
        name,
        icon,
        _hay: (name + ' ' + (hay || '')).toLowerCase(),
        run
      });
    if (this.currentView === 'graph') {
      action(
        'reset-zoom',
        'Reset graph zoom',
        ACTION_ICONS.zoom,
        () => this.resetGraphZoom(),
        'fit frame'
      );
    }
    if (this.loadedSampleId) {
      action('share', 'Copy shareable link', ACTION_ICONS.share, () => this.copyShareLink(), 'url');
    }
    action(
      'add-files',
      'Add or remove files',
      ACTION_ICONS.plus,
      () => this.openAddFilesModal(),
      'merge sample sbom import upload drop'
    );
    action(
      'changelog',
      "What's new",
      ACTION_ICONS.sparkle,
      () => this.openChangelogModal(),
      'changelog release notes'
    );
    action(
      'home',
      'Load a different SBOM',
      ACTION_ICONS.home,
      () => this.goHome(),
      'open close file home'
    );
    return cmds;
  },

  // The rows shown in the palette, in display order. Empty query → the command
  // menu; otherwise fuzzy-matched commands first, then element matches.
  get paletteItems() {
    const q = (this.paletteQuery || '').trim().toLowerCase();
    const commands = this.paletteCommands;
    if (!q) return commands;

    const scoredCmds = [];
    for (const c of commands) {
      const s = this._fieldScore(c._hay, q, 1);
      if (s > 0) scoredCmds.push({ c, s });
    }
    scoredCmds.sort((a, b) => b.s - a.s || a.c.name.length - b.c.name.length);

    const elements = [];
    for (const e of this.searchCorpus) {
      const s = this._entryScore(e, q);
      if (s > 0) elements.push({ e, s });
    }
    elements.sort(
      (a, b) => b.s - a.s || a.e._n.length - b.e._n.length || a.e._n.localeCompare(b.e._n)
    );

    return [
      ...scoredCmds.map((x) => x.c),
      ...elements
        .slice(0, PALETTE_ELEMENT_LIMIT)
        .map((x) => ({ kind: 'element', ...x.e, group: 'Results' }))
    ];
  },

  // True when this row starts a new section, so the template can print a header.
  paletteIsGroupStart(i) {
    const items = this.paletteItems;
    return i === 0 || items[i].group !== items[i - 1].group;
  },

  openPalette() {
    this.paletteOpen = true;
    this.paletteQuery = '';
    this.paletteActiveIndex = 0;
    // Focus the input once the overlay is in the DOM.
    this.$nextTick(() => this.$refs.paletteInput?.focus());
  },
  closePalette() {
    this.paletteOpen = false;
    this.paletteQuery = '';
    this.paletteActiveIndex = 0;
  },
  togglePalette() {
    if (this.paletteOpen) this.closePalette();
    else this.openPalette();
  },
  // Keep the highlighted row valid as the result set shrinks/grows while typing.
  onPaletteInput() {
    this.paletteActiveIndex = 0;
  },

  selectPaletteItem(item) {
    if (!item) return;
    if (item.kind === 'command') {
      const run = item.run;
      this.closePalette();
      run?.();
    } else {
      this.closePalette();
      if (item.nodeType === 'license') this.navigateToLicense(item.id);
      else this.navigateTo(item.id);
    }
  },

  paletteKeydown(event) {
    const items = this.paletteItems;
    if (event.key === 'ArrowDown') {
      if (!items.length) return;
      event.preventDefault();
      this.paletteActiveIndex = (this.paletteActiveIndex + 1) % items.length;
      this._scrollPaletteActiveIntoView();
    } else if (event.key === 'ArrowUp') {
      if (!items.length) return;
      event.preventDefault();
      this.paletteActiveIndex = (this.paletteActiveIndex - 1 + items.length) % items.length;
      this._scrollPaletteActiveIntoView();
    } else if (event.key === 'Enter') {
      if (!items.length) return;
      event.preventDefault();
      this.selectPaletteItem(items[this.paletteActiveIndex] || items[0]);
    } else if (event.key === 'Escape') {
      event.preventDefault();
      this.closePalette();
    }
  },

  _scrollPaletteActiveIntoView() {
    this.$nextTick(() => {
      const list = this.$refs.paletteList;
      const row = list?.querySelector('[data-palette-active="true"]');
      row?.scrollIntoView({ block: 'nearest' });
    });
  }
};
