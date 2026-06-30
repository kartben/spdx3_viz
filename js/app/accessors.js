import {
  cleanName as formatSpdxName,
  cleanFileName as formatFileName,
  fileExt as getFileExtension,
  formatDate as formatDisplayDate,
  getRelationshipColor,
  getRelationshipGroupLabel,
  getRelationshipSortOrder,
  getRelationshipTargetDisplayName,
  getElementDisplayName,
  getDetailPromotedFields,
  getNodeType as resolveNodeType,
  getNodeTypeColor,
  getElementBadgeClass,
  parseCompileFlags as parseBuildConfigFlags,
  parseBuildParameters as parseBuildParameterGroups,
  getToolUsageCount,
  getExternalIdentifiers,
  isMeaningfulValue,
  normalizeUrl,
  copyToClipboard
} from '../utils.js';

/* ==========================================================================
   Element accessors + display helpers
   Thin lookups into the relationship indexes, name/date formatting, build
   parameter helpers, and the relationship-group data the detail panel renders.
   Most are one-liners exposing a util or index to the templates as this.*().
   ========================================================================== */

export const accessorsMixin = {
  cleanName(spdxId) {
    return formatSpdxName(spdxId);
  },
  cleanFileName(spdxId) {
    return formatFileName(spdxId, this.elementMap);
  },
  fileExt(name) {
    return getFileExtension(name);
  },
  formatDate(date) {
    return formatDisplayDate(date);
  },
  depsOf(spdxId) {
    return this.depIndex.get(spdxId) || [];
  },
  dependentsOf(spdxId) {
    return this.dependentIndex.get(spdxId) || [];
  },
  containedFiles(spdxId) {
    return this.containsIndex.get(spdxId) || [];
  },
  parentPackage(spdxId) {
    return this.parentIndex.get(spdxId) || null;
  },
  fileTools(spdxId) {
    return this.toolIndex.get(spdxId) || [];
  },
  buildInputs(spdxId) {
    return this.buildInputIndex.get(spdxId) || [];
  },
  buildOutputs(spdxId) {
    return this.buildOutputIndex.get(spdxId) || [];
  },
  producedByBuilds(spdxId) {
    return this.producedByBuildIndex.get(spdxId) || [];
  },
  consumedByBuilds(spdxId) {
    return this.consumedByBuildIndex.get(spdxId) || [];
  },
  childBuilds(spdxId) {
    return this.buildStepIndex.get(spdxId) || [];
  },
  parentBuilds(spdxId) {
    return this.parentBuildIndex.get(spdxId) || [];
  },
  distributionArtifacts(spdxId) {
    return this.distributionArtifactIndex.get(spdxId) || [];
  },
  distributedBy(spdxId) {
    return this.distributedByIndex.get(spdxId) || [];
  },
  staticLinks(spdxId) {
    return this.staticLinkIndex.get(spdxId) || [];
  },
  configuresTargets(spdxId) {
    return this.configuresIndex.get(spdxId) || [];
  },
  configuredBy(spdxId) {
    return this.configuredByIndex.get(spdxId) || [];
  },
  snippetsOf(fileId) {
    return this.snippetsByFileIndex.get(fileId) || [];
  },
  isCompiledSource(file) {
    const ext = getFileExtension(file?.name || '').toLowerCase();
    return ['.c', '.cpp', '.cc', '.cxx', '.s'].includes(ext);
  },
  async loadFileSource(fileId) {
    if (this.fileSourceCache[fileId]) return;
    const url = this.fileSourceIndex.get(fileId);
    if (!url) return;
    const file = this.elementMap.get(fileId);

    this.fileSourceCache[fileId] = { loading: true, windows: null, error: null };

    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const content = await res.text();
      const result = this._buildSnippetWindows(fileId, content, file?.name);
      this.fileSourceCache[fileId] = { loading: false, error: null, ...result };
    } catch (err) {
      this.fileSourceCache[fileId] = { loading: false, windows: null, error: err.message };
    }
  },
  _buildSnippetWindows(fileId, content, fileName) {
    const ext = getFileExtension(fileName || '');
    const rawLines = content.split('\n');
    const snippetList = this.snippetsOf(fileId);
    if (!snippetList.length) return { windows: [] };

    // Syntax-highlight full content, then split by line
    let highlightedLines;
    const hljs = window.hljs;
    if (hljs) {
      const langMap = { '.c': 'c', '.h': 'c', '.cpp': 'cpp', '.py': 'python', '.js': 'javascript' };
      const lang = langMap[ext];
      try {
        const html = lang
          ? hljs.highlight(content, { language: lang, ignoreIllegals: true }).value
          : hljs.highlightAuto(content).value;
        highlightedLines = html.split('\n');
      } catch {
        highlightedLines = null;
      }
    }
    if (!highlightedLines) {
      highlightedLines = rawLines.map((l) =>
        l.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      );
    }

    // Build a Set of covered line numbers
    const coveredLines = new Set();
    for (const s of snippetList) {
      const lr = s.software_lineRange;
      if (!lr) continue;
      for (let i = lr.beginIntegerRange; i <= lr.endIntegerRange; i++) coveredLines.add(i);
    }

    // Build merged context windows (each snippet ±CONTEXT lines)
    const CONTEXT = 5;
    const rawWindows = [];
    for (const s of snippetList) {
      const lr = s.software_lineRange;
      if (!lr) continue;
      const wStart = Math.max(1, lr.beginIntegerRange - CONTEXT);
      const wEnd = Math.min(rawLines.length, lr.endIntegerRange + CONTEXT);
      const last = rawWindows[rawWindows.length - 1];
      if (last && wStart <= last.end + 2) {
        last.end = Math.max(last.end, wEnd);
      } else {
        rawWindows.push({ start: wStart, end: wEnd });
      }
    }

    const totalLines = rawLines.length;
    const windows = rawWindows.map((w) => ({
      startLine: w.start,
      endLine: w.end,
      gapBefore: w.start > 1,
      gapAfter: w.end < totalLines,
      lines: this._sliceLines(
        { _allHighlightedLines: highlightedLines, _coveredLines: coveredLines },
        w.start,
        w.end
      )
    }));

    return {
      windows,
      _allHighlightedLines: highlightedLines,
      _coveredLines: coveredLines,
      _totalLines: totalLines
    };
  },
  _sliceLines(cache, start, end) {
    return Array.from({ length: end - start + 1 }, (_, i) => {
      const lineNum = start + i;
      return {
        lineNum,
        html: cache._allHighlightedLines[lineNum - 1] ?? '',
        covered: cache._coveredLines.has(lineNum)
      };
    });
  },
  gapBeforeCount(fileId, wi) {
    const cache = this.fileSourceCache[fileId];
    const win = cache?.windows?.[wi];
    if (!win) return 0;
    const prevEnd = wi > 0 ? cache.windows[wi - 1].endLine : 0;
    return win.startLine - prevEnd - 1;
  },
  gapAfterCount(fileId, wi) {
    const cache = this.fileSourceCache[fileId];
    const win = cache?.windows?.[wi];
    if (!win) return 0;
    const nextStart =
      wi < cache.windows.length - 1 ? cache.windows[wi + 1].startLine : (cache._totalLines ?? 0) + 1;
    return nextStart - win.endLine - 1;
  },
  expandWindow(fileId, wi, direction) {
    const cache = this.fileSourceCache[fileId];
    if (!cache?._allHighlightedLines) return;

    const CHUNK = 50;
    const windows = cache.windows.map((w) => ({ ...w }));
    const w = windows[wi];

    if (direction === 'before') {
      const prevEnd = wi > 0 ? windows[wi - 1].endLine : 0;
      const newStart = Math.max(prevEnd + 1, w.startLine - CHUNK);
      w.lines = this._sliceLines(cache, newStart, w.endLine);
      w.gapBefore = newStart > (wi > 0 ? windows[wi - 1].endLine + 1 : 1);
      w.startLine = newStart;
    } else {
      const nextStart = wi < windows.length - 1 ? windows[wi + 1].startLine : Infinity;
      const newEnd = Math.min(nextStart - 1, w.endLine + CHUNK, cache._totalLines);
      w.lines = this._sliceLines(cache, w.startLine, newEnd);
      w.gapAfter = newEnd < Math.min(nextStart - 1, cache._totalLines);
      w.endLine = newEnd;
    }

    this.fileSourceCache = { ...this.fileSourceCache, [fileId]: { ...cache, windows } };
  },
  outgoingRels(spdxId) {
    return this.relFromIndex.get(spdxId) || [];
  },
  incomingRels(spdxId) {
    return this.relToIndex.get(spdxId) || [];
  },

  buildSortName(build) {
    return (
      this.buildOutputs(build.spdxId)
        .map((id) => this.relTargetDisplayName(id))
        .join(' ') ||
      build.build_buildId ||
      build.spdxId ||
      ''
    );
  },

  buildDisplayName(build) {
    const outputs = this.buildOutputs(build.spdxId);
    if (outputs.length) {
      return outputs.map((id) => this.relTargetDisplayName(id)).join(', ');
    }
    return build.name || build.build_buildId || build.spdxId || 'Build';
  },

  formatCount(count) {
    return new Intl.NumberFormat().format(count || 0);
  },

  getBuildConfigFor(targetSpdxId) {
    const configs = this.configuredBy(targetSpdxId);
    if (!configs.length) return null;
    return this.elementMap.get(configs[0].configId);
  },

  parseCompileFlags(config) {
    return parseBuildConfigFlags(config);
  },
  buildParameters(build) {
    return parseBuildParameterGroups(build);
  },
  buildParameterCount(build) {
    return this.buildParameters(build).reduce((count, group) => count + group.entries.length, 0);
  },
  buildParameterPreview(build) {
    return this.buildParameters(build)
      .flatMap((group) => group.entries)
      .slice(0, 3);
  },
  parameterTokenId(token) {
    if (typeof token === 'string') return token;
    return token?.renderKey || token?.id || this.parameterTokenText(token);
  },
  parameterTokenText(token) {
    if (typeof token === 'string') return token;
    return token?.display ?? token?.text ?? token?.value ?? '';
  },
  parameterTokenKind(token) {
    if (typeof token === 'string') return 'Value';
    return token?.kind || 'Value';
  },
  parameterTokenClass(token) {
    if (typeof token === 'string') return 'param-token param-token-value';
    return token?.className || 'param-token param-token-value';
  },
  toolUsageCount(spdxId) {
    return getToolUsageCount(spdxId, this.relationships);
  },
  externalIdentifiers(element) {
    return getExternalIdentifiers(element);
  },
  isMeaningful(value) {
    return isMeaningfulValue(value);
  },
  downloadUrl(value) {
    return normalizeUrl(value);
  },
  relColor(type) {
    return getRelationshipColor(type);
  },
  relGroupLabel(relType, direction) {
    return getRelationshipGroupLabel(relType, direction);
  },

  // Grouped relationship data for the detail panel
  get detailRelGroups() {
    if (!this.detailElement) return [];
    const id = this.detailElement.spdxId;
    const groups = new Map(); // key → { label, color, items:[] }

    // Vulnerability associations are surfaced in the dedicated security
    // section, not the generic relationship list (a single package can carry
    // thousands of them).
    const skip = (rel) => rel.relationshipType === 'hasAssociatedVulnerability';

    // Outgoing: this element → targets
    (this.relFromIndex.get(id) || []).forEach((rel) => {
      if (skip(rel)) return;
      const key = rel.relationshipType + ':out';
      if (!groups.has(key)) {
        groups.set(key, {
          key,
          label: this.relGroupLabel(rel.relationshipType, 'out'),
          color: this.relColor(rel.relationshipType),
          sortOrder: this.relSortOrder(rel.relationshipType, 'out'),
          items: []
        });
      }
      const targets = Array.isArray(rel.to) ? rel.to : [rel.to];
      targets.forEach((t) => {
        // Avoid duplicate entries
        if (!groups.get(key).items.find((i) => i.id === t)) {
          groups.get(key).items.push({
            id: t,
            displayName: this.relTargetDisplayName(t),
            direction: 'out',
            // LifecycleScopedRelationship scope (build / runtime / test / …)
            scope: rel.scope || ''
          });
        }
      });
    });

    // Incoming: sources → this element
    (this.relToIndex.get(id) || []).forEach((rel) => {
      if (skip(rel)) return;
      const key = rel.relationshipType + ':in';
      if (!groups.has(key)) {
        groups.set(key, {
          key,
          label: this.relGroupLabel(rel.relationshipType, 'in'),
          color: this.relColor(rel.relationshipType),
          sortOrder: this.relSortOrder(rel.relationshipType, 'in'),
          items: []
        });
      }
      if (!groups.get(key).items.find((i) => i.id === rel.from)) {
        groups.get(key).items.push({
          id: rel.from,
          displayName: this.relTargetDisplayName(rel.from),
          direction: 'in',
          scope: rel.scope || ''
        });
      }
    });

    return [...groups.values()].sort((a, b) => a.sortOrder - b.sortOrder);
  },

  // Sort order for relationship groups (most relevant first)
  relSortOrder(type, dir) {
    return getRelationshipSortOrder(type, dir);
  },
  relTargetDisplayName(spdxId) {
    return getRelationshipTargetDisplayName(spdxId, this.elementMap);
  },
  elementDisplayName(element) {
    return getElementDisplayName(element, this.elementMap);
  },
  get detailPromotedFields() {
    return getDetailPromotedFields(this.detailElement, this.elementMap);
  },
  elementBadgeClass(type) {
    return getElementBadgeClass(type);
  },
  getNodeType(item) {
    return resolveNodeType(item);
  },
  nodeTypeColor(type) {
    return getNodeTypeColor(type);
  },

  placeholderElement(spdxId) {
    return {
      type: 'ExternalReference',
      spdxId,
      name: this.cleanName(spdxId),
      placeholder: true
    };
  },

  copyHash(h) {
    copyToClipboard(h).then(() => {
      this.toastMsg = 'Copied to clipboard';
      setTimeout(() => (this.toastMsg = ''), 2000);
    });
  }
};
