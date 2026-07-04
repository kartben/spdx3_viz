/**
 * Build-configuration helpers: parsing compile flags and build parameters.
 *
 * @module lib/build
 */

/**
 * Parses compiler flags, defines, and languages from a build configuration
 *
 * @param {Object} config - The build configuration element
 * @returns {{flags: string[], defines: string[], languages: string[]}} Parsed configuration
 */
export function parseCompileFlags(config) {
  if (!config) return { flags: [], defines: [], languages: [] };

  const description = config.description || '';
  const comment = config.comment || '';

  const langMatch = description.match(/Languages?:\s*([^;]+)/i);
  const languages = langMatch ? langMatch[1].split(',').map((lang) => lang.trim()) : [];

  const defMatch = description.match(/Defines\s*\((\d+)\):\s*([^;]+)/i);
  let defines = [];
  if (defMatch) {
    defines = defMatch[2]
      .split(',')
      .map((def) => def.trim())
      .filter((def) => def && !def.includes('...'));
  }

  let flags = [];
  if (comment) {
    const flagMatch = comment.match(/Full compile command fragments?:\s*(.+)/i);
    if (flagMatch) {
      flags = flagMatch[1].split(/\s+/).filter((flag) => flag.startsWith('-'));
    }
  }

  return { flags, defines, languages };
}

/**
 * Splits a command-line style parameter value into display tokens.
 * Handles simple quoted strings without trying to be a full shell parser.
 *
 * @param {string} value - Parameter value
 * @returns {Array<string>} Display tokens
 */
export function splitParameterValue(value) {
  if (!value || typeof value !== 'string') return [];
  return (
    value
      .match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g)
      ?.map((token) => token.replace(/^(['"])(.*)\1$/, '$2')) || []
  );
}

/**
 * Assigns display semantics to build parameter tokens.
 *
 * @param {string} token - Parameter token
 * @returns {{kind: string, className: string}} Token display metadata
 */
export function classifyParameterToken(token) {
  if (/^-D/.test(token)) {
    return { kind: 'Define', className: 'param-token param-token-define' };
  }
  if (/^-I/.test(token) || /^-i(macros|system)/.test(token) || /^--sysroot=/.test(token)) {
    return { kind: 'Include path', className: 'param-token param-token-path' };
  }
  if (/^(\/|[A-Za-z]:\\)/.test(token) || /[/\\][^/\\]+/.test(token)) {
    return { kind: 'Path', className: 'param-token param-token-path' };
  }
  if (/^-O/.test(token)) {
    return { kind: 'Optimization', className: 'param-token param-token-opt' };
  }
  if (/^-std=/.test(token)) {
    return { kind: 'Language standard', className: 'param-token param-token-standard' };
  }
  if (/^-g/.test(token)) {
    return { kind: 'Debug', className: 'param-token param-token-debug' };
  }
  if (/^-m/.test(token)) {
    return { kind: 'Machine', className: 'param-token param-token-machine' };
  }
  if (/^-Werror/.test(token)) {
    return { kind: 'Warning as error', className: 'param-token param-token-error' };
  }
  if (/^-W/.test(token)) {
    return { kind: 'Warning', className: 'param-token param-token-warning' };
  }
  if (/^-f/.test(token)) {
    return { kind: 'Code generation', className: 'param-token param-token-feature' };
  }
  if (/^-/.test(token)) {
    return { kind: 'Option', className: 'param-token param-token-option' };
  }
  if (/^[A-Z_][A-Z0-9_]*(=.*)?$/.test(token)) {
    return { kind: 'Symbol', className: 'param-token param-token-symbol' };
  }
  if (/^\d+(\.\d+)*$/.test(token)) {
    return { kind: 'Version', className: 'param-token param-token-version' };
  }
  return { kind: 'Value', className: 'param-token param-token-value' };
}

/**
 * Parses SPDX build parameters into grouped display data.
 *
 * @param {Object} build - The build element
 * @returns {Array<{key: string, label: string, entries: Array<Object>}>} Grouped parameters
 */
export function parseBuildParameters(build) {
  const params = build?.build_parameter || build?.build_parameters || [];
  if (!Array.isArray(params)) return [];

  const groups = new Map();
  params.forEach((param, paramIndex) => {
    if (!param?.key) return;
    const parts = param.key.split(':');
    const groupKey = parts[0] || 'parameter';
    if (!groups.has(groupKey)) {
      groups.set(groupKey, {
        key: groupKey,
        label: groupKey.charAt(0).toUpperCase() + groupKey.slice(1),
        entries: []
      });
    }

    const tokens = splitParameterValue(param.value).map((token, index) => {
      const metadata = classifyParameterToken(token);
      const renderKey = `${param.key}:${paramIndex}:${index}`;
      return {
        id: renderKey,
        renderKey,
        text: token,
        display: token,
        kind: metadata.kind,
        className: metadata.className
      };
    });
    groups.get(groupKey).entries.push({
      id: `${param.key}:${paramIndex}`,
      renderKey: `${param.key}:${paramIndex}`,
      key: param.key,
      label: parts.slice(1).join(' / ') || param.key,
      value: param.value || '',
      tokens
    });
  });

  return [...groups.values()].sort((a, b) => a.label.localeCompare(b.label));
}

/**
 * Counts how many times a tool is referenced in relationships
 *
 * @param {string} toolSpdxId - The tool's SPDX ID
 * @param {Array} relationships - Array of relationship objects
 * @returns {number} Usage count
 */
export function getToolUsageCount(toolSpdxId, relationships) {
  let count = 0;
  relationships.forEach((rel) => {
    if (rel.relationshipType === 'usesTool') {
      const targets = Array.isArray(rel.to) ? rel.to : [rel.to];
      if (targets.includes(toolSpdxId)) count++;
    }
  });
  return count;
}
