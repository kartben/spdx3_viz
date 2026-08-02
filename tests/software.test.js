import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  NO_PURPOSE_KEY,
  buildDirectoryFacets,
  buildPurposeFacets,
  packageGaps,
  packageHasPurpose,
  primaryPurposeLabel,
  splitFilePath,
  summarizePackageDescription
} from '../src/lib/software.js';

describe('primaryPurposeLabel', () => {
  it('splits camelCase vocabulary tokens', () => {
    assert.equal(primaryPurposeLabel('operatingSystem'), 'Operating system');
    assert.equal(primaryPurposeLabel('deviceDriver'), 'Device driver');
  });

  it('accepts a CURIE or a full term IRI', () => {
    assert.equal(primaryPurposeLabel('spdx:Software/SoftwarePurpose/library'), 'Library');
    assert.equal(
      primaryPurposeLabel('https://spdx.org/rdf/3.1/terms/Software/SoftwarePurpose/container'),
      'Container'
    );
  });

  it('keeps acronyms upper case and falls back for empty values', () => {
    assert.equal(primaryPurposeLabel('bom'), 'BOM');
    assert.equal(primaryPurposeLabel(''), 'Unspecified');
    assert.equal(primaryPurposeLabel(null), 'Unspecified');
  });
});

describe('buildPurposeFacets', () => {
  const packages = [
    { software_primaryPurpose: 'library' },
    { software_primaryPurpose: 'library' },
    { software_primaryPurpose: 'application' },
    {},
    { software_primaryPurpose: 'spdx:Software/SoftwarePurpose/library' }
  ];

  it('counts declared purposes, most used first', () => {
    const facets = buildPurposeFacets(packages);
    assert.deepEqual(
      facets.map((f) => [f.key, f.count]),
      [
        ['library', 3],
        ['application', 1],
        [NO_PURPOSE_KEY, 1]
      ]
    );
  });

  it('always sorts the unspecified bucket last', () => {
    const facets = buildPurposeFacets([{}, {}, {}, { software_primaryPurpose: 'application' }]);
    assert.equal(facets[facets.length - 1].key, NO_PURPOSE_KEY);
    assert.equal(facets[facets.length - 1].label, 'Unspecified');
  });

  it('returns an empty list for no packages', () => {
    assert.deepEqual(buildPurposeFacets([]), []);
  });
});

describe('packageHasPurpose', () => {
  it('matches normalized vocabulary values', () => {
    assert.equal(
      packageHasPurpose(
        { software_primaryPurpose: 'spdx:Software/SoftwarePurpose/library' },
        'library'
      ),
      true
    );
  });

  it('matches undeclared packages against the unspecified key', () => {
    assert.equal(packageHasPurpose({}, NO_PURPOSE_KEY), true);
    assert.equal(packageHasPurpose({ software_primaryPurpose: 'library' }, NO_PURPOSE_KEY), false);
  });
});

describe('packageGaps', () => {
  it('reports a fully described package as having no gaps', () => {
    const gaps = packageGaps(
      {
        software_packageVersion: '1.2.3',
        suppliedBy: 'SPDXRef-Acme',
        software_packageUrl: 'pkg:npm/left-pad@1.2.3'
      },
      true
    );
    assert.deepEqual(gaps, {
      version: false,
      license: false,
      supplier: false,
      identifier: false
    });
  });

  it('treats NOASSERTION values as missing', () => {
    const gaps = packageGaps(
      {
        software_packageVersion: 'NOASSERTION',
        suppliedBy: 'SPDXRef-NoAssertion'
      },
      false
    );
    assert.deepEqual(gaps, {
      version: true,
      license: true,
      supplier: true,
      identifier: true
    });
  });

  it('accepts originatedBy in place of a supplier, and an externalIdentifier as the id', () => {
    const gaps = packageGaps(
      {
        originatedBy: ['SPDXRef-Origin'],
        externalIdentifier: [{ externalIdentifierType: 'cpe23', identifier: 'cpe:2.3:a:acme:x' }]
      },
      false
    );
    assert.equal(gaps.supplier, false);
    assert.equal(gaps.identifier, false);
  });
});

describe('summarizePackageDescription', () => {
  const packages = [
    // no gaps
    { spdxId: 'a', software_packageVersion: '1', suppliedBy: 'S', software_packageUrl: 'pkg:x/a' },
    // one gap (identifier)
    { spdxId: 'b', software_packageVersion: '1', suppliedBy: 'S' },
    // three gaps (version, supplier, identifier)
    { spdxId: 'c' },
    // four gaps
    { spdxId: 'd' }
  ];
  const licensed = new Set(['a', 'b', 'c']);
  const summary = summarizePackageDescription(packages, (p) => licensed.has(p.spdxId));

  it('counts each missing field', () => {
    assert.deepEqual(summary.gapCounts, {
      version: 2,
      license: 1,
      supplier: 2,
      identifier: 3
    });
  });

  it('buckets packages by how many fields they are missing', () => {
    assert.deepEqual(summary.buckets, { full: 1, partial: 1, sparse: 2 });
    assert.equal(summary.total, 4);
    assert.equal(summary.fullPct, 25);
  });

  it('handles an empty list without dividing by zero', () => {
    const empty = summarizePackageDescription([], () => false);
    assert.equal(empty.total, 0);
    assert.equal(empty.fullPct, 0);
  });
});

describe('splitFilePath', () => {
  it('splits a path into directory and file name', () => {
    assert.deepEqual(splitFilePath('usr/lib/libc.so'), { dir: 'usr/lib/', base: 'libc.so' });
  });

  it('leaves a bare file name undivided', () => {
    assert.deepEqual(splitFilePath('Makefile'), { dir: '', base: 'Makefile' });
    assert.deepEqual(splitFilePath(''), { dir: '', base: '' });
  });

  it('keeps a trailing slash as the whole name rather than an empty base', () => {
    assert.deepEqual(splitFilePath('usr/lib/'), { dir: '', base: 'usr/lib/' });
  });
});

describe('buildDirectoryFacets', () => {
  const files = [
    { name: 'usr/lib/a.so' },
    { name: 'usr/lib/b.so' },
    { name: 'usr/lib/deep/c.so' },
    { name: 'usr/bin/sh' },
    { name: 'README' }
  ];

  it('groups on the leading path segments, most populated first', () => {
    assert.deepEqual(
      buildDirectoryFacets(files).map((f) => [f.key, f.count]),
      [
        ['usr/lib', 3],
        ['usr/bin', 1]
      ]
    );
  });

  it('caps the number of facets', () => {
    const many = Array.from({ length: 40 }, (_, i) => ({ name: `d${i}/x/f.txt` }));
    assert.equal(buildDirectoryFacets(many, 5).length, 5);
  });

  it('returns nothing when no file carries a directory', () => {
    assert.deepEqual(buildDirectoryFacets([{ name: 'a' }, { name: 'b' }]), []);
  });
});
