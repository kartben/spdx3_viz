import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUTPUT = resolve(ROOT, 'public/samples/supply-chain/arborlink-sg1-supply-chain.spdx3.jsonld');
const NS = 'https://spdx.org/spdxdocs/arborlink-sg1-2026.07-supply-chain';
const CREATED = '2026-07-06T09:30:00Z';
const CREATION_INFO = '_:arborlink-sg1-creation-info';

const id = (fragment) => `${NS}#${fragment}`;
const slug = (value) =>
  value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');

const digest = (value) => createHash('sha256').update(`arborlink-sg1|${value}`).digest('hex');

const hash = (value) => ({
  type: 'Hash',
  algorithm: 'sha256',
  hashValue: digest(value)
});

const externalId = (identifier, comment, locator, authority = 'Arbor Devices (fictional)') => ({
  type: 'ExternalIdentifier',
  externalIdentifierType: identifier.includes('@') ? 'email' : 'other',
  identifier,
  issuingAuthority: authority,
  ...(comment ? { comment } : {}),
  ...(locator ? { identifierLocator: [locator] } : {})
});

const element = (type, fragment, properties = {}) => ({
  type,
  spdxId: id(fragment),
  creationInfo: CREATION_INFO,
  ...properties
});

const cdxProperties = (entries) => ({
  extension: [
    {
      type: 'extension_CdxPropertiesExtension',
      extension_cdxProperty: entries.map(([name, value]) => ({
        type: 'extension_CdxPropertyEntry',
        extension_cdxPropName: name,
        extension_cdxPropValue: String(value)
      }))
    }
  ]
});

const graph = [];
const relationships = [];
let relationshipSequence = 0;

function relationship(relationshipType, from, to, options = {}) {
  const targets = Array.isArray(to) ? to : [to];
  const relationshipClass = options.scope ? 'LifecycleScopedRelationship' : 'Relationship';
  const rel = element(
    relationshipClass,
    `relationship/${String(++relationshipSequence).padStart(3, '0')}-${slug(relationshipType)}`,
    {
      from,
      relationshipType,
      to: targets,
      ...options
    }
  );
  relationships.push(rel);
  return rel;
}

function linkAction(actionId, rels) {
  for (const [relationshipType, targets, options = {}] of rels) {
    if (targets && (Array.isArray(targets) ? targets.length : true)) {
      relationship(relationshipType, actionId, targets, options);
    }
  }
}

function scoped(type, from, to, scope, properties = {}) {
  return relationship(type, from, to, { scope, ...properties });
}

const organizations = [
  [
    'arbor-devices',
    'Arbor Devices, Inc. (fictional)',
    'Fictional secure industrial gateway producer and SBOM author.'
  ],
  [
    'siliconforge',
    'SiliconForge Components (fictional)',
    'Fictional supplier of compute modules and secure elements.'
  ],
  [
    'boardfab',
    'BoardFab EMS Malaysia (fictional)',
    'Fictional electronics manufacturing services partner.'
  ],
  [
    'secureseal',
    'SecureSeal Enclosures (fictional)',
    'Fictional enclosure and tamper-seal manufacturer.'
  ],
  [
    'futura-logistics',
    'Futura Logistics (fictional)',
    'Fictional carrier providing custody, storage, and lane telemetry.'
  ],
  [
    'assurance-lab',
    'Independent Assurance Lab Denver (fictional)',
    'Fictional receiving inspection and security test laboratory.'
  ],
  [
    'edgeops',
    'EdgeOps Energy (fictional)',
    'Fictional operator deploying the gateway at an industrial site.'
  ],
  [
    'circular-recoveries',
    'Circular Recoveries LLC (fictional)',
    'Fictional recycling and secure-destruction partner.'
  ]
].map(([key, name, summary]) =>
  element('Organization', `agent/org/${key}`, {
    name,
    summary,
    externalIdentifier: [externalId(`${key}@example.invalid`, 'Synthetic contact address')]
  })
);

const orgId = Object.fromEntries(
  organizations.map((org) => [org.spdxId.split('/').pop(), org.spdxId])
);

const people = [
  ['mira-patel', 'Mira Patel', 'Supply-chain security lead'],
  ['owen-ross', 'Owen Ross', 'Manufacturing quality engineer'],
  ['nina-cho', 'Nina Cho', 'Logistics coordinator'],
  ['samir-ali', 'Samir Ali', 'Receiving inspection lead'],
  ['claire-dubois', 'Claire Dubois', 'Product security engineer']
].map(([key, name, role]) =>
  element('Person', `agent/person/${key}`, {
    name,
    summary: `${role} in the fictional ArborLink SG-1 program.`,
    externalIdentifier: [
      externalId(`${key}@arbor.example.invalid`, 'Synthetic person contact address')
    ]
  })
);

const personId = Object.fromEntries(
  people.map((person) => [person.spdxId.split('/').pop(), person.spdxId])
);

const tools = [
  element('Tool', 'tool/synthetic-supply-chain-generator', {
    name: 'Synthetic SPDX 3.1 SupplyChain sample generator',
    version: '1.0.0',
    summary: 'Deterministic generator for the ArborLink SG-1 synthetic supply-chain sample.'
  }),
  element('Tool', 'tool/syft', {
    name: 'Syft',
    version: '1.28.0',
    summary: 'Container and filesystem SBOM scanner used in the fictional build pipeline.',
    externalRef: [
      {
        type: 'ExternalRef',
        externalRefType: 'altWebPage',
        locator: ['https://github.com/anchore/syft']
      }
    ]
  }),
  element('Tool', 'tool/trivy', {
    name: 'Trivy',
    version: '0.63.0',
    summary: 'Vulnerability scanner used to enrich the fictional release SBOM.',
    externalRef: [
      {
        type: 'ExternalRef',
        externalRefType: 'altWebPage',
        locator: ['https://github.com/aquasecurity/trivy']
      }
    ]
  }),
  element('Tool', 'tool/slsa-provenance-generator', {
    name: 'SLSA provenance generator',
    version: '2.1.0',
    summary:
      'Build provenance emitter used to model where, when, and how release artifacts were produced.',
    externalRef: [
      {
        type: 'ExternalRef',
        externalRefType: 'documentation',
        locator: ['https://slsa.dev/spec/v1.2/build-provenance']
      }
    ]
  }),
  element('Tool', 'tool/in-toto-run', {
    name: 'in-toto-run',
    version: '3.0.0',
    summary:
      'Link metadata capture tool used in the fictional provisioning and acceptance workflow.',
    externalRef: [
      { type: 'ExternalRef', externalRefType: 'documentation', locator: ['https://in-toto.io/'] }
    ]
  }),
  element('Tool', 'tool/secure-boot-attester', {
    name: 'SG-1 secure-boot attester',
    version: '2026.07',
    summary:
      'Fictional factory and receiving-lab attestation tool for secure boot, signer, and tamper state.'
  })
];

const toolId = Object.fromEntries(tools.map((tool) => [tool.spdxId.split('/').pop(), tool.spdxId]));

const locations = [
  ['loc/hq', 'Arbor Devices supply-chain control tower', 'Austin', 'TX', 'USA'],
  ['loc/final-assembly', 'Arbor Devices final assembly cell A3', 'Austin', 'TX', 'USA'],
  ['loc/siliconforge-hsinchu', 'SiliconForge Hsinchu secure element line', 'Hsinchu', '', 'TWN'],
  ['loc/boardfab-penang', 'BoardFab Penang SMT line 7', 'Penang', '', 'MYS'],
  ['loc/secureseal-ohio', 'SecureSeal enclosure plant', 'Dayton', 'OH', 'USA'],
  ['loc/austin-warehouse', 'Futura Austin secure staging warehouse', 'Austin', 'TX', 'USA'],
  ['loc/lax-hub', 'Futura LAX air-freight hub', 'Los Angeles', 'CA', 'USA'],
  ['loc/denver-lab', 'Independent Assurance Lab receiving bay', 'Denver', 'CO', 'USA'],
  ['loc/wyoming-site', 'EdgeOps Red Mesa wind-farm substation', 'Rawlins', 'WY', 'USA'],
  ['loc/phoenix-recovery', 'Circular Recoveries secure destruction room', 'Phoenix', 'AZ', 'USA']
].map(([fragment, name, city, provinceStateCode, country]) =>
  element('PhysicalLocation', fragment, {
    name,
    city,
    ...(provinceStateCode ? { provinceStateCode } : {}),
    country,
    locationHint: name
  })
);

const loc = Object.fromEntries(
  locations.map((location) => [location.spdxId.split('#')[1], location.spdxId])
);

const specifications = [
  element('Specification', 'spec/nist-sp-800-161r1', {
    name: 'NIST SP 800-161 Rev. 1 C-SCRM reference',
    summary: 'Reference for supply-chain risk management concepts used by this synthetic sample.',
    specType: 'formalStandard',
    externalRef: [
      {
        type: 'ExternalRef',
        externalRefType: 'documentation',
        locator: ['https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final']
      }
    ]
  }),
  element('Specification', 'spec/cisa-2025-sbom-min-elements', {
    name: 'CISA 2025 SBOM Minimum Elements reference',
    summary:
      'Reference for hashes, licensing, tool name, generation context, and delivery practices.',
    specType: 'guidance',
    externalRef: [
      {
        type: 'ExternalRef',
        externalRefType: 'documentation',
        locator: [
          'https://www.cisa.gov/resources-tools/resources/2025-minimum-elements-software-bill-materials-sbom'
        ]
      }
    ]
  }),
  element('Specification', 'spec/slsa-provenance-v1-2', {
    name: 'SLSA v1.2 Build Provenance reference',
    summary:
      'Reference for build provenance describing where, when, and how software artifacts were produced.',
    specType: 'guidance',
    externalRef: [
      {
        type: 'ExternalRef',
        externalRefType: 'documentation',
        locator: ['https://slsa.dev/spec/v1.2/build-provenance']
      }
    ]
  }),
  element('Specification', 'spec/arborlink-supply-chain-plan', {
    name: 'ArborLink SG-1 supply-chain assurance plan ASCAP-2026.07',
    summary:
      'Fictional plan defining procurement, custody, exception handling, and acceptance gates.',
    specType: 'specification',
    externalIdentifier: [externalId('ASCAP-2026.07', 'Fictional supply-chain assurance plan')]
  })
];

const specId = Object.fromEntries(
  specifications.map((spec) => [spec.spdxId.split('/').pop(), spec.spdxId])
);

const requirements = [
  [
    'req/provenance',
    'SCRM-REQ-01 provenance',
    'Every critical hardware and software component shall carry origin, supplier, generation tool, and integrity metadata.'
  ],
  [
    'req/custody',
    'SCRM-REQ-02 chain of custody',
    'Every custody and ownership transfer shall record previous/current responsible parties, product, time window, and location.'
  ],
  [
    'req/tamper',
    'SCRM-REQ-03 tamper handling',
    'Any shipment shock, seal, signer, or secure-boot deviation shall enter quarantine until independent resolution.'
  ],
  [
    'req/signed-firmware',
    'SCRM-REQ-04 signed firmware',
    'Production firmware shall be built from controlled inputs, signed by the release signer, and verified during provisioning and receiving inspection.'
  ],
  [
    'req/sbom-delivery',
    'SCRM-REQ-05 SBOM delivery',
    'The delivered device shall include a machine-readable SBOM with component hashes, licenses, tools, and generation context.'
  ],
  [
    'req/decommission',
    'SCRM-REQ-06 decommissioning',
    'End-of-life planning shall preserve custody, data-erasure evidence, and secure-destruction accountability.'
  ]
].map(([fragment, name, statement]) =>
  element('Requirement', fragment, {
    name,
    requirementStatement: statement,
    requirementUID: name.split(' ')[0],
    summary: 'Fictional supply-chain assurance requirement for the ArborLink SG-1 sample.'
  })
);

const reqId = Object.fromEntries(
  requirements.map((req) => [req.spdxId.split('/').pop(), req.spdxId])
);

const licenseExpressions = [
  element('simplelicensing_LicenseExpression', 'license/mit', {
    name: 'MIT license expression',
    simplelicensing_licenseExpression: 'MIT',
    simplelicensing_licenseListVersion: '3.26'
  }),
  element('simplelicensing_LicenseExpression', 'license/apache-2.0', {
    name: 'Apache-2.0 license expression',
    simplelicensing_licenseExpression: 'Apache-2.0',
    simplelicensing_licenseListVersion: '3.26'
  }),
  element('simplelicensing_LicenseExpression', 'license/gpl-2.0-only', {
    name: 'GPL-2.0-only license expression',
    simplelicensing_licenseExpression: 'GPL-2.0-only',
    simplelicensing_licenseListVersion: '3.26'
  }),
  element('simplelicensing_LicenseExpression', 'license/proprietary', {
    name: 'LicenseRef-Arbor-Proprietary expression',
    simplelicensing_licenseExpression: 'LicenseRef-Arbor-Proprietary',
    simplelicensing_licenseListVersion: '3.26'
  })
];

const licenseId = Object.fromEntries(
  licenseExpressions.map((license) => [license.spdxId.split('/').pop(), license.spdxId])
);

const productSpec = element('hardware_ProductSpecification', 'hardware/spec/sg1', {
  name: 'ArborLink SG-1 secure industrial edge gateway specification',
  summary:
    'Fictional product specification for a DIN-rail industrial gateway with secure boot, TPM-backed identity, and tamper evidence.',
  hardware_partNumber: 'ARB-SG1-IND-4G-POE',
  hardware_category: 'industrial edge gateway'
});

const dimensions = element('hardware_Dimensions', 'hardware/dimensions/sg1', {
  name: 'ArborLink SG-1 envelope dimensions',
  hardware_xAxisLength: { type: 'MeasureOfLength', quantity: 156, unitQUDT: 'MilliM' },
  hardware_yAxisLength: { type: 'MeasureOfLength', quantity: 124, unitQUDT: 'MilliM' },
  hardware_zAxisLength: { type: 'MeasureOfLength', quantity: 48, unitQUDT: 'MilliM' }
});

const hardware = [
  productSpec,
  dimensions,
  element('hardware_PhysicalHardware', 'hardware/device/sg1-sn-26-000042', {
    name: 'ArborLink SG-1 gateway SN SG1-26-000042',
    summary:
      'Serialized finished device tracked across assembly, transport, quarantine, resolution, delivery, deployment, and retirement planning.',
    hardware_partNumber: 'ARB-SG1-IND-4G-POE',
    hardware_serialNumber: 'SG1-26-000042',
    hardware_category: 'finished device',
    hardware_productAgent: [orgId['arbor-devices']],
    hardware_dimensions: dimensions.spdxId,
    hardware_mass: { type: 'MeasureOfMass', quantity: 0.84, unitQUDT: 'KiloGM' },
    verifiedUsing: [hash('hardware/device/sg1-sn-26-000042')]
  }),
  element('hardware_BulkHardware', 'hardware/lot/pcba-26-07-a17', {
    name: 'SG-1 PCB assembly lot PCBA-26-07-A17',
    summary: 'Fictional SMT assembly lot containing SG-1 controller boards.',
    hardware_partNumber: 'ARB-SG1-PCBA-REV-C',
    hardware_batchNumber: 'PCBA-26-07-A17',
    hardware_bulkQuantity: 240,
    hardware_category: 'printed circuit board assembly',
    hardware_productAgent: [orgId.boardfab],
    verifiedUsing: [hash('hardware/lot/pcba-26-07-a17')]
  }),
  element('hardware_BulkHardware', 'hardware/lot/compute-module-cm7-26h1', {
    name: 'Compute module lot CM7-26H1',
    summary: 'Fictional compute-module lot with lot-level supplier attestation.',
    hardware_partNumber: 'SFC-CM7-8G-IND',
    hardware_batchNumber: 'CM7-26H1',
    hardware_bulkQuantity: 500,
    hardware_category: 'compute module',
    hardware_productAgent: [orgId.siliconforge],
    verifiedUsing: [hash('hardware/lot/compute-module-cm7-26h1')]
  }),
  element('hardware_BulkHardware', 'hardware/lot/secure-element-se9-26h1', {
    name: 'Secure element lot SE9-26H1',
    summary:
      'Fictional secure element lot carrying wafer, personalization, and certificate-chain references.',
    hardware_partNumber: 'SFC-SE9-TPM',
    hardware_batchNumber: 'SE9-26H1',
    hardware_bulkQuantity: 1000,
    hardware_category: 'secure element',
    hardware_productAgent: [orgId.siliconforge],
    verifiedUsing: [hash('hardware/lot/secure-element-se9-26h1')]
  }),
  element('hardware_BulkHardware', 'hardware/lot/enclosure-26-07-k2', {
    name: 'Powder-coated enclosure lot ENC-26-07-K2',
    summary: 'Fictional enclosure lot made from recycled aluminum feedstock.',
    hardware_partNumber: 'SSL-ENC-SG1-IP54',
    hardware_batchNumber: 'ENC-26-07-K2',
    hardware_bulkQuantity: 300,
    hardware_category: 'enclosure',
    hardware_productAgent: [orgId.secureseal],
    verifiedUsing: [hash('hardware/lot/enclosure-26-07-k2')]
  }),
  element('hardware_PhysicalHardware', 'hardware/tamper-seal/ts-9f42', {
    name: 'Tamper-evident seal TS-9F42',
    summary:
      'Serialized tamper seal affixed after provisioning and checked at receiving inspection.',
    hardware_partNumber: 'SSL-TAMPER-VOID-13',
    hardware_serialNumber: 'TS-9F42',
    hardware_category: 'tamper evidence',
    hardware_productAgent: [orgId.secureseal],
    verifiedUsing: [hash('hardware/tamper-seal/ts-9f42')]
  })
];

const hwId = Object.fromEntries(hardware.map((hw) => [hw.spdxId.split('/').pop(), hw.spdxId]));

const packages = [
  [
    'pkg/firmware',
    'ArborLink SG-1 firmware image',
    '2026.07.0',
    'firmware',
    'pkg:generic/arbor/arborlink-sg1-firmware@2026.07.0',
    orgId['arbor-devices'],
    licenseId.proprietary
  ],
  [
    'pkg/bootloader',
    'SentinelBoot secure bootloader',
    '3.4.2',
    'firmware',
    'pkg:generic/arbor/sentinelboot@3.4.2',
    orgId['arbor-devices'],
    licenseId.proprietary
  ],
  [
    'pkg/linux-image',
    'Arbor industrial Linux image',
    '6.12.31-arbor1',
    'operatingSystem',
    'pkg:generic/arbor/industrial-linux@6.12.31-arbor1',
    orgId['arbor-devices'],
    licenseId['gpl-2.0-only']
  ],
  [
    'pkg/gateway-agent',
    'Arbor gateway-agent container',
    '2026.07.0',
    'container',
    'pkg:oci/gateway-agent@sha256:8d6d8bf8b56a91dbb70f4ca2e2efb4d3',
    orgId['arbor-devices'],
    licenseId.proprietary
  ],
  [
    'pkg/openssl',
    'OpenSSL',
    '3.5.1',
    'library',
    'pkg:generic/openssl@3.5.1',
    'https://spdx.org/rdf/3.1/terms/Core/NoAssertionElement',
    licenseId['apache-2.0']
  ],
  [
    'pkg/busybox',
    'BusyBox',
    '1.37.0',
    'application',
    'pkg:generic/busybox@1.37.0',
    'https://spdx.org/rdf/3.1/terms/Core/NoAssertionElement',
    licenseId['gpl-2.0-only']
  ],
  [
    'pkg/libmosquitto',
    'Eclipse Mosquitto client library',
    '2.0.22',
    'library',
    'pkg:generic/eclipse/mosquitto@2.0.22',
    'https://spdx.org/rdf/3.1/terms/Core/NoAssertionElement',
    licenseId['epl-2.0'] || licenseId.mit
  ]
].map(([fragment, name, version, purpose, purl, supplier, _declaredLicense]) =>
  element('software_Package', fragment, {
    name,
    software_packageVersion: version,
    software_primaryPurpose: purpose,
    software_packageUrl: purl,
    suppliedBy: [supplier],
    verifiedUsing: [hash(fragment)],
    summary: `${name} included in the fictional ArborLink SG-1 software bill of materials.`,
    externalIdentifier: [
      externalId(purl, 'Package URL identifier', 'https://github.com/package-url/purl-spec')
    ]
  })
);

const pkgId = Object.fromEntries(packages.map((pkg) => [pkg.spdxId.split('/').pop(), pkg.spdxId]));

const files = [
  [
    'file/release/firmware-swu',
    'dist/arborlink-sg1-2026.07.0.swu',
    'firmware',
    'application/octet-stream',
    29360128
  ],
  [
    'file/release/gateway-agent-oci',
    'dist/gateway-agent-2026.07.0-linux-arm64.oci.tar',
    'container',
    'application/vnd.oci.image.manifest.v1+json',
    73400320
  ],
  [
    'file/build/slsa-provenance',
    'attestations/arborlink-sg1-2026.07.0.intoto.jsonl',
    'evidence',
    'application/vnd.in-toto+json',
    32768
  ],
  [
    'file/build/sbom-generation-log',
    'evidence/sbom-generation-log.json',
    'evidence',
    'application/json',
    12044
  ],
  [
    'file/supply-chain/component-coc',
    'evidence/component-chain-of-custody.pdf',
    'evidence',
    'application/pdf',
    258901
  ],
  [
    'file/supply-chain/shock-telemetry',
    'evidence/futura-shock-telemetry-SG1-26-000042.csv',
    'evidence',
    'text/csv',
    18421
  ],
  [
    'file/supply-chain/inspection-record',
    'evidence/receiving-inspection-SG1-26-000042.pdf',
    'evidence',
    'application/pdf',
    384122
  ],
  [
    'file/supply-chain/secure-boot-test',
    'evidence/secure-boot-attestation-SG1-26-000042.json',
    'evidence',
    'application/json',
    19008
  ],
  [
    'file/supply-chain/resolution-record',
    'evidence/quarantine-resolution-SG1-26-000042.pdf',
    'evidence',
    'application/pdf',
    204944
  ],
  [
    'file/supply-chain/acceptance-pack',
    'delivery/arborlink-sg1-acceptance-pack.zip',
    'archive',
    'application/zip',
    8126464
  ],
  [
    'file/config/build-recipe',
    '.github/workflows/release-gateway.yml',
    'configuration',
    'text/yaml',
    9544
  ],
  [
    'file/config/provisioning-manifest',
    'factory/provisioning-manifest-SG1-26-000042.json',
    'configuration',
    'application/json',
    7422
  ],
  [
    'file/config/retirement-plan',
    'operations/retirement-plan-SG1-26-000042.md',
    'documentation',
    'text/markdown',
    6112
  ]
].map(([fragment, name, purpose, contentType, size]) =>
  element('software_File', fragment, {
    name,
    software_primaryPurpose: purpose,
    contentType,
    software_artifactSize: size,
    verifiedUsing: [hash(fragment)],
    summary: `Synthetic ${purpose} artifact for the ArborLink SG-1 supply-chain sample.`
  })
);

const fileId = Object.fromEntries(files.map((file) => [file.spdxId.split('/').pop(), file.spdxId]));

const build = element('build_Build', 'build/release-2026-07-0', {
  name: 'ArborLink SG-1 release build 2026.07.0',
  build_buildId: 'github-actions/arborlink-gateway/release/2026.07.0/run/884211',
  build_buildType: 'https://slsa.dev/container-based-build/v1',
  build_buildStartTime: '2026-07-01T14:20:00Z',
  build_buildEndTime: '2026-07-01T14:44:31Z',
  build_configSourceUri:
    'git+https://example.invalid/arbor/arborlink-gateway.git@refs/tags/v2026.07.0',
  build_configSourceDigest: [hash('git-tag-v2026.07.0')],
  build_configSourceEntrypoint: '.github/workflows/release-gateway.yml',
  build_environment: [
    {
      type: 'DictionaryEntry',
      key: 'runner:image',
      value: 'ubuntu-26.04-arm64-secure-build-20260615'
    },
    { type: 'DictionaryEntry', key: 'slsa:build-level', value: 'L3-like controls (synthetic)' },
    {
      type: 'DictionaryEntry',
      key: 'signing:key-policy',
      value: 'offline HSM release signer ARB-SIGN-2026-07'
    }
  ],
  build_parameter: [
    { type: 'DictionaryEntry', key: 'target:hardware', value: 'ARB-SG1-IND-4G-POE' },
    { type: 'DictionaryEntry', key: 'secure-boot:enforced', value: 'true' },
    { type: 'DictionaryEntry', key: 'sbom:format', value: 'SPDX-3.1 JSON-LD' }
  ],
  verifiedUsing: [hash('build/release-2026-07-0')]
});

const states = [
  [
    'state/received',
    'Components received',
    'Critical component lots are received and awaiting incoming inspection.'
  ],
  [
    'state/assembled',
    'Assembled',
    'The serialized gateway has been mechanically and electrically assembled.'
  ],
  [
    'state/provisioned',
    'Firmware provisioned',
    'Signed firmware, device identity, and tamper seal are provisioned.'
  ],
  [
    'state/in-transit',
    'In transit',
    'The gateway is under carrier custody and moving between controlled locations.'
  ],
  [
    'state/quarantine',
    'Out-of-spec quarantine',
    'The gateway is isolated because shock telemetry exceeded the lane threshold.'
  ],
  [
    'state/inspection-passed',
    'Inspection passed',
    'Independent receiving inspection found no tamper or integrity deviation.'
  ],
  [
    'state/accepted',
    'Accepted for deployment',
    'Customer acceptance is complete and custody has transferred to the operator.'
  ],
  ['state/deployed', 'Deployed', 'The gateway is installed at the EdgeOps Red Mesa site.'],
  [
    'state/retirement-planned',
    'Retirement planned',
    'End-of-life custody, data erasure, and destruction path are defined.'
  ]
].map(([fragment, name, description]) =>
  element('supplychain_State', fragment, {
    name,
    description,
    summary: description
  })
);

const stateId = Object.fromEntries(
  states.map((state) => [state.spdxId.split('/').pop(), state.spdxId])
);

const processes = [
  [
    'supplychain_BoundaryDefinitionProcess',
    'process/define-custody-boundary',
    'Define shipment custody boundary',
    'Defines product, evidence, location, and telemetry criteria for each custody boundary.'
  ],
  [
    'supplychain_HarvestProcess',
    'process/recycled-aluminum-intake',
    'Recycled aluminum intake process',
    'Captures the enclosure feedstock intake and batch evidence.'
  ],
  [
    'supplychain_ManufactureProcess',
    'process/critical-component-manufacture',
    'Critical component manufacture process',
    'Manufactures and attests compute-module, secure-element, PCBA, and enclosure lots.'
  ],
  [
    'supplychain_AssemblyProcess',
    'process/final-assembly',
    'Final assembly process',
    'Assembles serialized gateway hardware from qualified component lots.'
  ],
  [
    'supplychain_ReproduceProcess',
    'process/release-bundle-reproduction',
    'Release bundle reproduction process',
    'Reproduces the signed release bundle into the factory provisioning cache.'
  ],
  [
    'supplychain_ChangeProcess',
    'process/factory-provisioning',
    'Factory provisioning process',
    'Installs signed firmware, device identity, and production configuration.'
  ],
  [
    'supplychain_StorageProcess',
    'process/secure-staging-storage',
    'Secure staging storage process',
    'Stores provisioned units with seal and environmental monitoring before shipment.'
  ],
  [
    'supplychain_TransportProcess',
    'process/controlled-lane-transport',
    'Controlled-lane transport process',
    'Moves devices between approved locations with custody and shock telemetry.'
  ],
  [
    'supplychain_ResponsibilityChangeProcess',
    'process/custody-transfer',
    'Custody and ownership transfer process',
    'Records previous/current responsible parties and products affected by responsibility change.'
  ],
  [
    'supplychain_InspectionProcess',
    'process/receiving-inspection',
    'Receiving inspection process',
    'Performs visual tamper, seal, serial, and evidence package inspection.'
  ],
  [
    'supplychain_TestProcess',
    'process/secure-boot-acceptance-test',
    'Secure-boot acceptance test process',
    'Verifies firmware hash, signer, secure boot, and device identity at receiving.'
  ],
  [
    'supplychain_DefinedStateProcess',
    'process/quarantine-decision',
    'Quarantine decision process',
    'Maps telemetry and inspection evidence to accepted, quarantined, or rejected states.'
  ],
  [
    'supplychain_PlanProcess',
    'process/decommission-plan',
    'Decommissioning plan process',
    'Plans data erasure, secure destruction, recycling, and custody evidence.'
  ],
  [
    'supplychain_DestroyProcess',
    'process/secure-destruction',
    'Secure destruction process',
    'Destroys retired tamper seals and storage media under controlled evidence capture.'
  ]
].map(([type, fragment, name, description]) =>
  element(type, fragment, {
    name,
    description,
    processReadiness: 'operational',
    summary: description
  })
);

const processId = Object.fromEntries(
  processes.map((process) => [process.spdxId.split('/').pop(), process.spdxId])
);

const actions = [];
function action(type, fragment, props, rels) {
  const actionEl = element(type, fragment, props);
  actions.push(actionEl);
  linkAction(actionEl.spdxId, rels || []);
  return actionEl;
}

action(
  'supplychain_BoundaryDefinitionAction',
  'action/001-define-shipment-boundary',
  {
    name: 'Define SG-1 shipment custody boundary',
    startTime: '2026-06-28T09:00:00Z',
    endTime: '2026-06-28T10:30:00Z',
    actionLocation: loc['loc/hq'],
    supplychain_boundaryParameter: reqId.custody,
    summary:
      'Defines the custody boundary: serialized device, tamper seal, evidence package, telemetry logger, and accepted lane limits.'
  },
  [
    ['performedBy', [personId['mira-patel'], orgId['arbor-devices']]],
    ['hasRequirement', [reqId.custody, reqId.tamper]],
    ['conformsTo', [specId['arborlink-supply-chain-plan'], specId['nist-sp-800-161r1']]]
  ]
);

action(
  'supplychain_HarvestAction',
  'action/002-recycled-aluminum-intake',
  {
    name: 'Intake recycled aluminum feedstock for enclosure lot',
    startTime: '2026-06-29T08:00:00Z',
    endTime: '2026-06-29T11:20:00Z',
    actionLocation: loc['loc/secureseal-ohio'],
    summary: 'Records recycled aluminum feedstock intake before enclosure manufacture.'
  },
  [
    ['performedBy', [orgId.secureseal]],
    ['hasOutput', [hwId['enclosure-26-07-k2']], { scope: 'build' }],
    ['hasRequirement', [reqId.provenance]],
    ['hasEvidence', [fileId['component-coc']]]
  ]
);

action(
  'supplychain_ManufactureAction',
  'action/003-manufacture-critical-lots',
  {
    name: 'Manufacture attested compute and secure-element lots',
    startTime: '2026-06-30T02:00:00Z',
    endTime: '2026-06-30T18:45:00Z',
    actionLocation: loc['loc/siliconforge-hsinchu'],
    summary: 'Creates supplier-attested component lots that feed the SG-1 assembly.'
  },
  [
    ['performedBy', [orgId.siliconforge]],
    [
      'hasOutput',
      [hwId['compute-module-cm7-26h1'], hwId['secure-element-se9-26h1']],
      { scope: 'build' }
    ],
    ['hasRequirement', [reqId.provenance]],
    ['hasEvidence', [fileId['component-coc']]]
  ]
);

action(
  'supplychain_ManufactureAction',
  'action/004-manufacture-pcba-lot',
  {
    name: 'Manufacture SG-1 PCBA lot',
    startTime: '2026-07-01T01:00:00Z',
    endTime: '2026-07-01T13:20:00Z',
    actionLocation: loc['loc/boardfab-penang'],
    summary:
      'Assembles controller boards with lot-level traceability to critical supplied components.'
  },
  [
    ['performedBy', [orgId.boardfab]],
    [
      'hasInput',
      [hwId['compute-module-cm7-26h1'], hwId['secure-element-se9-26h1']],
      { scope: 'build' }
    ],
    ['hasOutput', [hwId['pcba-26-07-a17']], { scope: 'build' }],
    ['hasRequirement', [reqId.provenance]],
    ['hasEvidence', [fileId['component-coc']]]
  ]
);

action(
  'supplychain_CreateAction',
  'action/005-create-release-artifacts',
  {
    name: 'Create signed SG-1 release artifacts',
    startTime: '2026-07-01T14:20:00Z',
    endTime: '2026-07-01T14:44:31Z',
    actionLocation: loc['loc/hq'],
    summary:
      'Creates the release firmware, container image, SBOM log, and SLSA-style provenance attestation.'
  },
  [
    ['performedBy', [orgId['arbor-devices'], toolId['slsa-provenance-generator']]],
    ['usesTool', [toolId.syft, toolId.trivy, toolId['slsa-provenance-generator']]],
    [
      'hasOutput',
      [
        fileId['firmware-swu'],
        fileId['gateway-agent-oci'],
        fileId['slsa-provenance'],
        fileId['sbom-generation-log']
      ],
      { scope: 'build' }
    ],
    ['hasRequirement', [reqId['signed-firmware'], reqId['sbom-delivery']]],
    ['conformsTo', [specId['slsa-provenance-v1-2'], specId['cisa-2025-sbom-min-elements']]]
  ]
);

action(
  'supplychain_AssemblyAction',
  'action/006-final-assembly',
  {
    name: 'Assemble ArborLink SG-1 SN SG1-26-000042',
    startTime: '2026-07-02T15:00:00Z',
    endTime: '2026-07-02T18:10:00Z',
    actionLocation: loc['loc/final-assembly'],
    summary: 'Builds the serialized finished gateway from qualified component lots.'
  },
  [
    ['performedBy', [orgId['arbor-devices'], personId['owen-ross']]],
    ['hasInput', [hwId['pcba-26-07-a17'], hwId['enclosure-26-07-k2']], { scope: 'build' }],
    ['hasOutput', [hwId['sg1-sn-26-000042']], { scope: 'build' }],
    ['hasRequirement', [reqId.provenance]],
    ['hasEvidence', [fileId['component-coc']]]
  ]
);

action(
  'supplychain_ReproduceAction',
  'action/007-reproduce-release-bundle',
  {
    name: 'Reproduce release bundle into factory cache',
    startTime: '2026-07-02T18:20:00Z',
    endTime: '2026-07-02T18:45:00Z',
    actionLocation: loc['loc/final-assembly'],
    summary: 'Copies the signed release bundle to the provisioning station with hash verification.'
  },
  [
    ['performedBy', [toolId['in-toto-run'], orgId['arbor-devices']]],
    [
      'hasInput',
      [fileId['firmware-swu'], fileId['gateway-agent-oci'], fileId['slsa-provenance']],
      { scope: 'build' }
    ],
    ['hasOutput', [fileId['provisioning-manifest']], { scope: 'build' }],
    ['hasRequirement', [reqId['signed-firmware']]],
    ['hasEvidence', [fileId['slsa-provenance']]]
  ]
);

action(
  'supplychain_ChangeAction',
  'action/008-provision-firmware-and-seal',
  {
    name: 'Provision signed firmware, device identity, and tamper seal',
    startTime: '2026-07-02T19:00:00Z',
    endTime: '2026-07-02T19:36:00Z',
    actionLocation: loc['loc/final-assembly'],
    summary:
      'Changes the serialized device from assembled hardware to provisioned product ready for shipment.'
  },
  [
    ['performedBy', [orgId['arbor-devices'], toolId['secure-boot-attester']]],
    [
      'hasInput',
      [
        hwId['sg1-sn-26-000042'],
        hwId['ts-9f42'],
        fileId['firmware-swu'],
        fileId['gateway-agent-oci'],
        fileId['provisioning-manifest']
      ],
      { scope: 'build' }
    ],
    ['affects', [hwId['sg1-sn-26-000042'], hwId['ts-9f42']]],
    ['hasRequirement', [reqId['signed-firmware'], reqId.tamper]],
    ['hasEvidence', [fileId['secure-boot-test']]]
  ]
);

action(
  'supplychain_StateAction',
  'action/009-state-provisioned',
  {
    name: 'Mark device firmware provisioned',
    startTime: '2026-07-02T19:37:00Z',
    endTime: '2026-07-02T19:40:00Z',
    actionLocation: loc['loc/final-assembly'],
    supplychain_currentState: stateId.provisioned,
    supplychain_decisionProcess: processId['factory-provisioning'],
    summary: 'Records the state transition after successful provisioning and seal attachment.'
  },
  [
    ['performedBy', [personId['owen-ross']]],
    ['affects', [hwId['sg1-sn-26-000042']]],
    ['hasEvidence', [fileId['secure-boot-test']]]
  ]
);

action(
  'supplychain_StorageAction',
  'action/010-secure-staging-storage',
  {
    name: 'Store provisioned gateway in secure staging',
    startTime: '2026-07-02T20:00:00Z',
    endTime: '2026-07-03T07:45:00Z',
    actionLocation: loc['loc/austin-warehouse'],
    summary:
      'Stores the provisioned unit with seal inspection and environmental monitoring before shipment.'
  },
  [
    ['performedBy', [orgId['futura-logistics']]],
    ['affects', [hwId['sg1-sn-26-000042']]],
    ['hasRequirement', [reqId.custody, reqId.tamper]]
  ]
);

action(
  'supplychain_ResponsibilityChangeAction',
  'action/011-transfer-custody-to-carrier',
  {
    name: 'Transfer custody from Arbor Devices to Futura Logistics',
    startTime: '2026-07-03T08:00:00Z',
    endTime: '2026-07-03T08:20:00Z',
    actionLocation: loc['loc/austin-warehouse'],
    supplychain_previous: orgId['arbor-devices'],
    supplychain_current: orgId['futura-logistics'],
    supplychain_responsibilityChangedOn: hwId['sg1-sn-26-000042'],
    supplychain_responsibilityCategory: 'custody',
    summary: 'Records physical custody transfer at outbound pickup.'
  },
  [
    ['performedBy', [personId['nina-cho'], orgId['futura-logistics']]],
    ['hasRequirement', [reqId.custody]],
    ['hasEvidence', [fileId['component-coc']]]
  ]
);

action(
  'supplychain_BoundaryCrossingAction',
  'action/012-cross-factory-carrier-boundary',
  {
    name: 'Cross factory-to-carrier custody boundary',
    startTime: '2026-07-03T08:21:00Z',
    endTime: '2026-07-03T08:25:00Z',
    actionLocation: loc['loc/austin-warehouse'],
    summary: 'Device leaves Arbor controlled staging and enters carrier-controlled transport lane.'
  },
  [
    ['performedBy', [orgId['futura-logistics']]],
    ['affects', [hwId['sg1-sn-26-000042']]],
    ['hasRequirement', [reqId.custody]],
    ['hasEvidence', [fileId['component-coc']]]
  ]
);

action(
  'supplychain_TransportAction',
  'action/013-transport-austin-lax-denver',
  {
    name: 'Transport SG-1 from Austin through LAX to Denver receiving lab',
    startTime: '2026-07-03T08:30:00Z',
    endTime: '2026-07-04T17:10:00Z',
    actionLocation: loc['loc/austin-warehouse'],
    supplychain_pickupLocation: loc['loc/austin-warehouse'],
    supplychain_dropoffLocation: loc['loc/denver-lab'],
    supplychain_transportRoute:
      'Austin secure staging → LAX air-freight hub → Denver receiving lab',
    ...cdxProperties([
      ['arborlink:transport.mode', 'road+air+road'],
      ['arborlink:distance.km', '2380'],
      ['arborlink:co2e.kg', '186.4'],
      ['arborlink:co2e.method', 'Synthetic lane estimate from road/air distance factors']
    ]),
    summary: 'Controlled-lane shipment with carrier custody, shock telemetry, and evidence package.'
  },
  [
    ['performedBy', [orgId['futura-logistics']]],
    ['affects', [hwId['sg1-sn-26-000042']]],
    ['hasRequirement', [reqId.custody, reqId.tamper]],
    ['hasEvidence', [fileId['shock-telemetry']]]
  ]
);

const outOfSpec = action(
  'supplychain_OutOfSpecAction',
  'action/014-shock-excursion-out-of-spec',
  {
    name: 'Shock telemetry exceeds SG-1 shipment threshold',
    startTime: '2026-07-04T02:14:08Z',
    endTime: '2026-07-04T02:14:10Z',
    actionLocation: loc['loc/lax-hub'],
    summary:
      'Shock logger records 18.4 g for 14 ms, above the fictional 15 g lane threshold; product enters quarantine until resolved.'
  },
  [
    ['performedBy', [orgId['futura-logistics']]],
    ['affects', [hwId['sg1-sn-26-000042']]],
    ['hasRequirement', [reqId.tamper]],
    ['hasEvidence', [fileId['shock-telemetry']]]
  ]
);

action(
  'supplychain_StateAction',
  'action/015-state-quarantine',
  {
    name: 'Place SG-1 in out-of-spec quarantine',
    startTime: '2026-07-04T17:20:00Z',
    endTime: '2026-07-04T17:35:00Z',
    actionLocation: loc['loc/denver-lab'],
    supplychain_currentState: stateId.quarantine,
    supplychain_decisionProcess: processId['quarantine-decision'],
    summary: 'Independent lab holds the unit pending inspection and secure-boot acceptance testing.'
  },
  [
    ['performedBy', [orgId['assurance-lab'], personId['samir-ali']]],
    ['affects', [hwId['sg1-sn-26-000042']]],
    ['hasRequirement', [reqId.tamper]],
    ['hasEvidence', [fileId['shock-telemetry']]]
  ]
);

action(
  'supplychain_InspectionAction',
  'action/016-receiving-inspection',
  {
    name: 'Inspect seal, enclosure, serials, and evidence package',
    startTime: '2026-07-05T09:00:00Z',
    endTime: '2026-07-05T10:15:00Z',
    actionLocation: loc['loc/denver-lab'],
    summary:
      'Receiving inspection checks tamper seal, enclosure, serial numbers, custody records, and component evidence.'
  },
  [
    ['performedBy', [orgId['assurance-lab'], personId['samir-ali']]],
    ['affects', [hwId['sg1-sn-26-000042'], hwId['ts-9f42']]],
    ['hasRequirement', [reqId.tamper, reqId.custody]],
    ['hasEvidence', [fileId['inspection-record'], fileId['component-coc']]]
  ]
);

action(
  'supplychain_TestAction',
  'action/017-secure-boot-acceptance-test',
  {
    name: 'Run secure-boot and firmware-integrity acceptance test',
    startTime: '2026-07-05T10:30:00Z',
    endTime: '2026-07-05T11:20:00Z',
    actionLocation: loc['loc/denver-lab'],
    summary:
      'Verifies secure boot, release signer, firmware hash, device identity, and measured boot evidence after the shock excursion.'
  },
  [
    [
      'performedBy',
      [orgId['assurance-lab'], toolId['secure-boot-attester'], personId['claire-dubois']]
    ],
    ['usesTool', [toolId['secure-boot-attester'], toolId['in-toto-run']]],
    ['affects', [hwId['sg1-sn-26-000042'], fileId['firmware-swu']]],
    ['hasRequirement', [reqId['signed-firmware'], reqId.tamper]],
    ['hasEvidence', [fileId['secure-boot-test']]]
  ]
);

const resolution = action(
  'supplychain_ResolutionAction',
  'action/018-resolve-shock-excursion',
  {
    name: 'Resolve shipment shock excursion',
    startTime: '2026-07-05T12:00:00Z',
    endTime: '2026-07-05T13:05:00Z',
    actionLocation: loc['loc/denver-lab'],
    summary:
      'Independent lab accepts the unit after seal, enclosure, secure-boot, and firmware-integrity checks find no deviation.'
  },
  [
    ['performedBy', [orgId['assurance-lab'], personId['claire-dubois']]],
    ['resolved', [outOfSpec.spdxId]],
    ['hasResolution', [outOfSpec.spdxId]],
    ['affects', [hwId['sg1-sn-26-000042']]],
    ['hasRequirement', [reqId.tamper]],
    [
      'hasEvidence',
      [fileId['resolution-record'], fileId['inspection-record'], fileId['secure-boot-test']]
    ]
  ]
);

action(
  'supplychain_StateAction',
  'action/019-state-accepted',
  {
    name: 'Mark SG-1 accepted for deployment',
    startTime: '2026-07-05T13:15:00Z',
    endTime: '2026-07-05T13:25:00Z',
    actionLocation: loc['loc/denver-lab'],
    supplychain_currentState: stateId.accepted,
    supplychain_decisionProcess: processId['quarantine-decision'],
    summary: 'Records the state transition from quarantine to accepted-for-deployment.'
  },
  [
    ['performedBy', [orgId['assurance-lab']]],
    ['affects', [hwId['sg1-sn-26-000042']]],
    ['hasEvidence', [fileId['resolution-record']]]
  ]
);

action(
  'supplychain_ResponsibilityChangeAction',
  'action/020-transfer-ownership-to-edgeops',
  {
    name: 'Transfer ownership and custody to EdgeOps Energy',
    startTime: '2026-07-05T14:00:00Z',
    endTime: '2026-07-05T14:20:00Z',
    actionLocation: loc['loc/denver-lab'],
    supplychain_previous: orgId['futura-logistics'],
    supplychain_current: orgId.edgeops,
    supplychain_responsibilityChangedOn: hwId['sg1-sn-26-000042'],
    supplychain_responsibilityCategory: 'ownership',
    summary: 'Records customer acceptance and responsibility transfer after resolution.'
  },
  [
    ['performedBy', [orgId.edgeops, orgId['futura-logistics']]],
    ['hasRequirement', [reqId.custody]],
    ['hasEvidence', [fileId['acceptance-pack']]]
  ]
);

action(
  'supplychain_TransportAction',
  'action/021-transport-denver-wyoming',
  {
    name: 'Transport accepted SG-1 to EdgeOps Red Mesa site',
    startTime: '2026-07-05T15:00:00Z',
    endTime: '2026-07-06T08:40:00Z',
    actionLocation: loc['loc/denver-lab'],
    supplychain_pickupLocation: loc['loc/denver-lab'],
    supplychain_dropoffLocation: loc['loc/wyoming-site'],
    supplychain_transportRoute: 'Denver receiving lab → EdgeOps Red Mesa wind-farm substation',
    ...cdxProperties([
      ['arborlink:transport.mode', 'road'],
      ['arborlink:distance.km', '542'],
      ['arborlink:co2e.kg', '42.1'],
      ['arborlink:co2e.method', 'Synthetic road freight estimate for final-mile controlled lane']
    ]),
    summary: 'Final controlled-lane movement from acceptance lab to deployment site.'
  },
  [
    ['performedBy', [orgId.edgeops]],
    ['affects', [hwId['sg1-sn-26-000042']]],
    ['hasRequirement', [reqId.custody]],
    ['hasEvidence', [fileId['acceptance-pack']]]
  ]
);

action(
  'supplychain_UseAction',
  'action/022-commission-at-site',
  {
    name: 'Commission SG-1 at Red Mesa substation',
    startTime: '2026-07-06T09:00:00Z',
    endTime: '2026-07-06T10:30:00Z',
    actionLocation: loc['loc/wyoming-site'],
    summary: 'Installs and commissions the accepted gateway for operational telemetry ingestion.'
  },
  [
    ['performedBy', [orgId.edgeops]],
    ['affects', [hwId['sg1-sn-26-000042']]],
    ['hasRequirement', [reqId['sbom-delivery']]],
    ['hasEvidence', [fileId['acceptance-pack']]]
  ]
);

action(
  'supplychain_PlanAction',
  'action/023-plan-retirement',
  {
    name: 'Plan SG-1 retirement, erasure, and destruction path',
    startTime: '2026-07-06T10:45:00Z',
    endTime: '2026-07-06T11:15:00Z',
    actionLocation: loc['loc/wyoming-site'],
    summary:
      'Defines end-of-life custody, data erasure evidence, and destruction partner handoff before deployment begins.'
  },
  [
    ['performedBy', [orgId.edgeops, orgId['circular-recoveries']]],
    ['affects', [hwId['sg1-sn-26-000042']]],
    ['hasRequirement', [reqId.decommission]],
    ['hasOutput', [fileId['retirement-plan']]],
    ['conformsTo', [specId['arborlink-supply-chain-plan']]]
  ]
);

action(
  'supplychain_DestroyAction',
  'action/024-destroy-retired-tamper-seal',
  {
    name: 'Destroy removed factory tamper-seal coupon',
    startTime: '2026-07-06T11:20:00Z',
    endTime: '2026-07-06T11:28:00Z',
    actionLocation: loc['loc/wyoming-site'],
    supplychain_destructionPerformedBy: orgId.edgeops,
    summary:
      'Destroys the removed factory seal coupon after customer acceptance while preserving evidence for the device record.'
  },
  [
    ['performedBy', [orgId.edgeops]],
    ['affects', [hwId['ts-9f42']]],
    ['hasRequirement', [reqId.decommission]],
    ['hasEvidence', [fileId['retirement-plan']]]
  ]
);

action(
  'supplychain_StateAction',
  'action/025-state-deployed',
  {
    name: 'Mark SG-1 deployed with retirement plan',
    startTime: '2026-07-06T11:30:00Z',
    endTime: '2026-07-06T11:35:00Z',
    actionLocation: loc['loc/wyoming-site'],
    supplychain_currentState: stateId.deployed,
    supplychain_decisionProcess: processId['decommission-plan'],
    summary: 'Records operational deployment with an associated retirement plan.'
  },
  [
    ['performedBy', [orgId.edgeops]],
    ['affects', [hwId['sg1-sn-26-000042']]],
    ['hasEvidence', [fileId['acceptance-pack'], fileId['retirement-plan']]]
  ]
);

// Static product, software, build, and compliance relationships.
relationship('describes', id('sbom/arborlink-sg1'), hwId['sg1-sn-26-000042']);
relationship('contains', hwId['sg1-sn-26-000042'], [
  hwId['pcba-26-07-a17'],
  hwId['compute-module-cm7-26h1'],
  hwId['secure-element-se9-26h1'],
  hwId['enclosure-26-07-k2'],
  hwId['ts-9f42']
]);
relationship('runsOn', pkgId.firmware, hwId['sg1-sn-26-000042']);
relationship('runsOn', pkgId['gateway-agent'], hwId['sg1-sn-26-000042']);
scoped(
  'dependsOn',
  pkgId.firmware,
  [pkgId.bootloader, pkgId['linux-image'], pkgId.openssl, pkgId.busybox],
  'runtime'
);
scoped('dependsOn', pkgId['gateway-agent'], [pkgId.openssl, pkgId.libmosquitto], 'runtime');
scoped('hasDistributionArtifact', pkgId.firmware, fileId['firmware-swu'], 'build');
scoped('hasDistributionArtifact', pkgId['gateway-agent'], fileId['gateway-agent-oci'], 'build');
scoped('hasInput', build.spdxId, fileId['build-recipe'], 'build');
scoped(
  'hasOutput',
  build.spdxId,
  [
    fileId['firmware-swu'],
    fileId['gateway-agent-oci'],
    fileId['slsa-provenance'],
    fileId['sbom-generation-log']
  ],
  'build'
);
relationship('usesTool', build.spdxId, [
  toolId.syft,
  toolId.trivy,
  toolId['slsa-provenance-generator']
]);
relationship('hasDeclaredLicense', pkgId.firmware, licenseId.proprietary);
relationship('hasConcludedLicense', pkgId.firmware, licenseId.proprietary);
relationship('hasDeclaredLicense', pkgId['linux-image'], licenseId['gpl-2.0-only']);
relationship('hasDeclaredLicense', pkgId.openssl, licenseId['apache-2.0']);
relationship('hasDeclaredLicense', pkgId.busybox, licenseId['gpl-2.0-only']);
relationship('hasDeclaredLicense', pkgId.libmosquitto, licenseId.mit);
for (const req of requirements)
  relationship('conformsTo', req.spdxId, [specId['arborlink-supply-chain-plan']]);
relationship(
  'hasRequirement',
  hwId['sg1-sn-26-000042'],
  requirements.map((r) => r.spdxId)
);
relationship('hasEvidence', hwId['sg1-sn-26-000042'], [
  fileId['component-coc'],
  fileId['shock-telemetry'],
  fileId['inspection-record'],
  fileId['secure-boot-test'],
  fileId['resolution-record'],
  fileId['acceptance-pack']
]);

const vulnerability = element(
  'security_Vulnerability',
  'vulnerability/synthetic-openssl-config-hardening',
  {
    name: 'SYNTHETIC-SG1-OPENSSL-CONFIG-HARDENING',
    summary:
      'Synthetic vulnerability record used to exercise SPDX Security/VEX relationships. It does not correspond to a real CVE.',
    description:
      'A fictional OpenSSL configuration hardening advisory. SG-1 firmware is not affected because the vulnerable provider is not built into the image.',
    externalIdentifier: [
      externalId(
        'SYNTHETIC-SG1-OPENSSL-CONFIG-HARDENING',
        'Synthetic advisory identifier',
        'https://example.invalid/advisories/SYNTHETIC-SG1-OPENSSL-CONFIG-HARDENING'
      )
    ]
  }
);

const vex = element(
  'security_VexNotAffectedVulnAssessmentRelationship',
  'vex/openssl-config-not-affected',
  {
    from: vulnerability.spdxId,
    relationshipType: 'doesNotAffect',
    to: [pkgId.firmware, pkgId.openssl],
    security_justificationType: 'vulnerableCodeNotInExecutePath',
    security_impactStatement:
      'The fictional vulnerable OpenSSL provider is excluded from the ArborLink SG-1 image and not reachable at runtime.',
    security_impactStatementTime: '2026-07-01T16:20:00Z',
    security_statusNotes:
      'Synthetic VEX assessment generated to demonstrate enriched SBOM consumption.',
    security_vexVersion: '1.0'
  }
);

const cvss = element(
  'security_CvssV3VulnAssessmentRelationship',
  'vuln-assessment/openssl-config-cvss',
  {
    from: vulnerability.spdxId,
    relationshipType: 'affects',
    to: [pkgId.openssl],
    security_score: 7.1,
    security_severity: 'high',
    security_vectorString: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N'
  }
);

const sbom = element('software_Sbom', 'sbom/arborlink-sg1', {
  name: 'ArborLink SG-1 supply-chain, hardware, software, and security BOM',
  software_sbomType: ['design', 'build', 'deployed'],
  rootElement: [hwId['sg1-sn-26-000042'], pkgId.firmware, build.spdxId],
  summary:
    'Synthetic SPDX 3.1 sample demonstrating SupplyChain lifecycle actions integrated with Core, Hardware, Software, Build, Security, and SimpleLicensing data.'
});

const creationInfo = {
  type: 'CreationInfo',
  '@id': CREATION_INFO,
  specVersion: '3.1',
  created: CREATED,
  createdBy: [orgId['arbor-devices'], personId['mira-patel']],
  createdUsing: [toolId['synthetic-supply-chain-generator']],
  comment:
    'Synthetic, deterministic sample. No real product, shipment, person, or vulnerability is represented.'
};

const document = element('SpdxDocument', 'document', {
  name: 'ArborLink SG-1 synthetic SPDX 3.1 SupplyChain sample',
  dataLicense: 'https://spdx.org/licenses/CC0-1.0',
  namespaceMap: [{ type: 'NamespaceMap', prefix: 'arborlink', namespace: `${NS}#` }],
  profileConformance: [
    'core',
    'software',
    'hardware',
    'build',
    'security',
    'simpleLicensing',
    'supplyChain'
  ],
  rootElement: [sbom.spdxId, hwId['sg1-sn-26-000042']],
  summary:
    'Demonstrates SPDX 3.1 SupplyChain concepts across creation, transport, use, exception handling, resolution, and decommission planning.'
});

graph.push(
  document,
  creationInfo,
  ...organizations,
  ...people,
  ...tools,
  ...locations,
  ...specifications,
  ...requirements,
  ...licenseExpressions,
  ...hardware,
  ...packages,
  build,
  ...files,
  ...states,
  ...processes,
  ...actions,
  sbom,
  vulnerability,
  vex,
  cvss,
  ...relationships
);

function validateGraph() {
  const errors = [];
  const byId = new Map();
  for (const item of graph) {
    const key = item.spdxId || item['@id'];
    if (!key) {
      errors.push(`Element without spdxId/@id: ${JSON.stringify(item).slice(0, 120)}`);
      continue;
    }
    if (byId.has(key)) errors.push(`Duplicate id: ${key}`);
    byId.set(key, item);
  }

  const noAssertion = (value) => typeof value === 'string' && value.includes('NoAssertion');
  const checkRef = (owner, prop, value) => {
    if (!value || noAssertion(value) || /^https?:\/\/spdx\.org\/licenses\//.test(value)) return;
    if (!byId.has(value)) errors.push(`${owner} ${prop} references missing ${value}`);
  };
  const checkRefs = (owner, prop, value) => {
    if (Array.isArray(value)) value.forEach((v) => checkRef(owner, prop, v));
    else checkRef(owner, prop, value);
  };

  for (const item of graph) {
    const owner = item.spdxId || item['@id'];
    checkRefs(owner, 'creationInfo', item.creationInfo);
    checkRefs(owner, 'createdBy', item.createdBy);
    checkRefs(owner, 'createdUsing', item.createdUsing);
    checkRefs(owner, 'rootElement', item.rootElement);
    checkRefs(owner, 'from', item.from);
    checkRefs(owner, 'to', item.to);
    checkRefs(owner, 'suppliedBy', item.suppliedBy);
    checkRefs(owner, 'originatedBy', item.originatedBy);
    checkRefs(owner, 'hardware_productAgent', item.hardware_productAgent);
    checkRefs(owner, 'hardware_dimensions', item.hardware_dimensions);
    checkRefs(owner, 'actionLocation', item.actionLocation);
    checkRefs(owner, 'supplychain_pickupLocation', item.supplychain_pickupLocation);
    checkRefs(owner, 'supplychain_dropoffLocation', item.supplychain_dropoffLocation);
    checkRefs(owner, 'supplychain_boundaryParameter', item.supplychain_boundaryParameter);
    checkRefs(owner, 'supplychain_current', item.supplychain_current);
    checkRefs(owner, 'supplychain_previous', item.supplychain_previous);
    checkRefs(
      owner,
      'supplychain_responsibilityChangedOn',
      item.supplychain_responsibilityChangedOn
    );
    checkRefs(owner, 'supplychain_currentState', item.supplychain_currentState);
    checkRefs(owner, 'supplychain_decisionProcess', item.supplychain_decisionProcess);
    checkRefs(owner, 'supplychain_destructionPerformedBy', item.supplychain_destructionPerformedBy);
  }

  const actionTypes = new Set(actions.map((a) => a.type));
  for (const required of [
    'supplychain_AssemblyAction',
    'supplychain_ManufactureAction',
    'supplychain_TransportAction',
    'supplychain_ResponsibilityChangeAction',
    'supplychain_OutOfSpecAction',
    'supplychain_ResolutionAction',
    'supplychain_StateAction',
    'supplychain_PlanAction',
    'supplychain_DestroyAction'
  ]) {
    if (!actionTypes.has(required)) errors.push(`Missing representative action type ${required}`);
  }

  for (const a of actions) {
    if (!a.startTime) errors.push(`${a.spdxId} missing startTime`);
    if (!a.endTime) errors.push(`${a.spdxId} missing endTime`);
    if (!a.actionLocation) errors.push(`${a.spdxId} missing actionLocation`);
  }

  for (const a of actions.filter((item) => item.type === 'supplychain_TransportAction')) {
    if (!a.supplychain_pickupLocation) errors.push(`${a.spdxId} missing pickup location`);
    if (!a.supplychain_dropoffLocation) errors.push(`${a.spdxId} missing dropoff location`);
    if (!a.supplychain_transportRoute) errors.push(`${a.spdxId} missing route`);
  }

  for (const a of actions.filter(
    (item) => item.type === 'supplychain_ResponsibilityChangeAction'
  )) {
    for (const prop of [
      'supplychain_current',
      'supplychain_responsibilityChangedOn',
      'supplychain_responsibilityCategory',
      'startTime',
      'endTime'
    ]) {
      if (!a[prop]) errors.push(`${a.spdxId} missing ${prop}`);
    }
  }

  const resolutionRels = relationships.filter((rel) => rel.relationshipType === 'resolved');
  if (
    !resolutionRels.some(
      (rel) => rel.from === resolution.spdxId && rel.to.includes(outOfSpec.spdxId)
    )
  ) {
    errors.push('ResolutionAction does not resolve the OutOfSpecAction');
  }

  if (!document.profileConformance.includes('supplyChain')) {
    errors.push('SpdxDocument profileConformance does not include supplyChain');
  }

  if (errors.length) {
    throw new Error(
      `Supply-chain sample validation failed:\n${errors.map((e) => `- ${e}`).join('\n')}`
    );
  }
}

validateGraph();

const output = {
  '@context': 'https://spdx.github.io/spdx-spec/v3.1/rdf/spdx-context.jsonld',
  '@graph': graph
};

await mkdir(dirname(OUTPUT), { recursive: true });
await writeFile(OUTPUT, `${JSON.stringify(output, null, 2)}\n`);

const counts = graph.reduce((acc, item) => {
  acc[item.type] = (acc[item.type] || 0) + 1;
  return acc;
}, {});

console.log(`Wrote ${OUTPUT}`);
console.log(
  `Elements: ${graph.length}; actions: ${actions.length}; relationships: ${relationships.length}; states: ${states.length}; processes: ${processes.length}`
);
console.log(
  `SupplyChain action classes: ${Object.keys(counts)
    .filter((type) => type.startsWith('supplychain_') && type.endsWith('Action'))
    .sort()
    .join(', ')}`
);
