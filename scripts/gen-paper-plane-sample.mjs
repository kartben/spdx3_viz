import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUTPUT = resolve(ROOT, 'public/samples/paper-plane/paper-plane-supply-chain.spdx3.jsonld');
const NS = 'https://spdx.org/spdxdocs/paper-plane-supply-chain';
const CREATED = '2026-07-06T12:00:00Z';
const CREATION_INFO = '_:paper-plane-creation-info';

const id = (fragment) => `${NS}#${fragment}`;
const slug = (value) =>
  value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');

const digest = (value) => createHash('sha256').update(`paper-plane|${value}`).digest('hex');

const hash = (value) => ({
  type: 'Hash',
  algorithm: 'sha256',
  hashValue: digest(value)
});

const externalId = (identifier, comment, locator, authority = 'Origami Studio (fictional)') => ({
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

// 1. SpdxDocument & CreationInfo
const doc = {
  type: 'SpdxDocument',
  spdxId: `${NS}#document`,
  creationInfo: CREATION_INFO,
  name: 'Paper plane supply chain sample',
  dataLicense: 'https://spdx.org/licenses/CC0-1.0',
  namespaceMap: [
    {
      type: 'NamespaceMap',
      prefix: 'paperplane',
      namespace: `${NS}#`
    }
  ],
  profileConformance: ['core', 'hardware', 'simpleLicensing', 'supplyChain'],
  rootElement: [id('hardware/paper-airplane')],
  summary:
    'Demonstrates a minimalistic paper airplane supply chain tracking design, build, and test stages.'
};

const creationInfo = {
  type: 'CreationInfo',
  '@id': CREATION_INFO,
  specVersion: '3.1',
  created: CREATED,
  createdBy: [id('agent/person/alice-designer'), id('agent/org/origami-studio')],
  createdUsing: [id('tool/origami-cad-attester')],
  comment: 'Synthetic minimalistic paper plane sample.'
};

// 2. Agents (Organization, Persons, Tools)
const studio = element('Organization', 'agent/org/origami-studio', {
  name: 'Origami Studio (fictional)',
  summary: 'Fictional paper-folding craft studio and design house.',
  externalIdentifier: [externalId('studio@example.invalid', 'Synthetic contact address')]
});

const alice = element('Person', 'agent/person/alice-designer', {
  name: 'Alice',
  summary: 'Chief aeronautical folding architect in the fictional Origami program.',
  externalIdentifier: [externalId('alice@example.invalid', 'Synthetic person contact address')]
});

const bob = element('Person', 'agent/person/bob-folder', {
  name: 'Bob',
  summary: 'Expert folding builder in the fictional Origami program.',
  externalIdentifier: [externalId('bob@example.invalid', 'Synthetic person contact address')]
});

const charlie = element('Person', 'agent/person/charlie-pilot', {
  name: 'Charlie',
  summary: 'Test flight pilot in the fictional Origami program.',
  externalIdentifier: [externalId('charlie@example.invalid', 'Synthetic person contact address')]
});

const generatorTool = element('Tool', 'tool/origami-cad-attester', {
  name: 'Origami Flight-Spec CAD Tool & Folding Attester',
  version: '3.1.0',
  summary: 'Fictional design specification helper and folding validator tool.'
});

// 3. Locations
const locDesign = element('PhysicalLocation', 'loc/design-studio', {
  name: 'Paris Origami Design Lab',
  city: 'Paris',
  country: 'FRA',
  geographicPointLocation: ['+48.8566+002.3522/']
});

const locWorkshop = element('PhysicalLocation', 'loc/workshop', {
  name: 'London Folding Workshop',
  city: 'London',
  country: 'GBR',
  geographicPointLocation: ['+51.5074-000.1278/']
});

const locFlightZone = element('PhysicalLocation', 'loc/flight-zone', {
  name: 'Berlin Airport Test Hangar',
  city: 'Berlin',
  country: 'DEU',
  geographicPointLocation: ['+52.5200+013.4050/']
});

// 4. Requirements
const glideRequirement = element('Requirement', 'req/glide-distance', {
  name: 'GLIDE-REQ-01 distance',
  requirementStatement: 'The paper plane shall fly at least 5 meters in a straight line.',
  requirementUID: 'GLIDE-REQ-01',
  summary: 'Fictional glide distance verification requirement.'
});

// 5. Hardware Products
const paperSheet = element('hardware_PhysicalHardware', 'hardware/paper-sheet', {
  name: 'A4 Origami Paper Sheet',
  summary: 'Premium 80gsm white folding paper.',
  hardware_partNumber: 'ORIGAMI-PAPER-A4-W',
  hardware_category: 'raw material',
  hardware_productAgent: [studio.spdxId],
  verifiedUsing: [hash('hardware/paper-sheet')]
});

const paperAirplane = element('hardware_PhysicalHardware', 'hardware/paper-airplane', {
  name: 'Super-Glide Paper Airplane (Model A-1)',
  summary: 'Attested hand-folded high-performance paper airplane.',
  hardware_partNumber: 'GLIDER-A1',
  hardware_serialNumber: 'PP-2026-000001',
  hardware_category: 'finished device',
  hardware_productAgent: [studio.spdxId],
  verifiedUsing: [hash('hardware/paper-airplane')]
});

// 6. Evidence / Dataset
const flightTelemetry = element('dataset_DatasetPackage', 'dataset/flight-telemetry', {
  name: 'Flight Telemetry Log',
  summary: 'Recorded flight trajectory, wind speed, and glide distance (6.2 meters).',
  description: 'Flight data confirming successful 6.2 meter glide, satisfying GLIDE-REQ-01.',
  suppliedBy: [charlie.spdxId],
  verifiedUsing: [hash('dataset/flight-telemetry')]
});

// 7. Defined Processes
const designProcess = element('supplychain_BoundaryDefinitionProcess', 'process/design-process', {
  name: 'Origami design and specification process',
  processReadiness: 'operational',
  summary: 'Process for drafting folding specifications and flight requirements.'
});

const buildProcess = element('supplychain_AssemblyProcess', 'process/build-process', {
  name: 'Standard origami assembly process',
  processReadiness: 'operational',
  summary: 'Folding process following precision specs without adhesive.'
});

const testProcess = element('supplychain_TestProcess', 'process/test-process', {
  name: 'Flight acceptance testing process',
  processReadiness: 'operational',
  summary: 'Test flight validation process checking glide distance.'
});

// 8. States
const stateDesigned = element('supplychain_State', 'state/designed', {
  name: 'Designed',
  summary: 'Aerodynamic and folding plans finalized.',
  description: 'Specifications and flight requirements are signed off.'
});

const stateQuarantine = element('supplychain_State', 'state/quarantine', {
  name: 'Folding quarantine',
  summary: 'Glider wing alignment deviation detected.',
  description:
    'Visual quality check failed: left wing tip misaligned by 5mm. Quarantined for corrective refolding.'
});

const stateFolded = element('supplychain_State', 'state/folded', {
  name: 'Assembled and Folded',
  summary: 'Sheet of paper transformed into airplane.',
  description: 'Folding action is complete and ready for flight testing.'
});

const stateTested = element('supplychain_State', 'state/tested', {
  name: 'Tested and Certified',
  summary: 'Flight validation successful.',
  description: 'Paper plane has met or exceeded the 5-meter glide requirement.'
});

// 9. Actions
const actionDesign = element('supplychain_BoundaryDefinitionAction', 'action/001-design', {
  name: 'Design glider parameters and flight requirements',
  startTime: '2026-07-01T09:00:00Z',
  endTime: '2026-07-01T10:00:00Z',
  actionLocation: locDesign.spdxId,
  summary: 'Finalizes paper airplane design requirements.'
});

const actionStateDesigned = element('supplychain_StateAction', 'action/002-state-designed', {
  name: 'Mark design complete',
  startTime: '2026-07-01T10:01:00Z',
  endTime: '2026-07-01T10:05:00Z',
  actionLocation: locDesign.spdxId,
  supplychain_currentState: stateDesigned.spdxId,
  supplychain_decisionProcess: designProcess.spdxId,
  summary: 'Transitions product state to Designed.'
});

const actionTransportPaper = element('supplychain_TransportAction', 'action/003-transport-paper', {
  name: 'Ship origami paper lot from Paris to London workshop',
  startTime: '2026-07-01T11:00:00Z',
  endTime: '2026-07-01T15:00:00Z',
  actionLocation: locDesign.spdxId,
  supplychain_pickupLocation: locDesign.spdxId,
  supplychain_dropoffLocation: locWorkshop.spdxId,
  supplychain_transportRoute: 'Paris Design Lab → Eurostar high-speed rail → London Workshop',
  ...cdxProperties([
    ['paperplane:transport.mode', 'rail'],
    ['paperplane:distance.km', '340'],
    ['paperplane:co2e.kg', '1.2'],
    [
      'paperplane:co2e.method',
      'Calculated based on standard Eurostar rail freight emission factors.'
    ]
  ]),
  summary: 'Eco-friendly transport of high-quality paper lot.'
});

const actionHandoffPaper = element(
  'supplychain_ResponsibilityChangeAction',
  'action/004-handoff-paper',
  {
    name: 'Handoff paper feedstock custody to folding builder',
    startTime: '2026-07-01T15:30:00Z',
    endTime: '2026-07-01T15:35:00Z',
    actionLocation: locWorkshop.spdxId,
    supplychain_previous: alice.spdxId,
    supplychain_current: bob.spdxId,
    supplychain_responsibilityChangedOn: paperSheet.spdxId,
    supplychain_responsibilityCategory: 'custody',
    summary: 'Bob receives the premium white A4 paper sheet at London workshop.'
  }
);

const actionFold = element('supplychain_AssemblyAction', 'action/005-fold-airplane', {
  name: 'Fold sheet into Model A-1 glider',
  startTime: '2026-07-02T10:00:00Z',
  endTime: '2026-07-02T10:15:00Z',
  actionLocation: locWorkshop.spdxId,
  summary: 'Folding process of the paper plane.'
});

// Exception and Resolution Actions
const actionOutOfSpec = element('supplychain_OutOfSpecAction', 'action/006-out-of-spec-folding', {
  name: 'Fold alignment error detected',
  startTime: '2026-07-02T10:20:00Z',
  endTime: '2026-07-02T10:30:00Z',
  actionLocation: locWorkshop.spdxId,
  summary: 'Visual check failed: left wing tip is misaligned by 5mm.'
});

const actionStateQuarantine = element('supplychain_StateAction', 'action/006a-state-quarantine', {
  name: 'Quarantine paper plane for fold deviation',
  startTime: '2026-07-02T10:31:00Z',
  endTime: '2026-07-02T10:34:00Z',
  actionLocation: locWorkshop.spdxId,
  supplychain_currentState: stateQuarantine.spdxId,
  supplychain_decisionProcess: buildProcess.spdxId,
  summary: 'Transitions product state to Folding quarantine.'
});

const actionResolution = element('supplychain_ResolutionAction', 'action/007-resolve-folding', {
  name: 'Re-fold and adjust wing creases',
  startTime: '2026-07-02T10:35:00Z',
  endTime: '2026-07-02T10:45:00Z',
  actionLocation: locWorkshop.spdxId,
  summary: 'Refolded left wing to align perfectly with the fuselage.'
});

const actionStateFolded = element('supplychain_StateAction', 'action/008-state-folded', {
  name: 'Mark airplane folded',
  startTime: '2026-07-02T11:00:00Z',
  endTime: '2026-07-02T11:05:00Z',
  actionLocation: locWorkshop.spdxId,
  supplychain_currentState: stateFolded.spdxId,
  supplychain_decisionProcess: buildProcess.spdxId,
  summary: 'Transitions product state to Assembled and Folded.'
});

const actionTransportPlane = element('supplychain_TransportAction', 'action/009-transport-plane', {
  name: 'Transport folded paper airplane to Berlin flight hangar',
  startTime: '2026-07-03T09:00:00Z',
  endTime: '2026-07-04T12:00:00Z',
  actionLocation: locWorkshop.spdxId,
  supplychain_pickupLocation: locWorkshop.spdxId,
  supplychain_dropoffLocation: locFlightZone.spdxId,
  supplychain_transportRoute:
    'London workshop → road courier to GBR coast → ferry crossing → road transport to Berlin hangar',
  ...cdxProperties([
    ['paperplane:transport.mode', 'road+ferry'],
    ['paperplane:distance.km', '1100'],
    ['paperplane:co2e.kg', '5.8'],
    ['paperplane:co2e.method', 'Road courier delivery allocation based on package mass.']
  ]),
  summary: 'Secured transport of folded plane in a rigid envelope.'
});

const actionHandoffPlane = element(
  'supplychain_ResponsibilityChangeAction',
  'action/010-handoff-plane',
  {
    name: 'Handoff paper plane custody to test pilot',
    startTime: '2026-07-04T13:00:00Z',
    endTime: '2026-07-04T13:05:00Z',
    actionLocation: locFlightZone.spdxId,
    supplychain_previous: bob.spdxId,
    supplychain_current: charlie.spdxId,
    supplychain_responsibilityChangedOn: paperAirplane.spdxId,
    supplychain_responsibilityCategory: 'custody',
    summary: 'Charlie receives the folded plane at Berlin flight hangar.'
  }
);

const actionTest = element('supplychain_TestAction', 'action/011-flight-test', {
  name: 'Perform glide distance validation flight',
  startTime: '2026-07-05T14:00:00Z',
  endTime: '2026-07-05T14:15:00Z',
  actionLocation: locFlightZone.spdxId,
  summary: 'Airplane thrown with standardized force; glide distance measured.'
});

const actionStateTested = element('supplychain_StateAction', 'action/012-state-tested', {
  name: 'Mark flight tested and certified',
  startTime: '2026-07-05T15:00:00Z',
  endTime: '2026-07-05T15:05:00Z',
  actionLocation: locFlightZone.spdxId,
  supplychain_currentState: stateTested.spdxId,
  supplychain_decisionProcess: testProcess.spdxId,
  summary: 'Transitions product state to Tested and Certified.'
});

// Relationships
linkAction(actionDesign.spdxId, [
  ['performedBy', [alice.spdxId, studio.spdxId]],
  ['conformsTo', designProcess.spdxId]
]);

linkAction(actionTransportPaper.spdxId, [
  ['performedBy', bob.spdxId],
  ['hasInput', paperSheet.spdxId],
  ['hasOutput', paperSheet.spdxId]
]);

linkAction(actionFold.spdxId, [
  ['performedBy', bob.spdxId],
  ['hasInput', paperSheet.spdxId],
  ['hasOutput', paperAirplane.spdxId],
  ['conformsTo', buildProcess.spdxId]
]);

linkAction(actionOutOfSpec.spdxId, [
  ['performedBy', bob.spdxId],
  ['hasInput', paperAirplane.spdxId]
]);

linkAction(actionResolution.spdxId, [
  ['performedBy', bob.spdxId],
  ['hasInput', paperAirplane.spdxId],
  ['hasOutput', paperAirplane.spdxId]
]);

relationship('resolved', actionResolution.spdxId, actionOutOfSpec.spdxId);
relationship('hasResolution', actionResolution.spdxId, actionOutOfSpec.spdxId);

linkAction(actionTransportPlane.spdxId, [
  ['performedBy', bob.spdxId],
  ['hasInput', paperAirplane.spdxId],
  ['hasOutput', paperAirplane.spdxId]
]);

linkAction(actionTest.spdxId, [
  ['performedBy', charlie.spdxId],
  ['hasInput', paperAirplane.spdxId],
  ['hasRequirement', glideRequirement.spdxId],
  ['hasEvidence', flightTelemetry.spdxId],
  ['conformsTo', testProcess.spdxId]
]);

// Build graph array
graph.push(
  doc,
  creationInfo,
  studio,
  alice,
  bob,
  charlie,
  generatorTool,
  locDesign,
  locWorkshop,
  locFlightZone,
  glideRequirement,
  paperSheet,
  paperAirplane,
  flightTelemetry,
  designProcess,
  buildProcess,
  testProcess,
  stateDesigned,
  stateQuarantine,
  stateFolded,
  stateTested,
  actionDesign,
  actionStateDesigned,
  actionTransportPaper,
  actionHandoffPaper,
  actionFold,
  actionOutOfSpec,
  actionStateQuarantine,
  actionResolution,
  actionStateFolded,
  actionTransportPlane,
  actionHandoffPlane,
  actionTest,
  actionStateTested,
  ...relationships
);

// Verification and Write
function validateGraph() {
  const errors = [];

  const document = graph.find((el) => el.type === 'SpdxDocument');
  if (!document) errors.push('No SpdxDocument element found');

  const actionsList = graph.filter(
    (item) => item.type.startsWith('supplychain_') && item.type.endsWith('Action')
  );

  for (const a of actionsList.filter((item) => item.type === 'supplychain_TransportAction')) {
    if (!a.supplychain_pickupLocation) errors.push(`${a.spdxId} missing pickup location`);
    if (!a.supplychain_dropoffLocation) errors.push(`${a.spdxId} missing dropoff location`);
    if (!a.supplychain_transportRoute) errors.push(`${a.spdxId} missing route`);
  }

  for (const a of actionsList.filter(
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

  const resRel = relationships.find((rel) => rel.relationshipType === 'resolved');
  if (
    !resRel ||
    resRel.from !== actionResolution.spdxId ||
    !resRel.to.includes(actionOutOfSpec.spdxId)
  ) {
    errors.push('ResolutionAction does not resolve the OutOfSpecAction correctly');
  }

  if (!document?.profileConformance.includes('supplyChain')) {
    errors.push('SpdxDocument profileConformance does not include supplyChain');
  }

  if (errors.length) {
    throw new Error(
      `Paper plane supply-chain validation failed:\n${errors.map((e) => `- ${e}`).join('\n')}`
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

console.log(`Wrote ${OUTPUT}`);
console.log(
  `Elements: ${graph.length}; actions: ${actionsListCount()}; relationships: ${relationships.length}`
);

function actionsListCount() {
  return graph.filter(
    (item) => item.type.startsWith('supplychain_') && item.type.endsWith('Action')
  ).length;
}
