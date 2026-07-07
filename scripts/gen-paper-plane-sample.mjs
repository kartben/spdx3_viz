import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUTPUT = resolve(ROOT, 'public/samples/paper-plane/paper-plane-supply-chain.spdx3.jsonld');
const NS = 'https://spdx.org/spdxdocs/paper-plane-supply-chain';
const CREATED = '2026-07-07T12:00:00Z';
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

const measureLength = (mm) => ({ type: 'MeasureOfLength', quantity: mm, unitQUDT: 'MilliM' });
const measureMass = (grams) => ({ type: 'MeasureOfMass', quantity: grams, unitQUDT: 'GM' });

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
  profileConformance: ['core', 'dataset', 'hardware', 'simpleLicensing', 'supplyChain'],
  rootElement: [id('hardware/paper-airplane')],
  summary:
    'A friendly end-to-end origami supply chain: plan, design, fold, inspect, quarantine, re-fold, flight-test, demonstrate, and archive a single paper airplane.'
};

const creationInfo = {
  type: 'CreationInfo',
  '@id': CREATION_INFO,
  specVersion: '3.1',
  created: CREATED,
  createdBy: [id('agent/person/alice-designer'), id('agent/org/origami-studio')],
  createdUsing: [id('tool/origami-cad-attester')],
  comment: 'Synthetic paper plane sample walking the full SPDX supply chain lifecycle.'
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

const dana = element('Person', 'agent/person/dana-inspector', {
  name: 'Dana',
  summary: 'Quality inspector who measures every crease before a glider is cleared to fly.',
  externalIdentifier: [externalId('dana@example.invalid', 'Synthetic person contact address')]
});

const charlie = element('Person', 'agent/person/charlie-pilot', {
  name: 'Charlie',
  summary: 'Test flight pilot in the fictional Origami program.',
  externalIdentifier: [externalId('charlie@example.invalid', 'Synthetic person contact address')]
});

const generatorTool = element('Tool', 'tool/origami-cad-attester', {
  name: 'Origami Flight-Spec CAD Tool & Folding Attester',
  version: '3.1.0',
  summary: 'Fictional design specification helper, crease-angle gauge, and folding validator tool.'
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

const locMuseum = element('PhysicalLocation', 'loc/museum', {
  name: 'Amsterdam Paper Flight Museum',
  city: 'Amsterdam',
  country: 'NLD',
  geographicPointLocation: ['+52.3676+004.9041/']
});

// 4. Requirements
const glideRequirement = element('Requirement', 'req/glide-distance', {
  name: 'GLIDE-REQ-01 distance',
  requirementStatement: 'The paper plane shall glide at least 5 meters in a straight line.',
  requirementUID: 'GLIDE-REQ-01',
  summary: 'Fictional glide distance acceptance requirement.'
});

const symmetryRequirement = element('Requirement', 'req/wing-symmetry', {
  name: 'SYMM-REQ-01 wing symmetry',
  requirementStatement:
    'Both wing tips shall sit within ±2 mm of the fuselage centerline when the glider rests level.',
  requirementUID: 'SYMM-REQ-01',
  summary: 'Fictional wing symmetry tolerance checked during inspection.'
});

// 5. Hardware: specification, dimensions, and physical products
const gliderSpec = element('hardware_ProductSpecification', 'hardware/spec/glider-a1', {
  name: 'Super-Glide Model A-1 specification',
  summary:
    'Fictional folding specification: 11-step classic dart, symmetric dihedral wings, single fuselage keel, no adhesive.',
  hardware_partNumber: 'GLIDER-A1',
  hardware_category: 'finished device'
});

const sheetDimensions = element('hardware_Dimensions', 'hardware/dimensions/paper-sheet', {
  name: 'A4 sheet envelope dimensions',
  hardware_xAxisLength: measureLength(210),
  hardware_yAxisLength: measureLength(297),
  hardware_zAxisLength: measureLength(0.1)
});

const planeDimensions = element('hardware_Dimensions', 'hardware/dimensions/paper-airplane', {
  name: 'Model A-1 folded envelope dimensions',
  hardware_xAxisLength: measureLength(148), // wingspan
  hardware_yAxisLength: measureLength(280), // nose-to-tail length
  hardware_zAxisLength: measureLength(38) // resting height
});

const paperSheet = element('hardware_PhysicalHardware', 'hardware/paper-sheet', {
  name: 'A4 Origami Paper Sheet',
  summary: 'Premium 80 gsm white folding paper, the sole raw material of the glider.',
  hardware_partNumber: 'ORIGAMI-PAPER-A4-W',
  hardware_category: 'raw material',
  hardware_productAgent: [studio.spdxId],
  hardware_dimensions: sheetDimensions.spdxId,
  hardware_mass: measureMass(5),
  verifiedUsing: [hash('hardware/paper-sheet')]
});

const paperAirplane = element('hardware_PhysicalHardware', 'hardware/paper-airplane', {
  name: 'Super-Glide Paper Airplane (Model A-1)',
  summary: 'Attested hand-folded high-performance paper airplane, serialized and flight-certified.',
  hardware_partNumber: 'GLIDER-A1',
  hardware_serialNumber: 'PP-2026-000001',
  hardware_category: 'finished device',
  hardware_productAgent: [studio.spdxId],
  hardware_dimensions: planeDimensions.spdxId,
  hardware_mass: measureMass(5),
  verifiedUsing: [hash('hardware/paper-airplane')]
});

// 6. Evidence / Datasets
const inspectionFail = element('dataset_DatasetPackage', 'dataset/inspection-pre', {
  name: 'Wing-symmetry inspection record (pre-correction)',
  summary: 'Left wing tip measured 5 mm proud of centerline, exceeding the ±2 mm tolerance.',
  description: 'Gauge readout and photos captured during the first post-fold inspection.',
  suppliedBy: [dana.spdxId],
  verifiedUsing: [hash('dataset/inspection-pre')]
});

const inspectionPass = element('dataset_DatasetPackage', 'dataset/inspection-post', {
  name: 'Wing-symmetry inspection record (post-correction)',
  summary: 'Both wing tips measured within 0.5 mm of centerline, comfortably inside tolerance.',
  description: 'Re-inspection evidence confirming SYMM-REQ-01 after the corrective re-fold.',
  suppliedBy: [dana.spdxId],
  verifiedUsing: [hash('dataset/inspection-post')]
});

const flightTelemetry = element('dataset_DatasetPackage', 'dataset/flight-telemetry', {
  name: 'Flight telemetry log',
  summary: 'Recorded flight trajectory, launch force, wind speed, and glide distance (6.2 meters).',
  description: 'Flight data confirming a 6.2 meter glide, satisfying GLIDE-REQ-01 with margin.',
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
  summary: 'Precision folding process following the Model A-1 spec, no adhesive.'
});

const inspectionProcess = element('supplychain_InspectionProcess', 'process/inspection-process', {
  name: 'Crease and symmetry inspection process',
  processReadiness: 'operational',
  summary: 'Gauge-based inspection verifying wing symmetry before flight clearance.'
});

const testProcess = element('supplychain_TestProcess', 'process/test-process', {
  name: 'Flight acceptance testing process',
  processReadiness: 'operational',
  summary: 'Test-flight validation process measuring glide distance.'
});

const lifecycleProcess = element('supplychain_DefinedStateProcess', 'process/lifecycle-process', {
  name: 'Glider operational lifecycle process',
  processReadiness: 'operational',
  summary: 'Governs the in-service and archival states after certification.'
});

// 8. States
const stateDesigned = element('supplychain_State', 'state/designed', {
  name: 'Designed',
  summary: 'Aerodynamic and folding plans finalized.',
  description: 'Specifications and flight requirements are signed off.'
});

const stateQuarantine = element('supplychain_State', 'state/quarantine', {
  name: 'Folding quarantine',
  summary: 'Glider held back for a wing alignment deviation.',
  description:
    'Inspection failed: left wing tip 5 mm out of tolerance. Quarantined for corrective refolding.'
});

const stateFolded = element('supplychain_State', 'state/folded', {
  name: 'Assembled and folded',
  summary: 'Sheet of paper transformed into an airplane and cleared by re-inspection.',
  description: 'Folding is complete, symmetry verified, and the glider is ready for flight testing.'
});

const stateTested = element('supplychain_State', 'state/tested', {
  name: 'Tested and certified',
  summary: 'Flight validation successful.',
  description: 'The paper plane met and exceeded the 5-meter glide requirement.'
});

const stateInService = element('supplychain_State', 'state/in-service', {
  name: 'In service',
  summary: 'Flown publicly at least once.',
  description: 'The certified glider has completed its demonstration flight and is in active use.'
});

const stateArchived = element('supplychain_State', 'state/archived', {
  name: 'Archived',
  summary: 'Retired to the museum vitrine.',
  description: 'The glider is preserved under climate control with its full provenance record.'
});

// 9. Actions
const actionPlan = element('supplychain_PlanAction', 'action/001-plan', {
  name: 'Plan the Model A-1 folding run',
  startTime: '2026-06-30T09:00:00Z',
  endTime: '2026-06-30T10:30:00Z',
  actionLocation: locDesign.spdxId,
  summary: 'Sets the production plan, acceptance targets, and stage-by-stage custody chain.'
});

const actionDesign = element('supplychain_BoundaryDefinitionAction', 'action/002-design', {
  name: 'Design glider parameters and flight requirements',
  startTime: '2026-07-01T09:00:00Z',
  endTime: '2026-07-01T10:00:00Z',
  actionLocation: locDesign.spdxId,
  summary: 'Finalizes the Super-Glide Model A-1 specification and its acceptance requirements.'
});

const actionStateDesigned = element('supplychain_StateAction', 'action/003-state-designed', {
  name: 'Mark design complete',
  startTime: '2026-07-01T10:01:00Z',
  endTime: '2026-07-01T10:05:00Z',
  actionLocation: locDesign.spdxId,
  supplychain_currentState: stateDesigned.spdxId,
  supplychain_decisionProcess: designProcess.spdxId,
  summary: 'Transitions product state to Designed.'
});

const actionTransportPaper = element('supplychain_TransportAction', 'action/004-transport-paper', {
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
    ['paperplane:co2e.method', 'Calculated from standard Eurostar rail freight emission factors.']
  ]),
  summary: 'Low-carbon rail transport of the premium paper lot.'
});

const actionHandoffPaper = element(
  'supplychain_ResponsibilityChangeAction',
  'action/005-handoff-paper',
  {
    name: 'Handoff paper feedstock custody to folding builder',
    startTime: '2026-07-01T15:30:00Z',
    endTime: '2026-07-01T15:35:00Z',
    actionLocation: locWorkshop.spdxId,
    supplychain_previous: alice.spdxId,
    supplychain_current: bob.spdxId,
    supplychain_responsibilityChangedOn: paperSheet.spdxId,
    supplychain_responsibilityCategory: 'custody',
    summary: 'Bob receives the premium white A4 paper sheet at the London workshop.'
  }
);

const actionFold = element('supplychain_AssemblyAction', 'action/006-fold-airplane', {
  name: 'Fold sheet into Model A-1 glider',
  startTime: '2026-07-02T10:00:00Z',
  endTime: '2026-07-02T10:15:00Z',
  actionLocation: locWorkshop.spdxId,
  summary: 'Eleven precision folds turn a flat sheet into a Model A-1 dart.'
});

const actionInspect = element('supplychain_InspectionAction', 'action/007-inspect-fold', {
  name: 'Post-fold wing-symmetry inspection',
  startTime: '2026-07-02T10:20:00Z',
  endTime: '2026-07-02T10:35:00Z',
  actionLocation: locWorkshop.spdxId,
  summary: 'Dana gauges both wing tips against the centerline and logs the readings.'
});

const actionOutOfSpec = element('supplychain_OutOfSpecAction', 'action/008-out-of-spec', {
  name: 'Wing alignment out of tolerance',
  startTime: '2026-07-02T10:36:00Z',
  endTime: '2026-07-02T10:40:00Z',
  actionLocation: locWorkshop.spdxId,
  summary: 'Left wing tip sits 5 mm proud of centerline, failing SYMM-REQ-01.'
});

const actionStateQuarantine = element('supplychain_StateAction', 'action/009-state-quarantine', {
  name: 'Quarantine glider for fold deviation',
  startTime: '2026-07-02T10:41:00Z',
  endTime: '2026-07-02T10:44:00Z',
  actionLocation: locWorkshop.spdxId,
  supplychain_currentState: stateQuarantine.spdxId,
  supplychain_decisionProcess: buildProcess.spdxId,
  summary: 'Transitions product state to Folding quarantine.'
});

const actionResolution = element('supplychain_ResolutionAction', 'action/010-resolve-folding', {
  name: 'Re-crease and realign left wing',
  startTime: '2026-07-02T10:45:00Z',
  endTime: '2026-07-02T10:55:00Z',
  actionLocation: locWorkshop.spdxId,
  summary: 'Bob sharpens the wing crease so the tip lines up with the fuselage keel.'
});

const actionReinspect = element('supplychain_InspectionAction', 'action/011-reinspect-fold', {
  name: 'Re-inspection after correction',
  startTime: '2026-07-02T11:00:00Z',
  endTime: '2026-07-02T11:15:00Z',
  actionLocation: locWorkshop.spdxId,
  summary: 'Dana re-measures the corrected glider and clears it: 0.5 mm, well within tolerance.'
});

const actionStateFolded = element('supplychain_StateAction', 'action/012-state-folded', {
  name: 'Mark airplane folded',
  startTime: '2026-07-02T11:20:00Z',
  endTime: '2026-07-02T11:25:00Z',
  actionLocation: locWorkshop.spdxId,
  supplychain_currentState: stateFolded.spdxId,
  supplychain_decisionProcess: buildProcess.spdxId,
  summary: 'Transitions product state to Assembled and folded.'
});

const actionTransportPlane = element('supplychain_TransportAction', 'action/013-transport-plane', {
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
    ['paperplane:co2e.method', 'Road courier allocation based on package mass.']
  ]),
  summary: 'Secured transport of the folded glider in a rigid protective envelope.'
});

const actionHandoffPlane = element(
  'supplychain_ResponsibilityChangeAction',
  'action/014-handoff-plane',
  {
    name: 'Handoff paper plane custody to test pilot',
    startTime: '2026-07-04T13:00:00Z',
    endTime: '2026-07-04T13:05:00Z',
    actionLocation: locFlightZone.spdxId,
    supplychain_previous: bob.spdxId,
    supplychain_current: charlie.spdxId,
    supplychain_responsibilityChangedOn: paperAirplane.spdxId,
    supplychain_responsibilityCategory: 'custody',
    summary: 'Charlie receives the folded glider at the Berlin flight hangar.'
  }
);

const actionTest = element('supplychain_TestAction', 'action/015-flight-test', {
  name: 'Perform glide distance validation flight',
  startTime: '2026-07-05T14:00:00Z',
  endTime: '2026-07-05T14:15:00Z',
  actionLocation: locFlightZone.spdxId,
  summary: 'Glider launched with standardized force; glide distance measured at 6.2 meters.'
});

const actionStateTested = element('supplychain_StateAction', 'action/016-state-tested', {
  name: 'Mark flight tested and certified',
  startTime: '2026-07-05T15:00:00Z',
  endTime: '2026-07-05T15:05:00Z',
  actionLocation: locFlightZone.spdxId,
  supplychain_currentState: stateTested.spdxId,
  supplychain_decisionProcess: testProcess.spdxId,
  summary: 'Transitions product state to Tested and certified.'
});

const actionHandoffMuseum = element(
  'supplychain_ResponsibilityChangeAction',
  'action/017-handoff-museum',
  {
    name: 'Transfer custody from test pilot to the studio curator',
    startTime: '2026-07-06T10:00:00Z',
    endTime: '2026-07-06T10:05:00Z',
    actionLocation: locMuseum.spdxId,
    supplychain_previous: charlie.spdxId,
    supplychain_current: studio.spdxId,
    supplychain_responsibilityChangedOn: paperAirplane.spdxId,
    supplychain_responsibilityCategory: 'ownership',
    summary: 'The studio takes ownership for public exhibition at the Paper Flight Museum.'
  }
);

const actionDemo = element('supplychain_UseAction', 'action/018-demo-flight', {
  name: 'Fly the glider at the museum opening demonstration',
  startTime: '2026-07-06T11:00:00Z',
  endTime: '2026-07-06T11:20:00Z',
  actionLocation: locMuseum.spdxId,
  summary: 'A single ceremonial demonstration flight for museum visitors.'
});

const actionStateInService = element('supplychain_StateAction', 'action/019-state-in-service', {
  name: 'Mark glider in service',
  startTime: '2026-07-06T11:25:00Z',
  endTime: '2026-07-06T11:30:00Z',
  actionLocation: locMuseum.spdxId,
  supplychain_currentState: stateInService.spdxId,
  supplychain_decisionProcess: lifecycleProcess.spdxId,
  summary: 'Transitions product state to In service.'
});

const actionArchive = element('supplychain_StorageAction', 'action/020-archive', {
  name: 'Archive the certified glider in the museum vitrine',
  startTime: '2026-07-07T09:00:00Z',
  endTime: '2026-07-07T09:30:00Z',
  actionLocation: locMuseum.spdxId,
  summary: 'Places the glider under climate-controlled glass with its full provenance record.'
});

const actionStateArchived = element('supplychain_StateAction', 'action/021-state-archived', {
  name: 'Mark glider archived',
  startTime: '2026-07-07T09:35:00Z',
  endTime: '2026-07-07T09:40:00Z',
  actionLocation: locMuseum.spdxId,
  supplychain_currentState: stateArchived.spdxId,
  supplychain_decisionProcess: lifecycleProcess.spdxId,
  summary: 'Transitions product state to Archived.'
});

// 10. Relationships
linkAction(actionPlan.spdxId, [
  ['performedBy', [alice.spdxId, studio.spdxId]],
  ['hasRequirement', [glideRequirement.spdxId, symmetryRequirement.spdxId]],
  ['conformsTo', lifecycleProcess.spdxId]
]);

linkAction(actionDesign.spdxId, [
  ['performedBy', [alice.spdxId, studio.spdxId]],
  ['usesTool', generatorTool.spdxId],
  ['hasOutput', gliderSpec.spdxId],
  ['conformsTo', designProcess.spdxId]
]);

// The specification describes the finished glider it was drafted for.
relationship('describes', gliderSpec.spdxId, paperAirplane.spdxId);

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

linkAction(actionInspect.spdxId, [
  ['performedBy', dana.spdxId],
  ['usesTool', generatorTool.spdxId],
  ['hasInput', paperAirplane.spdxId],
  ['hasRequirement', symmetryRequirement.spdxId],
  ['hasEvidence', inspectionFail.spdxId],
  ['conformsTo', inspectionProcess.spdxId]
]);

linkAction(actionOutOfSpec.spdxId, [
  ['performedBy', dana.spdxId],
  ['hasInput', paperAirplane.spdxId]
]);

linkAction(actionResolution.spdxId, [
  ['performedBy', bob.spdxId],
  ['hasInput', paperAirplane.spdxId],
  ['hasOutput', paperAirplane.spdxId]
]);

// Exactly one `resolved` link from the ResolutionAction to the OutOfSpecAction.
// The tool derives the inverse ("Resolved by") on the exception side, so a second
// `hasResolution` edge in the same direction would render as a duplicate panel.
relationship('resolved', actionResolution.spdxId, actionOutOfSpec.spdxId);

linkAction(actionReinspect.spdxId, [
  ['performedBy', dana.spdxId],
  ['usesTool', generatorTool.spdxId],
  ['hasInput', paperAirplane.spdxId],
  ['hasRequirement', symmetryRequirement.spdxId],
  ['hasEvidence', inspectionPass.spdxId],
  ['conformsTo', inspectionProcess.spdxId]
]);

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

linkAction(actionDemo.spdxId, [
  ['performedBy', [charlie.spdxId, studio.spdxId]],
  ['hasInput', paperAirplane.spdxId],
  ['hasEvidence', flightTelemetry.spdxId]
]);

linkAction(actionArchive.spdxId, [
  ['performedBy', studio.spdxId],
  ['hasInput', paperAirplane.spdxId]
]);

// Build graph array
graph.push(
  doc,
  creationInfo,
  studio,
  alice,
  bob,
  dana,
  charlie,
  generatorTool,
  locDesign,
  locWorkshop,
  locFlightZone,
  locMuseum,
  glideRequirement,
  symmetryRequirement,
  gliderSpec,
  sheetDimensions,
  planeDimensions,
  paperSheet,
  paperAirplane,
  inspectionFail,
  inspectionPass,
  flightTelemetry,
  designProcess,
  buildProcess,
  inspectionProcess,
  testProcess,
  lifecycleProcess,
  stateDesigned,
  stateQuarantine,
  stateFolded,
  stateTested,
  stateInService,
  stateArchived,
  actionPlan,
  actionDesign,
  actionStateDesigned,
  actionTransportPaper,
  actionHandoffPaper,
  actionFold,
  actionInspect,
  actionOutOfSpec,
  actionStateQuarantine,
  actionResolution,
  actionReinspect,
  actionStateFolded,
  actionTransportPlane,
  actionHandoffPlane,
  actionTest,
  actionStateTested,
  actionHandoffMuseum,
  actionDemo,
  actionStateInService,
  actionArchive,
  actionStateArchived,
  ...relationships
);

// 11. Verification and Write
function validateGraph() {
  const errors = [];
  const elementIds = new Set(graph.filter((el) => el.spdxId).map((el) => el.spdxId));

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

  for (const a of actionsList.filter((item) => item.type === 'supplychain_StateAction')) {
    if (!a.supplychain_currentState) errors.push(`${a.spdxId} missing current state`);
    if (!a.supplychain_decisionProcess) errors.push(`${a.spdxId} missing decision process`);
  }

  // Every hardware dimensions reference must resolve to a real element.
  for (const hw of graph.filter((item) => item.hardware_dimensions)) {
    if (!elementIds.has(hw.hardware_dimensions)) {
      errors.push(`${hw.spdxId} references missing dimensions ${hw.hardware_dimensions}`);
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

  // Guard against the duplicate-relationship UI bug: `resolved` alone is enough,
  // a same-direction `hasResolution` edge renders as a redundant second panel.
  if (relationships.some((rel) => rel.relationshipType === 'hasResolution')) {
    errors.push('Duplicate hasResolution relationship present (use resolved only)');
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
