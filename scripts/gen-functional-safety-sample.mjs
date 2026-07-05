import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUTPUT = resolve(ROOT, 'public/samples/functional-safety/aeb-safety-case.spdx3.jsonld');
const NS = 'https://spdx.org/spdxdocs/helios-aeb-4.7.2-8d0d733c-6e5f-5d9c-9f41-9ef50b713c10';
const CREATED = '2026-07-05T09:00:00Z';
const CREATION_INFO = '_:helios-aeb-creation-info';

const id = (fragment) => `${NS}#${fragment}`;
const slug = (value) =>
  value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');

const externalId = (identifier, comment, locator) => ({
  type: 'ExternalIdentifier',
  externalIdentifierType: 'other',
  identifier,
  ...(comment ? { comment } : {}),
  ...(locator ? { identifierLocator: [locator] } : {}),
  issuingAuthority: identifier.startsWith('ISO ')
    ? 'International Organization for Standardization'
    : identifier.startsWith('FMVSS')
      ? 'United States Department of Transportation'
      : 'Northstar Mobility Labs (fictional)'
});

const element = (type, fragment, properties) => ({
  type,
  spdxId: id(fragment),
  creationInfo: CREATION_INFO,
  ...properties
});

const graph = [];
const relationships = [];
let relationshipSequence = 0;

function relationship(type, from, to, options = {}) {
  const targets = Array.isArray(to) ? to : [to];
  const relationshipClass = options.scope ? 'LifecycleScopedRelationship' : 'Relationship';
  const rel = element(
    relationshipClass,
    `relationship/${String(++relationshipSequence).padStart(3, '0')}`,
    {
      from,
      relationshipType: type,
      to: targets,
      ...options
    }
  );
  relationships.push(rel);
  return rel;
}

const creator = element('Organization', 'agent/northstar-mobility-labs', {
  name: 'Northstar Mobility Labs, Functional Safety Team (fictional)',
  summary: 'Fictional organization used only to create this synthetic demonstration.'
});

const generator = element('Tool', 'tool/synthetic-safety-case-generator', {
  name: 'Synthetic safety-case sample generator',
  version: '1.0.0',
  summary: 'Deterministic generator for this fictional SPDX demonstration.'
});

const teamDefs = [
  ['maya-chen', 'Maya Chen', 'Functional Safety Manager'],
  ['luca-bernard', 'Luca Bernard', 'Safety Architect'],
  ['priya-nair', 'Priya Nair', 'HARA and Safety Analysis Engineer'],
  ['elena-rossi', 'Elena Rossi', 'System Requirements Engineer'],
  ['jonah-fischer', 'Jonah Fischer', 'Software Safety Engineer'],
  ['amira-haddad', 'Amira Haddad', 'Verification Lead'],
  ['tomasz-kowalski', 'Tomasz Kowalski', 'HIL Test Engineer'],
  ['sofia-alvarez', 'Sofia Alvarez', 'Vehicle Test Engineer'],
  ['noah-williams', 'Noah Williams', 'Embedded Software Engineer'],
  ['aiko-tanaka', 'Aiko Tanaka', 'Static Analysis Engineer'],
  ['samuel-okafor', 'Samuel Okafor', 'Independent Safety Assessor'],
  ['ingrid-larsen', 'Ingrid Larsen', 'Configuration and Quality Manager']
];

const people = teamDefs.map(([key, name, role]) =>
  element('Person', `agent/person/${key}`, {
    name,
    summary: `${role} in the fictional Helios AEB project.`,
    comment: `Synthetic person. Role: ${role}. No real individual or employment relationship is represented.`,
    externalIdentifier: [
      {
        type: 'ExternalIdentifier',
        externalIdentifierType: 'email',
        identifier: `${key}@northstar.example.invalid`,
        issuingAuthority: 'Northstar Mobility Labs (fictional)'
      }
    ]
  })
);

const personId = Object.fromEntries(teamDefs.map(([key]) => [key, id(`agent/person/${key}`)]));
const personCreationInfoId = Object.fromEntries(
  teamDefs.map(([key]) => [key, `_:creation-info-${key}`])
);
const personCreationInfos = teamDefs.map(([key, name, role]) => ({
  type: 'CreationInfo',
  '@id': personCreationInfoId[key],
  specVersion: '3.1',
  created: CREATED,
  createdBy: [personId[key]],
  createdUsing: [generator.spdxId],
  comment: `Synthetic provenance record assigning ${role} work products to fictional person ${name}.`
}));

const tools = [
  generator,
  element('Tool', 'tool/strictdoc', {
    name: 'StrictDoc',
    version: '0.10',
    summary: 'Requirements authoring and traceability tool used in this synthetic workflow.',
    externalRef: [
      {
        type: 'ExternalRef',
        externalRefType: 'documentation',
        locator: ['https://strictdoc.readthedocs.io/']
      }
    ]
  }),
  element('Tool', 'tool/eclipse-opendut', {
    name: 'Eclipse openDuT',
    version: '0.11',
    summary: 'Test orchestration tool used for the fictional SIL and HIL campaigns.',
    externalRef: [
      {
        type: 'ExternalRef',
        externalRefType: 'altWebPage',
        locator: ['https://eclipse-opendut.github.io/opendut/']
      }
    ]
  }),
  element('Tool', 'tool/cbmc', {
    name: 'CBMC',
    version: '6.7',
    summary: 'Bounded model checker used for selected component analyses.',
    externalRef: [
      {
        type: 'ExternalRef',
        externalRefType: 'altWebPage',
        locator: ['https://www.cprover.org/cbmc/']
      }
    ]
  }),
  element('Tool', 'tool/gcov', {
    name: 'gcov',
    version: '15.1',
    summary: 'Coverage collection tool used by the fictional verification pipeline.'
  })
];

const specifications = [
  element('Specification', 'specification/iso-26262-2018', {
    name: 'ISO 26262:2018 reference',
    summary: 'Normative reference only. No certification or compliance claim is made.',
    specType: 'formalStandard',
    externalIdentifier: [
      externalId('ISO 26262:2018 (Parts 2, 4, 6 and 8)', 'Road vehicles functional safety')
    ]
  }),
  element('Regulation', 'specification/fmvss-127', {
    name: 'FMVSS No. 127 reference',
    summary: 'Public AEB performance reference used to make the fictional scenario concrete.',
    specType: 'regulation',
    externalIdentifier: [
      externalId(
        'FMVSS No. 127',
        'Automatic Emergency Braking Systems for Light Vehicles',
        'https://www.nhtsa.gov/document/final-rule-automatic-emergency-braking-systems-light-vehicles'
      )
    ]
  }),
  element('Specification', 'specification/safety-plan', {
    name: 'Helios AEB Safety Plan HSP-4.7',
    summary: 'Fictional plan defining lifecycle activities, independence, and release gates.',
    specType: 'specification',
    externalIdentifier: [externalId('HSP-4.7')]
  }),
  element('Specification', 'specification/item-definition', {
    name: 'Helios AEB Item Definition HID-4.7',
    summary: 'Fictional item boundary, operating modes, interfaces, and assumptions.',
    specType: 'specification',
    externalIdentifier: [externalId('HID-4.7')]
  }),
  element('Specification', 'specification/software-architecture', {
    name: 'Helios AEB Software Architecture HSA-4.7',
    summary: 'Fictional component boundaries and safety mechanism allocation.',
    specType: 'specification',
    externalIdentifier: [externalId('HSA-4.7')]
  })
];

const packageDefs = [
  ['helios-aeb-ecu', 'Helios AEB ECU release candidate', '4.7.2-rc3', 'firmware'],
  ['aeb-application', 'AEB application integration', '4.7.2', 'application'],
  ['threat-estimator', 'Collision threat estimator', '4.7.2', 'library'],
  ['object-fusion', 'Forward object fusion', '4.7.2', 'library'],
  ['signal-plausibility', 'Sensor and vehicle-signal plausibility monitor', '4.7.2', 'library'],
  ['brake-arbitrator', 'Brake demand arbitrator', '4.7.2', 'library'],
  ['safety-supervisor', 'AEB safety supervisor', '4.7.2', 'library'],
  ['vehicle-gateway', 'Vehicle network gateway', '4.7.2', 'library'],
  ['diagnostics', 'Safety diagnostics and event memory', '4.7.2', 'library'],
  ['safety-work-products', 'Helios AEB safety work products', '4.7.2-rc3', 'documentation'],
  ['freertos-kernel', 'FreeRTOS Kernel', '11.1.0', 'operatingSystem'],
  ['nanopb', 'nanopb', '0.4.9.1', 'library']
];

const packages = packageDefs.map(([key, name, version, purpose]) =>
  element('software_Package', `package/${key}`, {
    name,
    software_packageVersion: version,
    software_primaryPurpose: purpose,
    software_packageUrl:
      key === 'freertos-kernel'
        ? `pkg:github/FreeRTOS/FreeRTOS-Kernel@V${version}`
        : key === 'nanopb'
          ? `pkg:github/nanopb/nanopb@${version}`
          : `pkg:generic/northstar-mobility/${key}@${version}`,
    summary:
      key === 'freertos-kernel' || key === 'nanopb'
        ? 'Third-party package version selected by the fictional release candidate.'
        : 'Fictional internal package in the synthetic Helios AEB release candidate.'
  })
);

const packageId = Object.fromEntries(packageDefs.map(([key]) => [key, id(`package/${key}`)]));

const sourceFileDefs = [
  ['aeb-application', 'src/aeb_main.c'],
  ['aeb-application', 'src/aeb_state_machine.c'],
  ['threat-estimator', 'src/ttc_estimator.c'],
  ['threat-estimator', 'src/braking_envelope.c'],
  ['object-fusion', 'src/object_track_fusion.c'],
  ['object-fusion', 'src/pedestrian_classifier_adapter.c'],
  ['signal-plausibility', 'src/radar_camera_plausibility.c'],
  ['signal-plausibility', 'src/vehicle_signal_monitor.c'],
  ['brake-arbitrator', 'src/brake_demand_arbitrator.c'],
  ['brake-arbitrator', 'src/driver_override.c'],
  ['safety-supervisor', 'src/lockstep_monitor.c'],
  ['safety-supervisor', 'src/deadline_monitor.c'],
  ['vehicle-gateway', 'src/can_e2e_gateway.c'],
  ['vehicle-gateway', 'generated/aeb_messages.pb.c'],
  ['diagnostics', 'src/safety_event_memory.c'],
  ['diagnostics', 'src/freeze_frame.c']
];

const sourceFiles = sourceFileDefs.map(([owner, name]) =>
  element('software_File', `file/source/${slug(name)}`, {
    name,
    software_primaryPurpose: name.includes('generated/') ? 'source' : 'source',
    contentType: 'text/x-c',
    summary: `Fictional source artifact owned by ${owner}.`
  })
);

const releaseFiles = [
  element('software_File', 'file/release/helios-aeb.elf', {
    name: 'build/helios-aeb.elf',
    software_primaryPurpose: 'executable',
    software_artifactSize: 1482752,
    contentType: 'application/x-elf',
    summary: 'Fictional target ELF for the release candidate.'
  }),
  element('software_File', 'file/release/helios-aeb.hex', {
    name: 'dist/helios-aeb-4.7.2-rc3.hex',
    software_primaryPurpose: 'firmware',
    software_artifactSize: 917504,
    contentType: 'application/octet-stream',
    summary: 'Fictional flash image for the release candidate.'
  }),
  element('software_File', 'file/release/aeb-calibration.arxml', {
    name: 'config/aeb-calibration-4.7.2.arxml',
    software_primaryPurpose: 'configuration',
    software_artifactSize: 18342,
    contentType: 'application/xml',
    summary: 'Fictional production-intent calibration with controlled safety limits.'
  })
];

const evidenceDefs = [
  ['hara-report', 'HARA and safety goals review report', 'report', 'application/pdf'],
  [
    'safety-concept-review',
    'Functional and technical safety concept review record',
    'report',
    'application/pdf'
  ],
  ['fta-fmea-report', 'Fault-tree and software FMEA report', 'report', 'application/pdf'],
  ['system-hil-report', 'AEB system HIL regression report', 'report', 'application/pdf'],
  [
    'vehicle-validation-report',
    'Closed-course vehicle validation report',
    'report',
    'application/pdf'
  ],
  ['unit-test-report', 'Software unit test results', 'report', 'application/junit+xml'],
  ['coverage-report', 'Statement, branch, and MC/DC coverage report', 'report', 'text/html'],
  ['static-analysis-report', 'Static analysis and coding-rule report', 'report', 'application/pdf'],
  ['code-review-checklist', 'Independent source review checklist', 'report', 'application/pdf'],
  ['timing-trace', 'Worst-case execution and end-to-end timing trace', 'log', 'text/csv'],
  [
    'fault-injection-log',
    'Sensor, communication, and memory fault-injection log',
    'log',
    'application/json'
  ],
  ['night-pedestrian-recording', 'Night pedestrian target run recording', 'recording', 'video/mp4'],
  [
    'assessment-observation',
    'Independent release assessment observation',
    'observation',
    'application/pdf'
  ]
];

const evidenceOwner = {
  'hara-report': 'priya-nair',
  'safety-concept-review': 'luca-bernard',
  'fta-fmea-report': 'priya-nair',
  'system-hil-report': 'tomasz-kowalski',
  'vehicle-validation-report': 'sofia-alvarez',
  'unit-test-report': 'noah-williams',
  'coverage-report': 'aiko-tanaka',
  'static-analysis-report': 'aiko-tanaka',
  'code-review-checklist': 'jonah-fischer',
  'timing-trace': 'tomasz-kowalski',
  'fault-injection-log': 'tomasz-kowalski',
  'night-pedestrian-recording': 'sofia-alvarez',
  'assessment-observation': 'samuel-okafor'
};

const evidenceFiles = evidenceDefs.map(([key, name, , contentType]) =>
  element('software_File', `file/evidence/${key}`, {
    creationInfo: personCreationInfoId[evidenceOwner[key]],
    name: `evidence/${key}.${
      {
        'video/mp4': 'mp4',
        'text/csv': 'csv',
        'text/html': 'html',
        'application/json': 'json',
        'application/junit+xml': 'xml',
        'application/pdf': 'pdf'
      }[contentType] || 'bin'
    }`,
    software_primaryPurpose: 'evidence',
    originatedBy: [personId[evidenceOwner[key]]],
    contentType,
    summary: `${name}. Synthetic evidence metadata only; no real report is included.`
  })
);

const evidenceId = Object.fromEntries(
  evidenceDefs.map(([key]) => [key, id(`file/evidence/${key}`)])
);

const assumptions = [
  [
    'AOU-01',
    'The full-performance operating mode assumes a dry, paved road with tire-road friction coefficient of at least 0.7.'
  ],
  [
    'AOU-02',
    'The forward radar and camera are installed and aligned within the tolerances defined by HID-4.7.'
  ],
  ['AOU-03', 'The brake control ECU accepts a valid external deceleration request within 20 ms.'],
  [
    'AOU-04',
    'Safety-related CAN traffic remains below 60 percent bus utilization in all declared vehicle modes.'
  ],
  ['AOU-05', 'The vehicle low-voltage supply remains within 9 V to 16 V during AEB operation.'],
  [
    'AOU-06',
    'The driver remains responsible for the driving task and can override AEB through the service brake or accelerator interface.'
  ],
  [
    'AOU-07',
    'The target microcontroller is integrated according to its safety manual, including lockstep, memory protection, and watchdog constraints.'
  ],
  [
    'AOU-08',
    'Upstream perception provides object class, range, relative speed, confidence, and freshness metadata at 50 Hz.'
  ]
].map(([code, statement]) =>
  element('functionalsafety_Assumption', `assumption/${code.toLowerCase()}`, {
    name: code,
    functionalsafety_assumptionStatement: statement,
    rationale:
      'Defines an integration or operational constraint used by the fictional safety argument.',
    externalIdentifier: [externalId(code, 'Assumption of use')]
  })
);

const requirements = [
  [
    'SG-01',
    'Prevent unintended emergency braking',
    'The AEB item shall prevent an automated emergency-braking demand when no collision threat is confirmed.',
    null,
    'helios-aeb-ecu',
    'assessment',
    'HARA review confirms prevention of unintended braking is allocated as a top-level safety goal.',
    'hara-report'
  ],
  [
    'SG-02',
    'Provide timely collision mitigation',
    'The AEB item shall command braking early enough to mitigate an imminent frontal collision within its declared operating domain.',
    null,
    'helios-aeb-ecu',
    'demonstration',
    'Closed-course runs satisfy every speed, overlap, lighting, and target acceptance case in the validation plan.',
    'vehicle-validation-report'
  ],
  [
    'SG-03',
    'Preserve driver authority',
    'The AEB item shall preserve the driver ability to override an automated braking intervention.',
    null,
    'helios-aeb-ecu',
    'test',
    'Brake-pedal and accelerator override tests transfer authority within 100 ms without command oscillation.',
    'system-hil-report'
  ],
  [
    'SG-04',
    'Control faults within the FTTI',
    'The AEB item shall detect safety-relevant faults and reach its defined safe state within the allocated fault-tolerant time interval.',
    null,
    'helios-aeb-ecu',
    'test',
    'Injected single-point faults are detected and controlled within their allocated fault-tolerant time intervals.',
    'fault-injection-log'
  ],

  [
    'FSR-01',
    'Confirm collision threats independently',
    'The AEB function shall require two independent collision-threat checks before requesting emergency deceleration above 3.0 m/s2.',
    'SG-01',
    'aeb-application',
    'analysis',
    'Independence analysis finds no shared single failure that can authorize a high-deceleration request.',
    'fta-fmea-report'
  ],
  [
    'FSR-02',
    'Bound automatic deceleration',
    'The AEB function shall limit automated deceleration to 0.5 m/s2 when collision-threat confidence is below the calibrated confirmation threshold.',
    'SG-01',
    'brake-arbitrator',
    'test',
    'HIL sweeps below the confirmation threshold never exceed 0.5 m/s2 requested deceleration.',
    'system-hil-report'
  ],
  [
    'FSR-03',
    'Meet the braking-response deadline',
    'The AEB function shall issue a valid brake request within 80 ms after confirming an imminent collision threat.',
    'SG-02',
    'aeb-application',
    'test',
    'The 99.999th percentile end-to-end response is at most 80 ms under maximum declared ECU load.',
    'timing-trace'
  ],
  [
    'FSR-04',
    'Maintain intervention continuity',
    'The AEB function shall maintain a confirmed braking intervention through a single missing 20 ms perception update.',
    'SG-02',
    'threat-estimator',
    'test',
    'A single omitted perception update produces no release or increase of the active brake request.',
    'system-hil-report'
  ],
  [
    'FSR-05',
    'Honor driver override',
    'The AEB function shall release its automated brake request within 100 ms after a valid driver override is received.',
    'SG-03',
    'brake-arbitrator',
    'test',
    'All valid override paths reduce the automated request to zero within 100 ms.',
    'system-hil-report'
  ],
  [
    'FSR-06',
    'Reject stale safety inputs',
    'The AEB function shall reject a safety-related input whose age exceeds 100 ms.',
    'SG-04',
    'signal-plausibility',
    'test',
    'Every input older than 100 ms is rejected before the next control-cycle decision.',
    'fault-injection-log'
  ],
  [
    'FSR-07',
    'Enter the inhibited safe state',
    'The AEB function shall inhibit automated braking within 50 ms after detecting a critical internal fault.',
    'SG-04',
    'safety-supervisor',
    'test',
    'Each critical-fault injection causes the inhibited state within 50 ms and blocks subsequent brake requests.',
    'fault-injection-log'
  ],
  [
    'FSR-08',
    'Annunciate loss of AEB',
    'The AEB function shall request a driver warning within 500 ms after entering the inhibited safe state.',
    'SG-04',
    'diagnostics',
    'test',
    'The warning request is present on the vehicle network within 500 ms for every inhibit transition.',
    'system-hil-report'
  ],

  [
    'TSR-01',
    'Check radar and camera consistency',
    'The AEB ECU shall compare radar and camera longitudinal range estimates every 20 ms while both sensors are available.',
    'FSR-01',
    'signal-plausibility',
    'test',
    'A comparison executes in every 20 ms cycle with both inputs valid.',
    'system-hil-report'
  ],
  [
    'TSR-02',
    'Require dual authorization',
    'The AEB ECU shall authorize a request above 3.0 m/s2 only when the kinematic and fused-object threat channels both assert imminent collision.',
    'FSR-01',
    'brake-arbitrator',
    'analysis',
    'Model checking proves no reachable state authorizes high deceleration from one threat channel alone.',
    'static-analysis-report'
  ],
  [
    'TSR-03',
    'Clamp low-confidence demand',
    'The brake-demand interface shall clamp an unconfirmed automated request to the interval 0.0 m/s2 through 0.5 m/s2.',
    'FSR-02',
    'brake-arbitrator',
    'test',
    'Boundary and out-of-range vectors produce a request inside the 0.0 to 0.5 m/s2 interval.',
    'unit-test-report'
  ],
  [
    'TSR-04',
    'Complete the cyclic control path',
    'The AEB control path shall complete sensing, decision, arbitration, and transmission within 60 ms.',
    'FSR-03',
    'aeb-application',
    'test',
    'Instrumented maximum-load runs show an end-to-end control-path time no greater than 60 ms.',
    'timing-trace'
  ],
  [
    'TSR-05',
    'Detect missed control deadlines',
    'The safety supervisor shall detect an AEB control-cycle overrun before the following 20 ms cycle completes.',
    'FSR-03',
    'safety-supervisor',
    'test',
    'Every injected overrun is detected no later than the end of the following cycle.',
    'fault-injection-log'
  ],
  [
    'TSR-06',
    'Bridge one missing perception frame',
    'The threat estimator shall retain the last confirmed object state for exactly one missing 20 ms perception frame.',
    'FSR-04',
    'threat-estimator',
    'test',
    'One missing frame retains the prior state, while a second consecutive missing frame invalidates it.',
    'unit-test-report'
  ],
  [
    'TSR-07',
    'Detect latent monitor faults',
    'The AEB ECU shall detect a latent fault in each redundant threat-monitoring path within 10 operating hours.',
    'FSR-04',
    'safety-supervisor',
    'analysis',
    'Accelerated fault-injection evidence establishes a diagnostic interval no greater than 10 operating hours.',
    'fault-injection-log',
    'inconclusive'
  ],
  [
    'TSR-08',
    'Prioritize driver override',
    'The brake arbitrator shall prioritize a valid driver override over every automated AEB request.',
    'FSR-05',
    'brake-arbitrator',
    'analysis',
    'State-space exploration finds no reachable state in which an automated request outranks a valid override.',
    'static-analysis-report'
  ],
  [
    'TSR-09',
    'Monitor input freshness',
    'The vehicle gateway shall assign and validate monotonic reception timestamps for every safety-related input.',
    'FSR-06',
    'vehicle-gateway',
    'inspection',
    'Review confirms every safety-related receive path assigns and validates a monotonic timestamp.',
    'code-review-checklist'
  ],
  [
    'TSR-10',
    'Protect safety messages end to end',
    'The vehicle gateway shall reject a safety message with an invalid counter, data identifier, or CRC.',
    'FSR-06',
    'vehicle-gateway',
    'test',
    'Corruption of each protection field causes message rejection with no update to application data.',
    'fault-injection-log'
  ],
  [
    'TSR-11',
    'Supervise control-flow health',
    'The safety supervisor shall verify the expected control-flow checkpoint sequence once per 20 ms cycle.',
    'FSR-07',
    'safety-supervisor',
    'test',
    'Missing, repeated, and reordered checkpoints are detected within the active cycle.',
    'fault-injection-log'
  ],
  [
    'TSR-12',
    'Transmit the loss-of-function warning',
    'The diagnostic manager shall transmit the AEB unavailable status at least once every 100 ms while inhibition is active.',
    'FSR-08',
    'diagnostics',
    'test',
    'The unavailable status appears at intervals no greater than 100 ms throughout inhibition.',
    'system-hil-report'
  ],

  [
    'SSR-EST-01',
    'Compute closing speed',
    'The threat estimator shall compute longitudinal closing speed from synchronized object and ego-velocity samples once per 20 ms cycle.',
    'TSR-04',
    'threat-estimator',
    'test',
    'Equivalence-class vectors match the reference result within 0.05 m/s.',
    'unit-test-report'
  ],
  [
    'SSR-EST-02',
    'Bound time to collision',
    'The threat estimator shall saturate computed time to collision to the interval 0.0 s through 10.0 s.',
    'TSR-04',
    'threat-estimator',
    'test',
    'Zero, negative, overflow, and nominal inputs always return a value in the declared interval.',
    'unit-test-report'
  ],
  [
    'SSR-EST-03',
    'Age a retained track once',
    'The threat estimator shall increment retained-object age by 20 ms when exactly one perception frame is missing.',
    'TSR-06',
    'threat-estimator',
    'test',
    'A single missing frame increases age by exactly 20 ms without changing position or relative velocity.',
    'unit-test-report'
  ],
  [
    'SSR-EST-04',
    'Invalidate a twice-missed track',
    'The threat estimator shall invalidate an object after two consecutive missing perception frames.',
    'TSR-06',
    'threat-estimator',
    'test',
    'The valid flag clears on the second consecutive missing frame and not on the first.',
    'unit-test-report'
  ],
  [
    'SSR-FUS-01',
    'Associate forward tracks',
    'The object-fusion component shall associate radar and camera tracks only when longitudinal separation is at most 1.5 m.',
    'TSR-01',
    'object-fusion',
    'test',
    'Association occurs at and below 1.5 m and is rejected above 1.5 m.',
    'unit-test-report'
  ],
  [
    'SSR-FUS-02',
    'Reject divergent sensor ranges',
    'The plausibility monitor shall flag range disagreement when synchronized radar and camera ranges differ by more than 2.0 m for three cycles.',
    'TSR-01',
    'signal-plausibility',
    'test',
    'The flag asserts on the third divergent cycle and clears only after five consistent cycles.',
    'unit-test-report'
  ],
  [
    'SSR-FUS-03',
    'Prevent single-channel authorization',
    'The fusion component shall expose separate kinematic-threat and fused-object-threat authorization outputs.',
    'TSR-02',
    'object-fusion',
    'inspection',
    'Interface and data-flow review confirm separate storage, calculation, and output paths.',
    'code-review-checklist'
  ],
  [
    'SSR-ARB-01',
    'Require both threat channels',
    'The brake arbitrator shall reject a request above 3.0 m/s2 unless both threat-authorization inputs are true in the same cycle.',
    'TSR-02',
    'brake-arbitrator',
    'test',
    'All four Boolean input combinations produce high-deceleration authorization only for true and true.',
    'unit-test-report'
  ],
  [
    'SSR-ARB-02',
    'Clamp unconfirmed demand',
    'The brake arbitrator shall limit an unconfirmed input demand greater than 0.5 m/s2 to 0.5 m/s2.',
    'TSR-03',
    'brake-arbitrator',
    'test',
    'Boundary values and every generated value above 0.5 m/s2 produce exactly 0.5 m/s2.',
    'unit-test-report'
  ],
  [
    'SSR-ARB-03',
    'Reject non-finite demand',
    'The brake arbitrator shall replace a non-finite deceleration input with 0.0 m/s2 and set an input-fault flag.',
    'TSR-03',
    'brake-arbitrator',
    'test',
    'NaN and positive or negative infinity produce zero demand and assert the fault flag.',
    'unit-test-report'
  ],
  [
    'SSR-ARB-04',
    'Apply brake-pedal override',
    'The brake arbitrator shall set automated demand to 0.0 m/s2 when brake-pedal override is valid.',
    'TSR-08',
    'brake-arbitrator',
    'test',
    'Each valid brake-pedal override vector produces zero automated demand in the same cycle.',
    'unit-test-report'
  ],
  [
    'SSR-ARB-05',
    'Apply accelerator override',
    'The brake arbitrator shall set automated demand to 0.0 m/s2 when accelerator position exceeds the calibrated override threshold.',
    'TSR-08',
    'brake-arbitrator',
    'test',
    'Values above the threshold produce zero demand, while the boundary value preserves the active request.',
    'unit-test-report'
  ],
  [
    'SSR-SUP-01',
    'Check cyclic checkpoints',
    'The safety supervisor shall compare the observed checkpoint sequence with the configured sequence every 20 ms.',
    'TSR-11',
    'safety-supervisor',
    'test',
    'Every cyclic comparison identifies complete and incomplete sequences correctly.',
    'unit-test-report'
  ],
  [
    'SSR-SUP-02',
    'Latch control-flow faults',
    'The safety supervisor shall latch a control-flow fault until the next successful power-on self-test.',
    'TSR-11',
    'safety-supervisor',
    'test',
    'The fault remains latched across application resets and clears only after a successful power-on self-test.',
    'system-hil-report'
  ],
  [
    'SSR-SUP-03',
    'Detect deadline overrun',
    'The safety supervisor shall set a deadline fault when the control task completion timestamp exceeds its 20 ms deadline.',
    'TSR-05',
    'safety-supervisor',
    'test',
    'Completion at 20 ms passes, and completion later than 20 ms sets the deadline fault.',
    'unit-test-report'
  ],
  [
    'SSR-SUP-04',
    'Request inhibition on critical fault',
    'The safety supervisor shall request AEB inhibition in the same cycle that a critical fault is latched.',
    'TSR-05',
    'safety-supervisor',
    'test',
    'Every critical-fault vector asserts inhibition before the cycle output is committed.',
    'unit-test-report'
  ],
  [
    'SSR-GWY-01',
    'Use a monotonic timestamp',
    'The vehicle gateway shall timestamp accepted safety messages from the ECU monotonic clock.',
    'TSR-09',
    'vehicle-gateway',
    'inspection',
    'Review traces every accepted safety message to the monotonic clock API.',
    'code-review-checklist'
  ],
  [
    'SSR-GWY-02',
    'Reject stale messages',
    'The vehicle gateway shall mark a safety message invalid when its computed age exceeds 100 ms.',
    'TSR-09',
    'vehicle-gateway',
    'test',
    'Ages through 100 ms remain valid, and the first value above 100 ms is invalid.',
    'unit-test-report'
  ],
  [
    'SSR-GWY-03',
    'Validate rolling counters',
    'The vehicle gateway shall reject a rolling counter that is neither the expected value nor the one permitted startup value.',
    'TSR-10',
    'vehicle-gateway',
    'test',
    'Expected and startup counters pass; repeats, skips, and out-of-range counters fail.',
    'unit-test-report'
  ],
  [
    'SSR-GWY-04',
    'Validate message CRC',
    'The vehicle gateway shall validate the configured CRC over the protected payload before publishing application data.',
    'TSR-10',
    'vehicle-gateway',
    'test',
    'Each single-bit corruption in the protected payload is rejected before publication.',
    'unit-test-report'
  ],
  [
    'SSR-DIA-01',
    'Publish unavailable status',
    'The diagnostic manager shall publish AEB unavailable status every 100 ms while inhibition is active.',
    'TSR-12',
    'diagnostics',
    'test',
    'A 10 s inhibited run contains no publication interval greater than 100 ms.',
    'system-hil-report'
  ],
  [
    'SSR-DIA-02',
    'Record inhibition cause',
    'The diagnostic manager shall store the first detected inhibition cause and monotonic timestamp for each ignition cycle.',
    'TSR-12',
    'diagnostics',
    'test',
    'The first cause and timestamp persist and are not overwritten by later causes in the same ignition cycle.',
    'unit-test-report'
  ],
  [
    'SSR-DIA-03',
    'Retain the diagnostic snapshot',
    'The diagnostic manager shall retain the latest two inhibition snapshots across an interrupted low-voltage shutdown.',
    'TSR-12',
    'diagnostics',
    'test',
    'Power interruption at every millisecond offset preserves two complete and CRC-valid snapshots.',
    'fault-injection-log',
    'fail'
  ],
  [
    'SSR-APP-01',
    'Execute one decision per cycle',
    'The AEB application shall execute exactly one decision and arbitration sequence in each activated 20 ms cycle.',
    'TSR-04',
    'aeb-application',
    'analysis',
    'Control-flow analysis proves one decision and one arbitration call on every normal activated path.',
    'static-analysis-report'
  ]
];

const requirementIds = Object.fromEntries(
  requirements.map(([code]) => [code, id(`requirement/${code.toLowerCase()}`)])
);
const verificationIds = {};
const evaluationIds = {};

function verificationPrecondition(code, method) {
  if (method === 'assessment' || method === 'review' || method === 'audit') {
    return 'Baselined work products, approved checklist, and independent reviewer are available.';
  }
  if (method === 'analysis' || method === 'inspection') {
    return code.startsWith('SSR-')
      ? 'Baselined component design, release-candidate source, and analysis configuration are available.'
      : 'Baselined safety concept, architecture, and analysis assumptions are available.';
  }
  if (code.startsWith('SG-')) {
    return 'Production-intent vehicle, calibrated targets, controlled track, and synchronized data acquisition are available.';
  }
  if (code.startsWith('FSR-') || code.startsWith('TSR-')) {
    return 'Target ECU HIL, sensor restbus, brake-actuator model, and release-candidate calibration are available.';
  }
  return 'The component test harness is built from the release candidate with interfaces stubbed at documented boundaries.';
}

const requirementElements = [];
const verificationElements = [];
const evaluationElements = [];
const evidenceRelationships = [];

function requirementOwner(code) {
  if (code.startsWith('SG-')) return 'maya-chen';
  if (code.startsWith('FSR-')) return 'elena-rossi';
  if (code.startsWith('TSR-')) return 'luca-bernard';
  return code.startsWith('SSR-GWY-') || code.startsWith('SSR-APP-')
    ? 'noah-williams'
    : 'jonah-fischer';
}

function verificationOwner(code, method) {
  if (method === 'assessment' || method === 'audit') return 'samuel-okafor';
  if (method === 'analysis') {
    return code.startsWith('SG-') || code.startsWith('FSR-') ? 'priya-nair' : 'aiko-tanaka';
  }
  if (method === 'demonstration' || code.startsWith('SG-')) return 'sofia-alvarez';
  if (method === 'inspection' || method === 'review') return 'ingrid-larsen';
  if (code.startsWith('SSR-')) return 'noah-williams';
  return 'tomasz-kowalski';
}

for (const [
  code,
  name,
  statement,
  parent,
  implementation,
  method,
  criterion,
  evidence,
  result = 'pass'
] of requirements) {
  const lifecycle = code.startsWith('SG-') || code.startsWith('FSR-') ? 'design' : 'development';
  const req = element('Requirement', `requirement/${code.toLowerCase()}`, {
    creationInfo: personCreationInfoId[requirementOwner(code)],
    name: `${code}: ${name}`,
    summary: code.startsWith('SG-')
      ? 'Safety goal'
      : code.startsWith('FSR-')
        ? 'Functional safety requirement'
        : code.startsWith('TSR-')
          ? 'Technical safety requirement'
          : 'Software safety requirement',
    requirementStatement: statement,
    requirementUID: externalId(code, 'Controlled requirement identifier'),
    devLifecycleStage: [lifecycle],
    rationale: parent
      ? `Refines ${parent} with an independently verifiable allocation.`
      : 'Top-level safety goal derived from the fictional hazard analysis.'
  });
  requirementElements.push(req);

  const verificationCode = `VER-${code}`;
  const verificationId = id(`verification/${code.toLowerCase()}`);
  const performer = verificationOwner(code, method);
  verificationIds[code] = verificationId;
  const verification = element(
    'functionalsafety_RequirementVerification',
    `verification/${code.toLowerCase()}`,
    {
      creationInfo: personCreationInfoId['amira-haddad'],
      name: `${verificationCode}: ${name}`,
      summary: `${method[0].toUpperCase()}${method.slice(1)} verification of ${code}.`,
      functionalsafety_verificationMethod: [method],
      functionalsafety_verificationPrecondition: [verificationPrecondition(code, method)],
      functionalsafety_verificationPostcondition: [criterion],
      rationale: `The selected ${method} method directly addresses the measurable acceptance criterion for ${code}.`,
      externalIdentifier: [externalId(verificationCode, 'Verification record identifier')]
    }
  );
  verificationElements.push(verification);

  const evaluationCode = `EVAL-${code}`;
  const evaluationId = id(`evaluation/${code.toLowerCase()}`);
  evaluationIds[code] = evaluationId;
  const evaluation = element(
    'functionalsafety_EvaluationResult',
    `evaluation/${code.toLowerCase()}`,
    {
      creationInfo: personCreationInfoId[performer],
      name: `${evaluationCode}: ${name}`,
      functionalsafety_evaluation: result,
      functionalsafety_evaluationBasedOn: verificationId,
      rationale:
        result === 'pass'
          ? `Synthetic evidence ${evidence} meets the stated acceptance criterion with no unresolved safety-relevant deviation.`
          : result === 'fail'
            ? 'Power interruption at 8 ms left only one complete snapshot. Fictional defect AEB-481 remains open.'
            : 'The accelerated campaign covered 6.2 equivalent operating hours, which is insufficient to establish the 10-hour bound.',
      ...(result === 'inconclusive'
        ? { comment: 'Additional accelerated fault-injection cycles are required before release.' }
        : {}),
      externalIdentifier: [externalId(evaluationCode, 'Evaluation result identifier')]
    }
  );
  evaluationElements.push(evaluation);

  if (parent) relationship('tracedToDetail', requirementIds[parent], req.spdxId);
  relationship('implementedBy', req.spdxId, packageId[implementation], {
    scope: lifecycle
  });
  relationship('verifiedBy', req.spdxId, verificationId);

  const evidenceType = evidenceDefs.find(([key]) => key === evidence)?.[2] || 'report';
  evidenceRelationships.push(
    element(
      'functionalsafety_EvidenceRelationship',
      `evidence-relationship/${code.toLowerCase()}`,
      {
        from: evaluationId,
        relationshipType: 'hasEvidence',
        to: [evidenceId[evidence]],
        functionalsafety_evidenceCategory: evidenceType,
        externalIdentifier: [externalId(`EVID-${code}`, 'Evidence-link identifier')]
      }
    )
  );
}

const rootPackageId = packageId['helios-aeb-ecu'];
const safetyWorkProductsId = packageId['safety-work-products'];

relationship(
  'contains',
  rootPackageId,
  packageDefs.slice(1, 9).map(([key]) => packageId[key])
);
relationship('hasStaticLink', rootPackageId, [packageId['freertos-kernel'], packageId.nanopb], {
  scope: 'runtime'
});
relationship(
  'hasDistributionArtifact',
  rootPackageId,
  releaseFiles.slice(0, 2).map((file) => file.spdxId)
);
relationship('configures', releaseFiles[2].spdxId, rootPackageId, { scope: 'runtime' });
relationship('dependsOn', packageId['aeb-application'], [
  packageId['threat-estimator'],
  packageId['object-fusion'],
  packageId['signal-plausibility'],
  packageId['brake-arbitrator'],
  packageId['safety-supervisor'],
  packageId['vehicle-gateway'],
  packageId.diagnostics,
  packageId['freertos-kernel']
]);
relationship('dependsOn', packageId['vehicle-gateway'], packageId.nanopb);

for (const [owner, name] of sourceFileDefs) {
  relationship('contains', packageId[owner], id(`file/source/${slug(name)}`));
}
relationship(
  'contains',
  safetyWorkProductsId,
  evidenceFiles.map((file) => file.spdxId)
);

relationship(
  'assumes',
  rootPackageId,
  assumptions.map((assumption) => assumption.spdxId)
);
relationship(
  'hasSpecification',
  rootPackageId,
  specifications.slice(2).map((spec) => spec.spdxId),
  {
    scope: 'design'
  }
);
relationship('hasSpecification', specifications[2].spdxId, [
  specifications[0].spdxId,
  specifications[1].spdxId
]);
relationship(
  'hasRequirement',
  specifications[3].spdxId,
  requirementElements
    .filter((req) => /#requirement\/(sg|fsr)-/.test(req.spdxId))
    .map((req) => req.spdxId)
);
relationship(
  'hasRequirement',
  specifications[4].spdxId,
  requirementElements
    .filter((req) => /#requirement\/(tsr|ssr)-/.test(req.spdxId))
    .map((req) => req.spdxId)
);
relationship('usesTool', specifications[2].spdxId, id('tool/strictdoc'), {
  scope: 'development'
});
for (const verification of verificationElements) {
  if (verification.functionalsafety_verificationMethod.includes('test')) {
    relationship('usesTool', verification.spdxId, id('tool/eclipse-opendut'), { scope: 'test' });
  }
}

for (const verification of verificationElements) {
  if (verification.functionalsafety_verificationMethod.includes('analysis')) {
    relationship('usesTool', verification.spdxId, id('tool/cbmc'), { scope: 'test' });
  }
}
relationship('usesTool', evidenceId['coverage-report'], id('tool/gcov'), { scope: 'test' });

const sbom = element('software_Sbom', 'sbom/helios-aeb-4.7.2-rc3', {
  name: 'Helios AEB 4.7.2-rc3 synthetic safety SBOM',
  summary:
    'Synthetic and fictional AEB release-candidate SBOM with safety lifecycle traceability. It is not certification data.',
  profileConformance: ['core', 'software', 'functionalSafety'],
  software_sbomType: ['build'],
  rootElement: [rootPackageId]
});

graph.push(
  creator,
  ...people,
  ...tools,
  ...specifications,
  ...packages,
  ...sourceFiles,
  ...releaseFiles,
  ...evidenceFiles,
  ...assumptions,
  ...requirementElements,
  ...verificationElements,
  ...evaluationElements,
  ...evidenceRelationships,
  ...relationships,
  sbom,
  ...personCreationInfos
);

const elementIds = graph
  .filter((entry) => entry.spdxId && entry.type !== 'SpdxDocument')
  .map((entry) => entry.spdxId);
sbom.element = elementIds.filter((entryId) => entryId !== sbom.spdxId);

const document = element('SpdxDocument', 'document', {
  name: 'Helios AEB synthetic Functional Safety demonstration',
  summary:
    'Entirely synthetic and fictional data for demonstrating SPDX 3.1 Functional Safety traceability. Not a real product, safety case, assessment, or certification.',
  dataLicense: 'https://spdx.org/licenses/CC0-1.0',
  profileConformance: ['core', 'software', 'functionalSafety'],
  rootElement: [sbom.spdxId],
  element: [sbom.spdxId, ...elementIds.filter((entryId) => entryId !== sbom.spdxId)]
});

const creationInfo = {
  type: 'CreationInfo',
  '@id': CREATION_INFO,
  specVersion: '3.1',
  created: CREATED,
  createdBy: [creator.spdxId],
  createdUsing: [generator.spdxId],
  comment:
    'Every product, organization, requirement, result, identifier, and evidence record in this document is synthetic and fictional.'
};

const output = {
  '@context': 'https://spdx.org/rdf/3.1/spdx-context.jsonld',
  '@graph': [document, ...graph, creationInfo]
};

await mkdir(dirname(OUTPUT), { recursive: true });
await writeFile(OUTPUT, `${JSON.stringify(output, null, 2)}\n`);
console.log(`Wrote ${OUTPUT}`);
console.log(
  `${requirementElements.length} requirements, ${verificationElements.length} verifications, ${evaluationElements.length} evaluations`
);
