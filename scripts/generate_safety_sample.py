#!/usr/bin/env python3
"""Generate the synthetic Functional Safety sample SBOM.

This emits an SPDX 3.1 JSON-LD document that exercises the SPDX 3.1
**FunctionalSafety** profile (https://spdx.github.io/spdx-spec/v3.1-dev/model/FunctionalSafety/),
together with the Core, Software and SimpleLicensing profiles.

The scenario is *entirely fictional*: a SIL 3 emergency-shutdown (ESD)
"Safety Logic Solver" firmware for the process industry, built on a
2-out-of-3 (TMR) architecture with de-energize-to-trip behaviour. No real
product, company, person, test result or certificate is described. It exists
only to demonstrate how safety requirements, verifications, evaluations,
assumptions and their evidence are modelled in SPDX 3.1 and rendered by this
visualizer's Functional Safety view.

Model notes (kept faithful to the 3.1 model):
  * Core `Requirement`            -> requirementStatement / devLifecycleStage /
                                     rationale / requirementUID
  * functionalsafety_RequirementVerification -> verificationMethod (VerificationType
                                     enum), verificationPrecondition/Postcondition,
                                     rationale, verificationUID
  * functionalsafety_EvaluationResult        -> evaluation (pass/fail/inconclusive),
                                     evaluationBasedOn (-> a verification), rationale
                                     (mandatory); inconclusive carries a comment
  * functionalsafety_Assumption              -> assumptionStatement / rationale
  * functionalsafety_EvidenceRelationship    -> a Relationship subclass carrying
                                     evidenceCategory (EvidenceType) + evidenceUID
  * Core RelationshipType values used: implementedBy, verifiedBy, assumes,
                                     conformsTo, hasEvidence, hasRequirement,
                                     contains, dependsOn, usesTool, hasDeclaredLicense,
                                     hasConcludedLicense

The *UID properties (requirementUID, verificationUID, ...) are the canonical
3.1 way to attach a work-product identifier; we also mirror each UID into the
generic Core `externalIdentifier` list so the visualizer (which reads
`externalIdentifier`) surfaces the id chip on the card.

Run:  python3 scripts/generate_safety_sample.py
Out:  samples/safety/esd-3000-safety-controller.spdx3.json
"""

import json
import os

BASE = "https://spdx.example.com/esd3000/"
CI = "_:creationinfo"
CI_RTOS = "_:creationinfo_rtos"
CI_OSS = "_:creationinfo_oss"

graph = []
_rel_seq = 0


def add(obj):
    graph.append(obj)
    return obj["spdxId"] if "spdxId" in obj else obj.get("@id")


def rel(from_id, rtype, to, *, ci=CI, extra=None, rtype_id=None):
    """Append a plain Core Relationship."""
    global _rel_seq
    _rel_seq += 1
    to_list = to if isinstance(to, list) else [to]
    obj = {
        "type": "Relationship",
        "spdxId": f"{BASE}rel/{rtype_id or rtype}-{_rel_seq}",
        "creationInfo": ci,
        "relationshipType": rtype,
        "from": from_id,
        "to": to_list,
    }
    if extra:
        obj.update(extra)
    graph.append(obj)
    return obj["spdxId"]


def ext_id(identifier, id_type="other", locator=None, comment=None):
    o = {
        "type": "ExternalIdentifier",
        "externalIdentifierType": id_type,
        "identifier": identifier,
    }
    if locator:
        o["identifierLocator"] = [locator]
    if comment:
        o["comment"] = comment
    return o


_ev_seq = 0


def _emit_evidence(from_id, ev_keys, uid_prefix):
    """Link evidence artifacts to an element via functionalsafety_EvidenceRelationship.

    EvidenceRelationship is a Core Relationship subclass, so it carries
    from/to/relationshipType (hasEvidence) plus the FunctionalSafety
    evidenceCategory / evidenceUID properties.
    """
    global _ev_seq
    for k in ev_keys:
        fid, cat = EV[k]
        _ev_seq += 1
        evuid = f"EV-{uid_prefix}-{k}"
        graph.append({
            "type": "functionalsafety_EvidenceRelationship",
            "spdxId": f"{BASE}rel/evidence-{_ev_seq}",
            "creationInfo": CI,
            "relationshipType": "hasEvidence",
            "from": from_id,
            "to": [fid],
            "functionalsafety_evidenceCategory": cat,
            "functionalsafety_evidenceUID": ext_id(evuid, "other"),
        })


# ---------------------------------------------------------------------------
# Agents (fictional)
# ---------------------------------------------------------------------------
ORG_SUPPLIER = BASE + "agent/meridian-process-safety"
ORG_RTOS = BASE + "agent/nucleussafe"
ORG_ASSESSOR = BASE + "agent/isap"
PERSON_FSM = BASE + "agent/i-halvorsen"
PERSON_VV = BASE + "agent/m-bianchi"
PERSON_ASSESSOR = BASE + "agent/a-rao"

add({"type": "Organization", "spdxId": ORG_SUPPLIER, "creationInfo": CI,
     "name": "Meridian Process Safety AG",
     "comment": "Fictional supplier of the ESD-3000 safety logic solver."})
add({"type": "Organization", "spdxId": ORG_RTOS, "creationInfo": CI,
     "name": "NucleusSafe GmbH",
     "comment": "Fictional vendor of the pre-certified SIL 3 RTOS."})
add({"type": "Organization", "spdxId": ORG_ASSESSOR, "creationInfo": CI,
     "name": "Independent Safety Assessment Partners (ISAP)",
     "comment": "Fictional independent functional-safety assessor (FSA)."})
add({"type": "Person", "spdxId": PERSON_FSM, "creationInfo": CI,
     "name": "Ingrid Halvorsen",
     "comment": "Fictional Functional Safety Manager (FSM)."})
add({"type": "Person", "spdxId": PERSON_VV, "creationInfo": CI,
     "name": "Marco Bianchi",
     "comment": "Fictional Verification & Validation lead."})
add({"type": "Person", "spdxId": PERSON_ASSESSOR, "creationInfo": CI,
     "name": "Dr. Anaya Rao",
     "comment": "Fictional independent functional-safety assessor."})

add({"type": "CreationInfo", "@id": CI, "specVersion": "3.1.0",
     "createdBy": [ORG_SUPPLIER, PERSON_FSM], "created": "2026-05-20T09:00:00Z"})
add({"type": "CreationInfo", "@id": CI_RTOS, "specVersion": "3.1.0",
     "createdBy": [ORG_RTOS], "created": "2025-11-03T00:00:00Z"})
add({"type": "CreationInfo", "@id": CI_OSS, "specVersion": "3.1.0",
     "createdBy": [ORG_SUPPLIER], "created": "2024-06-01T00:00:00Z"})

# ---------------------------------------------------------------------------
# Licenses
# ---------------------------------------------------------------------------
LIC = {
    "meridian": (BASE + "license/LicenseRef-Meridian-Proprietary",
                 "LicenseRef-Meridian-Proprietary"),
    "nucleussafe": (BASE + "license/LicenseRef-NucleusSafe-Commercial",
                    "LicenseRef-NucleusSafe-Commercial"),
    "bsd3": ("https://spdx.org/licenses/BSD-3-Clause", "BSD-3-Clause"),
    "apache2": ("https://spdx.org/licenses/Apache-2.0", "Apache-2.0"),
    "mit": ("https://spdx.org/licenses/MIT", "MIT"),
}
for key, (lid, expr) in LIC.items():
    add({"type": "simplelicensing_LicenseExpression", "spdxId": lid,
         "creationInfo": CI, "simplelicensing_licenseExpression": expr,
         "simplelicensing_licenseListVersion": "3.25.0"})


# ---------------------------------------------------------------------------
# Packages
# ---------------------------------------------------------------------------
# key -> (name, version, purpose, license_key, supplier, ci, comment)
PKG_DEFS = [
    ("firmware", "ESD-3000 Safety Logic Solver Firmware", "3.2.0", "application",
     "meridian", ORG_SUPPLIER, CI,
     "SIL 3 emergency-shutdown (ESD) logic solver firmware. 2oo3 (TMR) "
     "architecture, de-energize-to-trip. Systematic capability SC 3 (IEC 61508-3). "
     "SYNTHETIC / FICTIONAL sample data."),
    ("safety_kernel", "libsafe-rt (Safety Runtime Executive)", "2.4.1", "library",
     "meridian", ORG_SUPPLIER, CI,
     "Deterministic, statically-scheduled safety executive with program-flow "
     "monitoring. Developed to SC 3 (SIL 3)."),
    ("rtos", "SafeRTOS-IEC (pre-certified RTOS kernel)", "9.1.0", "operatingSystem",
     "nucleussafe", ORG_RTOS, CI_RTOS,
     "Third-party RTOS kernel delivered with an IEC 61508 SIL 3 safety manual and "
     "certificate (fictional). Provides MPU-backed temporal/spatial partitioning."),
    ("voter", "tmr-voter (2oo3 Voting Engine)", "1.7.0", "library",
     "meridian", ORG_SUPPLIER, CI,
     "2-out-of-3 majority voter over the three independent processing channels. SIL 3."),
    ("io_diag", "io-diag (I/O Diagnostics & Line Monitoring)", "3.0.2", "library",
     "meridian", ORG_SUPPLIER, CI,
     "Analog/digital I/O diagnostics: line-open/short monitoring, reference checks. SIL 3."),
    ("self_test", "cpu-selftest (POST/BIST Self-Test Library)", "2.2.0", "library",
     "meridian", ORG_SUPPLIER, CI,
     "Power-on and cyclic self-tests: March-C+ RAM test, CPU register/ALU test, "
     "program-memory CRC. Contributes to diagnostic coverage. SIL 3."),
    ("wdt", "wdt-monitor (Windowed Watchdog Supervisor)", "1.3.4", "library",
     "meridian", ORG_SUPPLIER, CI,
     "Windowed (question/answer) watchdog serviced only from the main safety loop. SIL 3."),
    ("safe_comms", "safebus (Black-Channel Safety Protocol)", "4.1.0", "library",
     "meridian", ORG_SUPPLIER, CI,
     "Safety layer over an untrusted (black-channel) transport: CRC, sequence "
     "number, timeout, connection ID. SIL 3."),
    ("sensor_val", "sensor-validate (Range & Rate Validation)", "2.0.5", "library",
     "meridian", ORG_SUPPLIER, CI,
     "Range, rate-of-change, stuck-signal and redundant cross-check validation of "
     "process inputs. SIL 3."),
    ("safe_state", "safe-state-mgr (De-energize-to-Trip Manager)", "1.5.0", "library",
     "meridian", ORG_SUPPLIER, CI,
     "Latching safe-state manager driving redundant output switching elements to "
     "the de-energized state. SIL 3."),
    ("crc_lib", "crc-safe (Safety CRC/Checksum Library)", "1.2.0", "library",
     "bsd3", ORG_SUPPLIER, CI_OSS,
     "Open-source CRC-32 implementation, adopted and re-qualified for safety use "
     "under IEC 61508-3 §7.4.2.12 (SEooC / proven-in-use assessment)."),
    ("hal", "hal-esd (Hardware Abstraction Layer)", "3.3.0", "library",
     "meridian", ORG_SUPPLIER, CI,
     "Hardware abstraction and MPU configuration. Developed to SIL 2 with SIL 3 "
     "diagnostic interfaces."),
    ("hmi_gw", "hmi-gateway (Read-only HMI Gateway)", "5.0.1", "application",
     "mit", ORG_SUPPLIER, CI,
     "Non-safety (QM) read-only gateway. Isolated by MPU partitioning; cannot "
     "command safety outputs (freedom-from-interference argument)."),
    ("logger", "event-logger (Sequence-of-Events Logger)", "2.6.0", "library",
     "apache2", ORG_SUPPLIER, CI,
     "Non-safety (QM) sequence-of-events (SoE) logger for diagnostics annunciation."),
    ("config_loader", "config-loader (Validated Parameter Loader)", "1.4.0", "library",
     "meridian", ORG_SUPPLIER, CI,
     "Loads and validates (CRC + range) safety parameters before allowing the "
     "operational state. SIL 3."),
]
PKG = {}
for key, name, ver, purpose, lic, supplier, ci, comment in PKG_DEFS:
    pid = BASE + "package/" + key
    PKG[key] = pid
    obj = {
        "type": "software_Package", "spdxId": pid, "creationInfo": ci,
        "name": name, "software_packageVersion": ver,
        "software_primaryPurpose": purpose, "suppliedBy": supplier,
        "software_copyrightText": "Copyright (c) Meridian Process Safety AG (fictional)."
        if lic == "meridian" else "NOASSERTION",
        "comment": comment,
    }
    if key == "firmware":
        obj["description"] = (
            "SYNTHETIC / FICTIONAL functional-safety SBOM. ESD-3000 is an imaginary "
            "SIL 3 emergency-shutdown logic solver used purely to demonstrate the "
            "SPDX 3.1 FunctionalSafety profile. No real product or evidence.")
        obj["software_downloadLocation"] = "NOASSERTION"
    PKG[key] = pid
    add(obj)
    # licenses
    lid = LIC[lic][0]
    rel(pid, "hasDeclaredLicense", lid, ci=ci)
    rel(pid, "hasConcludedLicense", lid, ci=ci)

# Containment + dependencies
SUBSYSTEMS = [k for k, *_ in PKG_DEFS if k != "firmware"]
rel(PKG["firmware"], "contains", [PKG[k] for k in SUBSYSTEMS])
rel(PKG["firmware"], "dependsOn", [PKG["rtos"], PKG["crc_lib"]])

# ---------------------------------------------------------------------------
# Source files
# ---------------------------------------------------------------------------
# key -> (path, parent_pkg, comment)
FILE_DEFS = [
    ("scheduler_c", "/src/kernel/scheduler.c", "safety_kernel",
     "Strictly-periodic safety scheduler; no dynamic allocation after init."),
    ("flow_mon_c", "/src/kernel/flow_monitor.c", "safety_kernel",
     "Program-flow / control-flow monitoring of the safety loop."),
    ("health_mon_c", "/src/kernel/health_monitor.c", "safety_kernel",
     "Aggregates diagnostic results and drives the fault-reaction state machine."),
    ("tmr_vote_c", "/src/voter/tmr_vote.c", "voter",
     "2oo3 majority voting and channel-discrepancy detection."),
    ("march_c", "/src/selftest/march_c.c", "self_test",
     "March-C+ RAM test over safety-related RAM."),
    ("reg_test_c", "/src/selftest/register_test.c", "self_test",
     "CPU register and ALU diverse-instruction test."),
    ("rom_crc_c", "/src/selftest/rom_crc.c", "self_test",
     "Program-memory CRC-32 signature check (start-up + cyclic)."),
    ("wdt_c", "/src/wdt/windowed_wdt.c", "wdt",
     "Windowed watchdog question/answer servicing."),
    ("safebus_layer_c", "/src/comms/safebus_layer.c", "safe_comms",
     "Black-channel safety layer: sequence number, timeout, connection ID."),
    ("safebus_crc_c", "/src/comms/safebus_crc.c", "safe_comms",
     "Independent safety CRC over safety messages."),
    ("range_check_c", "/src/sensor/range_check.c", "sensor_val",
     "Per-cycle engineering-range validation of analog inputs."),
    ("rate_limit_c", "/src/sensor/rate_limit.c", "sensor_val",
     "Rate-of-change plausibility and stuck-signal detection."),
    ("xcheck_c", "/src/sensor/cross_check.c", "sensor_val",
     "Redundant-transmitter cross-check and discrepancy fault."),
    ("io_diag_c", "/src/io/io_diag.c", "io_diag",
     "Analog/digital input & output diagnostics."),
    ("line_mon_c", "/src/io/line_monitor.c", "io_diag",
     "Open-circuit / short-circuit line monitoring."),
    ("de_energize_c", "/src/state/de_energize.c", "safe_state",
     "Drives redundant output switching elements to the de-energized state."),
    ("safe_state_c", "/src/state/safe_state_mgr.c", "safe_state",
     "Latching safe-state manager and authenticated-reset handling."),
    ("crc32_c", "/src/crc/crc32.c", "crc_lib",
     "CRC-32 primitive (open source, re-qualified for safety use)."),
    ("param_verify_c", "/src/config/param_verify.c", "config_loader",
     "Parameter CRC + range validation before operational state."),
    ("mpu_cfg_c", "/src/hal/mpu_config.c", "hal",
     "MPU region configuration enforcing spatial partitioning (FFI)."),
]
FILE = {}
for key, path, parent, comment in FILE_DEFS:
    fid = BASE + "file/" + key
    FILE[key] = fid
    add({"type": "software_File", "spdxId": fid, "creationInfo": CI,
         "name": path, "software_primaryPurpose": "source",
         "software_fileKind": "file", "comment": comment})
# per-package containment of files
from collections import defaultdict
_by_pkg = defaultdict(list)
for key, path, parent, comment in FILE_DEFS:
    _by_pkg[parent].append(FILE[key])
for parent, fids in _by_pkg.items():
    rel(PKG[parent], "contains", fids)

# ---------------------------------------------------------------------------
# Evidence / documentation artifacts
# ---------------------------------------------------------------------------
# key -> (path, evidence_category, comment)
EV_DEFS = [
    ("fmeda_report", "/safety/FMEDA_ESD3000_v3.2.pdf", "report",
     "FMEDA computing SFF and diagnostic coverage for the safety function."),
    ("sa_report", "/verification/StaticAnalysis_MISRA_Report.pdf", "report",
     "MISRA C:2012 static-analysis report with justified deviations."),
    ("wcet_report", "/verification/WCET_Analysis_Report.pdf", "report",
     "Static worst-case execution-time analysis of the safety loop."),
    ("hil_report", "/verification/HIL_VnV_Test_Report.pdf", "report",
     "Hardware-in-the-loop fault-injection test report."),
    ("unit_report", "/verification/UnitTest_Coverage_Report.html", "report",
     "Unit-test results with statement and MC/DC structural coverage."),
    ("integration_report", "/verification/Integration_Test_Report.pdf", "report",
     "Software integration test report."),
    ("mc_report", "/verification/ModelChecking_Report.pdf", "report",
     "Bounded model-checking report for selected safety properties."),
    ("review_records", "/verification/Code_Review_Records.pdf", "observation",
     "Signed code-review and inspection records with checklists."),
    ("soe_log", "/verification/HIL_SequenceOfEvents.log", "log",
     "Sequence-of-events log captured during HIL fault injection."),
    ("tool_qual_report", "/safety/Tool_Qualification_Report.pdf", "report",
     "Tool classification/qualification report per IEC 61508-3 §7.4.4."),
    ("safety_manual", "/safety/Safety_Manual_ESD3000.pdf", "report",
     "Safety manual: assumptions of use, proof-test interval, PFDavg."),
    ("srs_doc", "/safety/SW_Safety_Requirements_Spec.pdf", "report",
     "Software safety requirements specification (source of SRS-SW-*)."),
    ("safety_case", "/safety/Safety_Case_Report.pdf", "report",
     "Compiled safety case referencing all verification evidence."),
]
EV = {}
for key, path, cat, comment in EV_DEFS:
    fid = BASE + "evidence/" + key
    EV[key] = (fid, cat)
    add({"type": "software_File", "spdxId": fid, "creationInfo": CI,
         "name": path, "software_primaryPurpose": "documentation",
         "software_fileKind": "file", "comment": comment})

# ---------------------------------------------------------------------------
# Tools (with IEC 61508 tool class in the comment)
# ---------------------------------------------------------------------------
# key -> (name, version, comment)
TOOL_DEFS = [
    ("iar", "IAR Embedded Workbench for Arm (Functional Safety Edition)", "9.50",
     "C/C++ compiler & linker. Delivered with a functional-safety certificate "
     "(fictional); tool confidence: qualified, IEC 61508-3 tool class T3."),
    ("ldra", "LDRA tool suite", "20.1",
     "MISRA C:2012 static analysis & coding-standard checking. Tool class T2, "
     "qualified per IEC 61508-3 §7.4.4 (fictional qualification)."),
    ("vectorcast", "VectorCAST", "2024",
     "Unit / integration test execution and statement + MC/DC coverage. Tool class T2."),
    ("cbmc", "CBMC (C Bounded Model Checker)", "5.95",
     "Bounded model checking of selected safety properties. Tool class T2 for the "
     "qualified property set (fictional)."),
    ("ait", "AbsInt aiT WCET Analyzer", "23.10",
     "Static worst-case execution-time analysis. Tool class T2."),
    ("medini", "Ansys medini analyze", "2024 R1",
     "FMEDA / safety-analysis tool. Tool class T2."),
    ("hil_bench", "Meridian HIL Safety Test Bench", "R7",
     "In-house hardware-in-the-loop fault-injection rig. Tool class T3, qualified "
     "by validation against reference faults (fictional)."),
    ("git", "Git", "2.44",
     "Configuration management / version control. Tool class T1."),
]
TOOL = {}
for key, name, ver, comment in TOOL_DEFS:
    tid = BASE + "tool/" + key
    TOOL[key] = tid
    add({"type": "Tool", "spdxId": tid, "creationInfo": CI, "name": name,
         "software_packageVersion": ver, "comment": comment,
         "externalIdentifier": [ext_id(f"{name} {ver}", "other",
                                        comment="Tool identification for tool qualification.")]})
rel(PKG["firmware"], "usesTool", [TOOL["iar"], TOOL["git"]])

# ---------------------------------------------------------------------------
# Assumptions of use (safety manual) + conformsTo baselines
# ---------------------------------------------------------------------------
# aid -> (name, statement, rationale, is_baseline)
ASSUMPTION_DEFS = [
    ("AoU-01", "Periodic proof test",
     "The end user performs a full proof test of the safety function at intervals "
     "not exceeding 12 months, as described in the safety manual.",
     "The claimed PFDavg for the SIL 3 safety function is only achieved with this "
     "proof-test interval.", False),
    ("AoU-02", "De-energize-to-trip wiring",
     "Final elements are wired de-energize-to-trip, so that loss of output power "
     "results in the process safe state.",
     "The logic solver commands the safe state by removing output power; the field "
     "wiring must translate that into the physical safe state.", False),
    ("AoU-03", "Environmental limits",
     "The controller is operated within the specified environmental limits "
     "(-25 to +70 C, condensation-free), per the safety manual.",
     "Failure rates and diagnostic assumptions in the FMEDA are only valid inside "
     "the qualified environment.", False),
    ("AoU-04", "SIL of sensors and final elements",
     "Field sensors and final elements are selected and maintained to at least the "
     "SIL claimed for the overall safety instrumented function.",
     "The logic solver contributes only its allocated portion of the SIF's PFDavg.",
     False),
    ("AoU-05", "Configuration by qualified personnel",
     "Safety parameters are configured only by personnel trained on the engineering "
     "tool, and the configuration is independently verified before commissioning.",
     "Systematic configuration faults are controlled by competence and independent "
     "review, not by the logic solver alone.", False),
    ("AoU-06", "Monitored power supply",
     "A monitored, adequately-rated power supply is provided; loss or out-of-tolerance "
     "supply is detected and drives the system to the safe state.",
     "Power-supply integrity is a precondition for the diagnostics to run.", False),
    ("AoU-07", "EMC and surge immunity",
     "The installation meets the EMC and surge-immunity assumptions (IEC 61326-3-1) "
     "used in the safety analysis.",
     "The residual-error-rate calculation of the safety communication layer assumes "
     "a bounded bit-error rate.", False),
    ("AoU-08", "No defeat of hardware fault tolerance",
     "External wiring and installation do not defeat the internal 2oo3 architecture; "
     "the recommended channel separation is applied.",
     "Common-cause failures could otherwise undermine the HFT=1 claim.", False),
    ("AoU-09", "Management of change for updates",
     "Firmware is not updated while the safety function is in operation; updates "
     "follow the documented management-of-change procedure.",
     "Online reprogramming is outside the analysed operational context.", False),
    # conformsTo baselines (modelled as Assumptions: normative constraints on use)
    ("BASE-61508", "IEC 61508 compliance baseline",
     "The software safety lifecycle conforms to IEC 61508-3:2010 (route 1S), "
     "achieving systematic capability SC 3 for a SIL 3 safety function.",
     "Establishes the normative development baseline the product claims conformance to.",
     True),
    ("BASE-MISRA", "MISRA C:2012 coding baseline",
     "Safety-related C code conforms to MISRA C:2012 (Amendment 2), with documented "
     "and approved deviations only.",
     "Establishes the coding-standard baseline the safety components conform to.",
     True),
]
ASSUM = {}
for aid, name, statement, rationale, is_baseline in ASSUMPTION_DEFS:
    sid = BASE + "assumption/" + aid
    ASSUM[aid] = sid
    add({
        "type": "functionalsafety_Assumption", "spdxId": sid, "creationInfo": CI,
        "name": f"{aid}: {name}",
        "functionalsafety_assumptionStatement": statement,
        "rationale": rationale,
        "functionalsafety_assumptionUID": ext_id(aid, "other"),
        "externalIdentifier": [ext_id(aid, "other",
                                      comment="Assumption of use identifier.")],
    })

# firmware-level assumptions of use
rel(PKG["firmware"], "assumes",
    [ASSUM[a] for a in ("AoU-03", "AoU-04", "AoU-05", "AoU-06", "AoU-08", "AoU-09")])
# conformsTo the normative baselines
rel(PKG["firmware"], "conformsTo", [ASSUM["BASE-61508"]])
for k in ("safety_kernel", "voter", "safe_state", "safe_comms", "self_test"):
    rel(PKG[k], "conformsTo", [ASSUM["BASE-MISRA"]])

# ---------------------------------------------------------------------------
# Verification-method templates
# ---------------------------------------------------------------------------
# tag -> (VerificationType enum, title, precondition, postcondition, evidence, tools)
VKIND = {
    "unit": ("test", "Unit test (statement + MC/DC coverage)",
             "Unit-test harness built with the qualified test tool; hardware I/O replaced by stubs.",
             "All test cases pass; 100% statement and MC/DC structural coverage achieved or justified.",
             ["unit_report"], ["vectorcast"]),
    "integration": ("test", "Software integration test",
                    "Integrated safety components running on the target with the RTOS.",
                    "Interfaces behave as specified across component boundaries; no regressions.",
                    ["integration_report"], ["vectorcast"]),
    "hil": ("test", "Hardware-in-the-loop fault-injection test",
            "ESD-3000 target on the HIL bench with fault-injection harness on I/O and power rails.",
            "The safe state is reached within the required time for every injected fault; events logged.",
            ["hil_report", "soe_log"], ["hil_bench"]),
    "fault": ("test", "Fault insertion test",
              "Single faults inserted at the pin/register level while the safety loop runs.",
              "Each inserted fault is detected and annunciated within the diagnostic test interval.",
              ["hil_report", "soe_log"], ["hil_bench"]),
    "misra": ("analysis", "Static analysis - MISRA C:2012 (mandatory + required)",
              "Full safety codebase analysed with the qualified static-analysis tool and project MISRA profile.",
              "No unresolved mandatory/required violations; all deviations individually justified and approved.",
              ["sa_report"], ["ldra"]),
    "wcet": ("analysis", "Static worst-case execution-time analysis",
             "Safety loop object code analysed with the WCET tool against the target microarchitecture.",
             "Computed WCET is within the configured cycle-time budget with margin.",
             ["wcet_report"], ["ait"]),
    "cbmc": ("analysis", "Bounded model checking",
             "Property harness and environment assumptions supplied to the model checker.",
             "The safety property holds within the analysed bound with no counterexample.",
             ["mc_report"], ["cbmc"]),
    "fmeda": ("analysis", "FMEDA (failure modes, effects and diagnostic analysis)",
              "Component failure-rate database and diagnostic assumptions loaded into the FMEDA tool.",
              "Computed SFF and diagnostic coverage meet the SIL 3 targets for the safety function.",
              ["fmeda_report"], ["medini"]),
    "review": ("review", "Peer code review",
               "Two independent reviewers using the safety code-review checklist.",
               "All findings resolved or dispositioned; checklist complete and signed off.",
               ["review_records"], []),
    "inspection": ("inspection", "Design inspection",
                   "Formal inspection of the design against its upper-level requirement, with a checklist and recorded roles.",
                   "Acceptance criteria met; inspector independence documented.",
                   ["review_records"], []),
    "demo": ("demonstration", "On-target demonstration",
             "Integrated system on the HIL bench under nominal and boundary conditions.",
             "Observed behaviour matches the requirement; recording archived.",
             ["hil_report"], ["hil_bench"]),
    "assessment": ("assessment", "Independent assessment",
                   "Work products provided to the independent assessor with the assessment plan.",
                   "Assessor judges the objective met; rationale and any conditions recorded.",
                   ["safety_case"], []),
}

# ---------------------------------------------------------------------------
# Requirements
# ---------------------------------------------------------------------------
# Each requirement:
#   uid, name, statement, stage, owner(pkg key), impl(list of file/pkg keys),
#   assumes(list of aids), sil_note, hazard,
#   verifs: list of dicts {kind, result(pass/fail/inconclusive/None), comment?, rationale?}
R = []


def req(uid, name, statement, stage, owner, impl, verifs,
        assumes=None, sil="SIL 3", hazard=None):
    R.append({
        "uid": uid, "name": name, "statement": statement, "stage": stage,
        "owner": owner, "impl": impl, "verifs": verifs,
        "assumes": assumes or [], "sil": sil, "hazard": hazard,
    })


# --- A. Safe state, voting, output path ---
req("SRS-SW-001", "Safe state on demand",
    "On a validated shutdown demand the software shall command the safety outputs to the "
    "de-energized (safe) state within the process safety time of 100 ms.",
    "runtime", "safe_state", ["de_energize_c", "safe_state_c"],
    [{"kind": "hil", "result": "pass"}, {"kind": "cbmc", "result": "pass"}],
    assumes=["AoU-02"], hazard="H-01: failure to de-energize the final element on demand")
req("SRS-SW-002", "De-energize-to-trip triggers",
    "The software shall treat loss of the output-enable signal, an internal dangerous "
    "fault, or watchdog expiry as a demand to enter the safe state.",
    "runtime", "safe_state", ["safe_state_c", "health_mon_c"],
    [{"kind": "hil", "result": "pass"}, {"kind": "review", "result": "pass"}],
    hazard="H-01")
req("SRS-SW-003", "2oo3 majority voting",
    "The application shall determine the shutdown decision by 2-out-of-3 majority voting "
    "over the three independent processing channels.",
    "design", "voter", ["tmr_vote_c"],
    [{"kind": "unit", "result": "pass"}, {"kind": "cbmc", "result": "pass"}],
    hazard="H-02: undetected single-channel fault causes wrong decision")
req("SRS-SW-004", "Latched safe state",
    "Once entered, the safe state shall be latched and shall require an authenticated "
    "manual reset to clear.",
    "runtime", "safe_state", ["safe_state_c"],
    [{"kind": "unit", "result": "pass"}, {"kind": "hil", "result": "pass"}])
req("SRS-SW-005", "Independent output paths",
    "The software shall drive the two redundant output switching elements over "
    "independent code paths and I/O ports.",
    "design", "safe_state", ["de_energize_c", "io_diag_c"],
    [{"kind": "review", "result": "pass"}, {"kind": "fault", "result": "pass"}])
req("SRS-SW-006", "Channel-discrepancy detection",
    "The voter shall flag and log any channel whose result discrepates from the majority "
    "for more than two consecutive cycles.",
    "runtime", "voter", ["tmr_vote_c"],
    [{"kind": "unit", "result": "pass"}, {"kind": "fault", "result": "pass"}])

# --- B. Sensor input validation ---
req("SRS-SW-010", "Analog input range check",
    "Each analog process input shall be validated against its configured engineering "
    "range (4-20 mA / 0.5-4.5 V) every acquisition cycle; out-of-range inputs shall be "
    "marked invalid.",
    "runtime", "sensor_val", ["range_check_c"],
    [{"kind": "unit", "result": "pass"}])
req("SRS-SW-011", "Rate-of-change plausibility",
    "The software shall reject sensor samples whose rate of change exceeds the configured "
    "plausibility limit and substitute the last valid value for at most three cycles "
    "before declaring a fault.",
    "runtime", "sensor_val", ["rate_limit_c"],
    [{"kind": "unit", "result": "pass"},
     {"kind": "hil", "result": "fail",
      "comment": "Defect DEF-2231: at the 3-cycle boundary a fast ramp was accepted for "
                 "one extra cycle before the fault was declared. Fix in progress; retest planned.",
      "rationale": "HIL ramp-injection at the plausibility boundary revealed an "
                   "off-by-one in the substitution counter."}],
    hazard="H-03: accepting an implausible sensor value delays a trip")
req("SRS-SW-012", "Redundant transmitter cross-check",
    "Where a measurement is provided by redundant transmitters, the software shall compare "
    "them and declare a discrepancy fault if they diverge by more than the configured tolerance.",
    "runtime", "sensor_val", ["xcheck_c"],
    [{"kind": "unit", "result": "pass"}, {"kind": "hil", "result": "pass"}])
req("SRS-SW-013", "Line monitoring",
    "The I/O layer shall detect open-circuit and short-circuit line faults on each safety "
    "input and output channel via line-monitoring diagnostics.",
    "runtime", "io_diag", ["line_mon_c", "io_diag_c"],
    [{"kind": "fault", "result": "pass"}, {"kind": "fmeda", "result": "pass"}])
req("SRS-SW-014", "Stuck-signal detection",
    "The software shall detect a frozen analog input (no change over the configured "
    "stuck-at window) and mark the channel faulted.",
    "runtime", "sensor_val", ["rate_limit_c"],
    [{"kind": "unit", "result": "pass"}, {"kind": "fault", "result": "pass"}])

# --- C. Diagnostics / self-test ---
req("SRS-SW-020", "Cyclic RAM test",
    "The self-test library shall execute a March-C+ test over all safety-related RAM "
    "within each diagnostic test interval of 1 s.",
    "runtime", "self_test", ["march_c"],
    [{"kind": "unit", "result": "pass"}, {"kind": "fault", "result": "pass"}])
req("SRS-SW-021", "Program-memory CRC",
    "The software shall verify the integrity of safety-related program memory using a "
    "CRC-32 signature checked at start-up and cyclically within the diagnostic test interval.",
    "runtime", "self_test", ["rom_crc_c", "crc32_c"],
    [{"kind": "unit", "result": "pass"}, {"kind": "fault", "result": "pass"}])
req("SRS-SW-022", "CPU register/ALU test",
    "The self-test library shall verify the CPU core register set and ALU using a diverse "
    "instruction test sequence within each diagnostic test interval.",
    "runtime", "self_test", ["reg_test_c"],
    [{"kind": "unit", "result": "pass"}, {"kind": "fmeda", "result": "pass"}])
req("SRS-SW-023", "Diagnostic coverage target",
    "The aggregate diagnostic coverage of the software-implemented diagnostics shall be "
    ">= 99% (high) for the safety function, consistent with the SIL 3 FMEDA.",
    "design", "self_test", ["health_mon_c", "march_c", "rom_crc_c", "reg_test_c"],
    [{"kind": "fmeda", "result": "pass"}],
    assumes=["AoU-01"], hazard="H-04: undetected dangerous fault accumulates")
req("SRS-SW-024", "Windowed watchdog",
    "A windowed watchdog shall be serviced only from the main safety loop within its open "
    "window; early or late service shall force the safe state.",
    "runtime", "wdt", ["wdt_c"],
    [{"kind": "hil", "result": "pass"}, {"kind": "unit", "result": "pass"}])
req("SRS-SW-025", "Program-flow monitoring",
    "The software shall monitor control-flow of the safety loop and force the safe state "
    "on any detected sequence or timing deviation.",
    "runtime", "safety_kernel", ["flow_mon_c"],
    [{"kind": "fault", "result": "pass"}, {"kind": "review", "result": "pass"}])
req("SRS-SW-026", "Fault annunciation",
    "Every detected dangerous fault shall be annunciated within 1 s via the diagnostic "
    "status output and the sequence-of-events log.",
    "runtime", "io_diag", ["health_mon_c", "io_diag_c"],
    [])  # deliberately unverified (V&V in progress) -> shows "Unverified" status

# --- D. Safety communication (black channel) ---
req("SRS-SW-030", "Independent safety CRC",
    "Safety messages exchanged over the backplane and fieldbus shall be protected by a CRC "
    "independent of any transport-layer checksum.",
    "design", "safe_comms", ["safebus_crc_c"],
    [{"kind": "unit", "result": "pass"}, {"kind": "cbmc", "result": "pass"}])
req("SRS-SW-031", "Message sequence number",
    "Each safety message shall carry a monotonic sequence number; the receiver shall reject "
    "duplicated, out-of-order, or lost messages.",
    "runtime", "safe_comms", ["safebus_layer_c"],
    [{"kind": "unit", "result": "pass"}, {"kind": "cbmc", "result": "pass"}])
req("SRS-SW-032", "Communication watchdog",
    "The receiver shall enter the safe state if a valid safety message is not received "
    "within the configured communication watchdog time.",
    "runtime", "safe_comms", ["safebus_layer_c"],
    [{"kind": "hil", "result": "pass"}])
req("SRS-SW-033", "Connection authenticity",
    "Each safety connection shall be identified by a unique connection ID; messages with an "
    "unexpected connection ID shall be discarded.",
    "runtime", "safe_comms", ["safebus_layer_c"],
    [{"kind": "unit", "result": "pass"}, {"kind": "review", "result": "pass"}])
req("SRS-SW-034", "Residual error rate",
    "The safety communication layer shall achieve a residual error rate consistent with "
    "SIL 3 for the configured bit-error-rate assumption.",
    "design", "safe_comms", ["safebus_crc_c", "safebus_layer_c"],
    [{"kind": "fmeda", "result": None}],   # verification done, evaluation pending -> "Verified"
    assumes=["AoU-07"])

# --- E. Architecture / freedom from interference ---
req("SRS-SW-040", "Freedom from interference",
    "Non-safety functions (HMI gateway, event logger) shall not be able to interfere with "
    "safety functions in time, memory, or execution; spatial and temporal partitioning "
    "shall be enforced by the MPU and the RTOS.",
    "design", "hal", ["mpu_cfg_c", "scheduler_c"],
    [{"kind": "inspection", "result": "pass"}, {"kind": "fault", "result": "pass"}],
    hazard="H-05: a non-safety task corrupts safety state")
req("SRS-SW-041", "Memory protection enforcement",
    "The MPU shall be configured so that safety tasks cannot be corrupted by non-safety "
    "tasks, and any protection violation shall force the safe state.",
    "runtime", "hal", ["mpu_cfg_c"],
    [{"kind": "fault", "result": "pass"}, {"kind": "unit", "result": "pass"}])
req("SRS-SW-042", "Read-only HMI access",
    "The HMI gateway shall have read-only access to safety data and shall not be able to "
    "command any safety output.",
    "design", "hmi_gw", ["mpu_cfg_c"],
    [{"kind": "inspection", "result": "pass"}])
req("SRS-SW-043", "Channel independence",
    "The three processing channels shall execute independent object code with no shared "
    "mutable safety state other than the voted result.",
    "design", "voter", ["tmr_vote_c", "scheduler_c"],
    [{"kind": "review", "result": "pass"}])

# --- F. Timing ---
req("SRS-SW-050", "Cycle-time budget",
    "The safety loop shall complete within its configured cycle time of 20 ms under "
    "worst-case execution time (WCET).",
    "test", "safety_kernel", ["scheduler_c"],
    [{"kind": "wcet", "result": "pass"}, {"kind": "demo", "result": "pass"}])
req("SRS-SW-051", "Fault-reaction-time margin",
    "The total fault-detection-to-safe-state time shall not exceed 50% of the process "
    "safety time under any single fault.",
    "test", "safety_kernel", ["health_mon_c", "safe_state_c"],
    [{"kind": "hil", "result": "pass"}, {"kind": "wcet", "result": "pass"}])
req("SRS-SW-052", "Deterministic scheduling",
    "The safety scheduler shall be strictly periodic and free of dynamic memory allocation "
    "after initialization.",
    "design", "safety_kernel", ["scheduler_c"],
    [{"kind": "misra", "result": "pass"}, {"kind": "review", "result": "pass"}])

# --- G. Configuration ---
req("SRS-SW-060", "Validated configuration",
    "Safety-relevant configuration parameters shall be loaded only after a CRC and range "
    "validation; an invalid configuration shall prevent transition to the operational state.",
    "runtime", "config_loader", ["param_verify_c", "crc32_c"],
    [{"kind": "unit", "result": "pass"}, {"kind": "hil", "result": "pass"}],
    assumes=["AoU-05"])
req("SRS-SW-061", "Runtime write protection",
    "Safety parameters shall be write-protected at runtime and modifiable only via the "
    "authenticated engineering interface with a two-stage confirmation.",
    "runtime", "config_loader", ["param_verify_c"],
    [{"kind": "review", "result": "pass"}])

# --- H. Systematic capability / process ---
req("SRS-SW-070", "MISRA C:2012 conformance",
    "All safety-related source code shall conform to MISRA C:2012 (mandatory and required "
    "rules); deviations shall be individually justified and approved.",
    "development", "safety_kernel",
    ["scheduler_c", "tmr_vote_c", "safe_state_c", "safebus_layer_c"],
    [{"kind": "misra", "result": "pass"}])
req("SRS-SW-071", "Structural coverage",
    "Safety-related code shall achieve 100% statement and MC/DC structural coverage during "
    "unit verification; shortfalls shall be justified.",
    "test", "safety_kernel", ["scheduler_c", "tmr_vote_c"],
    [{"kind": "unit", "result": "inconclusive",
      "comment": "MC/DC coverage at 98.7%: two decisions in the error-handling of "
                 "safebus_layer.c are not yet exercised. Coverage-shortfall justification "
                 "under review by the FSM; treated as inconclusive until dispositioned.",
      "rationale": "Structural-coverage measurement is complete but the shortfall waiver "
                   "has not yet been approved."}])
req("SRS-SW-072", "Tool qualification",
    "Software tools that can introduce or fail to detect faults in the safety function "
    "shall be qualified/classified per IEC 61508-3 §7.4.4.",
    "development", "firmware",
    ["scheduler_c"],
    [{"kind": "assessment", "result": "pass",
      "rationale": "Tool classification (T1-T3) and qualification evidence reviewed by the "
                   "independent assessor; all class T3 tools carry qualification."}])
req("SRS-SW-073", "Defensive programming",
    "Safety functions shall use defensive programming: range checks on all external inputs, "
    "default-safe switch cases, and no reliance on undefined behaviour.",
    "development", "safety_kernel", ["range_check_c", "safebus_layer_c"],
    [{"kind": "misra", "result": "pass"}, {"kind": "review", "result": "pass"}])

# --- I. Fault reaction / degradation ---
req("SRS-SW-080", "Fail-safe on diagnostic defeat",
    "On detection of a fault that defeats a diagnostic, the software shall enter the safe "
    "state within the diagnostic test interval rather than continue operation.",
    "runtime", "safety_kernel", ["health_mon_c", "safe_state_c"],
    [{"kind": "fault", "result": "pass"}, {"kind": "fmeda", "result": "pass"}])
req("SRS-SW-081", "No automatic restart",
    "Following a safe-state trip caused by an internal fault, the software shall not restart "
    "the safety function automatically; a diagnostic self-check and manual reset shall be "
    "required.",
    "runtime", "safe_state", ["safe_state_c", "health_mon_c"],
    [{"kind": "hil", "result": "pass"}, {"kind": "review", "result": "pass"}])


# ---------------------------------------------------------------------------
# Emit requirements, verifications, evaluations, and their relationships
# ---------------------------------------------------------------------------
ALM = "https://alm.spdx.example.com/esd3000/"  # fictional requirements-tool base URL

for r in R:
    uid = r["uid"]
    rid = BASE + "requirement/" + uid
    comment = f"{r['sil']}, systematic capability SC 3."
    if r["hazard"]:
        comment += f" Traces to hazard {r['hazard']}."
    add({
        "type": "Requirement", "spdxId": rid, "creationInfo": CI,
        "name": f"{uid}: {r['name']}",
        "requirementStatement": r["statement"],
        "devLifecycleStage": r["stage"],
        "rationale": comment,
        "comment": comment,
        "requirementUID": ext_id(uid, "other", locator=f"{ALM}req/{uid}"),
        "externalIdentifier": [ext_id(uid, "other", locator=f"{ALM}req/{uid}",
                                      comment="Software safety requirement UID.")],
    })

    # owner package "has a requirement on" this Requirement (traceability)
    rel(PKG[r["owner"]], "hasRequirement", [rid])

    # implementedBy the source files / packages
    impl_ids = []
    for k in r["impl"]:
        impl_ids.append(FILE[k] if k in FILE else PKG[k])
    if impl_ids:
        rel(rid, "implementedBy", impl_ids)

    # assumptions
    if r["assumes"]:
        rel(rid, "assumes", [ASSUM[a] for a in r["assumes"]])

    # verifications + evaluations
    verif_ids = []
    for i, v in enumerate(r["verifs"], start=1):
        method, title, pre, post, ev_keys, tool_keys = VKIND[v["kind"]]
        vuid = f"{uid}-V{i}"
        vid = BASE + "verification/" + vuid
        verif_ids.append(vid)
        vrationale = v.get("rationale",
                           f"{title} selected to verify {uid}; method appropriate for the "
                           f"claimed SIL 3 and the nature of the requirement.")
        add({
            "type": "functionalsafety_RequirementVerification", "spdxId": vid,
            "creationInfo": CI, "name": f"{vuid}: {title}",
            "functionalsafety_verificationMethod": method,
            "functionalsafety_verificationPrecondition": pre,
            "functionalsafety_verificationPostcondition": post,
            "rationale": vrationale,
            "functionalsafety_verificationUID": ext_id(vuid, "other",
                                                       locator=f"{ALM}ver/{vuid}"),
            "externalIdentifier": [ext_id(vuid, "other", locator=f"{ALM}ver/{vuid}",
                                          comment="Verification specification UID.")],
        })
        # verification uses qualified tool(s)
        if tool_keys:
            rel(vid, "usesTool", [TOOL[k] for k in tool_keys],
                extra={"comment": "Tool qualified/classified per IEC 61508-3 §7.4.4."})

        result = v.get("result")
        if result is None:
            # verification exists but not yet evaluated: attach evidence to the
            # verification itself so it is still traceable.
            _emit_evidence(vid, ev_keys, vuid)
            continue

        # EvaluationResult (rationale is mandatory in 3.1; inconclusive needs a comment)
        euid = f"{uid}-E{i}"
        eid = BASE + "evaluation/" + euid
        default_rat = {
            "pass": f"Acceptance criteria of {vuid} met; requirement {uid} is satisfied.",
            "fail": f"Acceptance criteria of {vuid} not met; see comment for the open defect.",
            "inconclusive": f"{vuid} did not yield a definitive result; see comment.",
        }[result]
        eobj = {
            "type": "functionalsafety_EvaluationResult", "spdxId": eid,
            "creationInfo": CI, "name": f"{euid}: {result} ({title})",
            "functionalsafety_evaluation": result,
            "functionalsafety_evaluationBasedOn": vid,
            "rationale": v.get("rationale", default_rat),
        }
        if result in ("fail", "inconclusive") or v.get("comment"):
            eobj["comment"] = v.get(
                "comment",
                "See the verification report for details.")
        add(eobj)
        # Evidence for the evaluation, via an EvidenceRelationship (3.1)
        _emit_evidence(eid, ev_keys, euid)

    if verif_ids:
        rel(rid, "verifiedBy", verif_ids)


# Product-level evidence: the compiled safety case, safety manual and SRS.
_emit_evidence(PKG["firmware"], ["safety_case", "safety_manual", "srs_doc"], "PRODUCT")
# Tool-qualification evidence for the tool-qualification requirement.
_emit_evidence(BASE + "requirement/SRS-SW-072", ["tool_qual_report"], "SRS-SW-072")

# ---------------------------------------------------------------------------
# SBOM root + SpdxDocument
# ---------------------------------------------------------------------------
SBOM_ID = BASE + "sbom"
add({
    "type": "software_Sbom", "spdxId": SBOM_ID, "creationInfo": CI,
    "name": "ESD-3000 Safety Logic Solver SBOM",
    "software_sbomType": ["design", "source"],
    "rootElement": [PKG["firmware"]],
    "comment": "SYNTHETIC / FICTIONAL sample demonstrating the SPDX 3.1 "
               "FunctionalSafety profile.",
})
add({
    "type": "SpdxDocument", "spdxId": BASE + "document", "creationInfo": CI,
    "name": "ESD-3000 Functional Safety SBOM (SYNTHETIC)",
    "profileConformance": ["core", "software", "simpleLicensing", "functionalSafety"],
    "rootElement": [SBOM_ID],
    "comment": "Entirely fictional data. The ESD-3000, its vendor, people, tools, test "
               "results and certificates do not exist. Purpose: demonstrate SPDX 3.1 "
               "FunctionalSafety modelling (requirements, verifications, evaluations, "
               "assumptions and their evidence) in the SPDX 3 SBOM Visualizer.",
})

# ---------------------------------------------------------------------------
# Serialize
# ---------------------------------------------------------------------------
doc = {
    "@context": "https://spdx.org/rdf/3.1/spdx-context.jsonld",
    "@graph": graph,
}

out_dir = os.path.join(os.path.dirname(__file__), "..", "samples", "safety")
os.makedirs(out_dir, exist_ok=True)
out_path = os.path.join(out_dir, "esd-3000-safety-controller.spdx3.json")
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=2, ensure_ascii=True)
    fh.write("\n")

# Small summary to stdout
counts = {}
for el in graph:
    counts[el["type"]] = counts.get(el["type"], 0) + 1
print(f"Wrote {out_path}")
print(f"  {len(graph)} elements, {os.path.getsize(out_path)} bytes")
for t in sorted(counts):
    print(f"    {counts[t]:4d}  {t}")
