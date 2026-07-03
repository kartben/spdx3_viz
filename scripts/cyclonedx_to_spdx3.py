#!/usr/bin/env python3
"""Convert a CycloneDX 1.7 SBOM to an SPDX 3.0.1 JSON-LD document.

This uses the official SPDX Python model bindings (https://github.com/spdx/spdx-python-model,
``pip install spdx-python-model``) and tries to preserve as much of the CycloneDX
document as possible, mapping it onto native SPDX 3 concepts:

  * ``metadata.tools`` / ``metadata.component.supplier`` -> Tool / Organization + CreationInfo
  * ``metadata.component``                              -> root software_Package (the scanned image)
  * ``components[]``                                    -> software_Package (with SoftwarePurpose)
  * ``components[].licenses``                           -> hasDeclaredLicense relationships to
                                                          LicenseExpression / CustomLicense elements
  * ``components[].hashes``                             -> Hash (verifiedUsing)
  * ``components[].supplier``                           -> suppliedBy Organization
  * ``components[].purl``                               -> ExternalIdentifier(packageUrl) + packageUrl
  * ``components[].properties`` (e.g. Trivy metadata)   -> CdxPropertiesExtension (lossless)
  * ``dependencies[]``                                  -> dependsOn Relationship
  * ``vulnerabilities[]``                               -> security_Vulnerability
  * ``vulnerabilities[].ratings``                       -> Cvss{V2,V3,V4}VulnAssessmentRelationship
  * ``vulnerabilities[].affects`` (VEX status)          -> Vex{Affected,NotAffected,...}
                                                          VulnAssessmentRelationship
  * ``vulnerabilities[].cwes`` / ``.advisories``        -> ExternalRef (cwe / securityAdvisory)

Usage:
    python3 scripts/cyclonedx_to_spdx3.py bom.cdx.json -o bom.spdx3.json
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
from datetime import datetime, timezone
from urllib.parse import quote

try:
    from spdx_python_model import v3_0_1 as spdx
except ImportError:  # pragma: no cover - dependency hint
    sys.exit(
        "The 'spdx-python-model' package is required.\n"
        "Install it with:  python3 -m pip install spdx-python-model"
    )


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def parse_dt(value):
    """Parse an ISO-8601 timestamp into a timezone-aware datetime (or None)."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def slug(text, maxlen=100):
    """Turn arbitrary text into an IRI-path-safe fragment.

    Long values are truncated but get a hash suffix derived from the *full*
    input, so distinct inputs can never collide onto the same spdxId.
    """
    if not text:
        return "unknown"
    text = str(text)
    encoded = quote(text, safe="")
    if len(encoded) <= maxlen:
        return encoded
    digest = hashlib.md5(text.encode("utf-8")).hexdigest()[:12]
    return f"{encoded[:maxlen]}-{digest}"


# CycloneDX component `type` -> SPDX software_SoftwarePurpose
PURPOSE_MAP = {
    "application": spdx.software_SoftwarePurpose.application,
    "framework": spdx.software_SoftwarePurpose.framework,
    "library": spdx.software_SoftwarePurpose.library,
    "container": spdx.software_SoftwarePurpose.container,
    "platform": spdx.software_SoftwarePurpose.platform,
    "operating-system": spdx.software_SoftwarePurpose.operatingSystem,
    "device": spdx.software_SoftwarePurpose.device,
    "device-driver": spdx.software_SoftwarePurpose.deviceDriver,
    "firmware": spdx.software_SoftwarePurpose.firmware,
    "file": spdx.software_SoftwarePurpose.file,
    "machine-learning-model": spdx.software_SoftwarePurpose.model,
    "data": spdx.software_SoftwarePurpose.data,
}

# CycloneDX hash `alg` -> SPDX HashAlgorithm
HASH_MAP = {
    "MD5": spdx.HashAlgorithm.md5,
    "SHA-1": spdx.HashAlgorithm.sha1,
    "SHA-224": spdx.HashAlgorithm.sha224,
    "SHA-256": spdx.HashAlgorithm.sha256,
    "SHA-384": spdx.HashAlgorithm.sha384,
    "SHA-512": spdx.HashAlgorithm.sha512,
    "SHA3-256": spdx.HashAlgorithm.sha3_256,
    "SHA3-384": spdx.HashAlgorithm.sha3_384,
    "SHA3-512": spdx.HashAlgorithm.sha3_512,
    "BLAKE2b-256": spdx.HashAlgorithm.blake2b256,
    "BLAKE2b-384": spdx.HashAlgorithm.blake2b384,
    "BLAKE2b-512": spdx.HashAlgorithm.blake2b512,
    "BLAKE3": spdx.HashAlgorithm.blake3,
}

# CycloneDX rating severity -> SPDX security_CvssSeverityType
SEVERITY_MAP = {
    "critical": spdx.security_CvssSeverityType.critical,
    "high": spdx.security_CvssSeverityType.high,
    "medium": spdx.security_CvssSeverityType.medium,
    "low": spdx.security_CvssSeverityType.low,
    "info": spdx.security_CvssSeverityType.none,
    "none": spdx.security_CvssSeverityType.none,
}

# CycloneDX VEX analysis.state -> SPDX Vex*VulnAssessmentRelationship class + relationship type.
# CycloneDX `affects[].versions[].status` uses the same vocabulary.
VEX_STATE = {
    "affected": (
        spdx.security_VexAffectedVulnAssessmentRelationship,
        spdx.RelationshipType.affects,
    ),
    "exploitable": (
        spdx.security_VexAffectedVulnAssessmentRelationship,
        spdx.RelationshipType.affects,
    ),
    "unaffected": (
        spdx.security_VexNotAffectedVulnAssessmentRelationship,
        spdx.RelationshipType.doesNotAffect,
    ),
    "not_affected": (
        spdx.security_VexNotAffectedVulnAssessmentRelationship,
        spdx.RelationshipType.doesNotAffect,
    ),
    "resolved": (
        spdx.security_VexFixedVulnAssessmentRelationship,
        spdx.RelationshipType.fixedIn,
    ),
    "fixed": (
        spdx.security_VexFixedVulnAssessmentRelationship,
        spdx.RelationshipType.fixedIn,
    ),
    "false_positive": (
        spdx.security_VexNotAffectedVulnAssessmentRelationship,
        spdx.RelationshipType.doesNotAffect,
    ),
    "in_triage": (
        spdx.security_VexUnderInvestigationVulnAssessmentRelationship,
        spdx.RelationshipType.underInvestigationFor,
    ),
    "under_investigation": (
        spdx.security_VexUnderInvestigationVulnAssessmentRelationship,
        spdx.RelationshipType.underInvestigationFor,
    ),
}

# CycloneDX VEX justification -> SPDX security_VexJustificationType
JUSTIFICATION_MAP = {
    "code_not_present": spdx.security_VexJustificationType.vulnerableCodeNotPresent,
    "code_not_reachable": spdx.security_VexJustificationType.vulnerableCodeNotInExecutePath,
    "requires_configuration": spdx.security_VexJustificationType.vulnerableCodeCannotBeControlledByAdversary,
    "requires_dependency": spdx.security_VexJustificationType.vulnerableCodeCannotBeControlledByAdversary,
    "requires_environment": spdx.security_VexJustificationType.vulnerableCodeCannotBeControlledByAdversary,
    "protected_by_compiler": spdx.security_VexJustificationType.inlineMitigationsAlreadyExist,
    "protected_at_runtime": spdx.security_VexJustificationType.inlineMitigationsAlreadyExist,
    "protected_at_perimeter": spdx.security_VexJustificationType.inlineMitigationsAlreadyExist,
    "protected_by_mitigating_control": spdx.security_VexJustificationType.inlineMitigationsAlreadyExist,
}


# --------------------------------------------------------------------------- #
# Converter
# --------------------------------------------------------------------------- #

class Converter:
    def __init__(self, cdx, namespace=None):
        self.cdx = cdx
        serial = cdx.get("serialNumber", "").replace("urn:uuid:", "") or "cyclonedx"
        self.ns = (namespace or f"https://spdx.org/spdxdocs/cdx2spdx-{serial}").rstrip("/")

        self.objects = []          # every Element we mint (gets serialized)
        self.ref_to_pkg = {}       # CycloneDX bom-ref -> software_Package
        self.orgs = {}             # supplier name -> Organization
        self.licenses = {}         # cache key -> AnyLicenseInfo element
        self._seq = 0

        self.creation_info = None  # shared CreationInfo for every element

    # -- id/registry helpers ------------------------------------------------ #

    def iri(self, kind, key):
        return f"{self.ns}/{kind}/{slug(key)}"

    def seq_iri(self, kind):
        self._seq += 1
        return f"{self.ns}/{kind}/{self._seq}"

    def new(self, cls, spdx_id):
        """Instantiate an Element, wire up creationInfo + spdxId, and register it."""
        obj = cls()
        obj._id = spdx_id
        if self.creation_info is not None and hasattr(obj, "creationInfo"):
            obj.creationInfo = self.creation_info
        self.objects.append(obj)
        return obj

    # -- creation info ------------------------------------------------------ #

    def build_creation_info(self):
        meta = self.cdx.get("metadata", {})
        ci = spdx.CreationInfo()
        ci.specVersion = "3.0.1"
        ci.created = parse_dt(meta.get("timestamp")) or datetime.now(timezone.utc)
        self.creation_info = ci  # set early so tools/agents inherit it

        created_by = []
        created_using = []

        for tool in meta.get("tools", {}).get("components", []):
            name = tool.get("name", "tool")
            version = tool.get("version")
            t = self.new(spdx.Tool, self.iri("Tool", f"{name}-{version or ''}"))
            t.name = f"{name} {version}".strip() if version else name
            created_using.append(t)
            # A tool's manufacturer becomes the acting Organization (Agent).
            manuf = (tool.get("manufacturer") or {}).get("name")
            if manuf:
                created_by.append(self.organization(manuf))

        # Legacy CycloneDX `metadata.tools` as a plain array of {name,version}.
        if isinstance(meta.get("tools"), list):
            for tool in meta["tools"]:
                name = tool.get("name", "tool")
                version = tool.get("version")
                t = self.new(spdx.Tool, self.iri("Tool", f"{name}-{version or ''}"))
                t.name = f"{name} {version}".strip() if version else name
                created_using.append(t)

        author = (meta.get("authors") or [{}])[0].get("name") if meta.get("authors") else None
        if author:
            created_by.append(self.person(author))
        if not created_by:
            created_by.append(self.organization("NOASSERTION"))

        ci.createdBy = created_by
        if created_using:
            ci.createdUsing = created_using
        return ci

    # -- agents ------------------------------------------------------------- #

    def organization(self, name):
        if name not in self.orgs:
            org = self.new(spdx.Organization, self.iri("Agent", name))
            org.name = name
            self.orgs[name] = org
        return self.orgs[name]

    def person(self, name):
        key = f"person:{name}"
        if key not in self.orgs:
            p = self.new(spdx.Person, self.iri("Agent", key))
            p.name = name
            self.orgs[key] = p
        return self.orgs[key]

    # -- licenses ----------------------------------------------------------- #

    def license_element(self, entry):
        """Map one CycloneDX license entry to an AnyLicenseInfo element (cached)."""
        if "expression" in entry:
            expr = entry["expression"]
            return self._license_expression(expr)

        lic = entry.get("license", {})
        if lic.get("id"):
            return self._license_expression(lic["id"])
        name = lic.get("name")
        if not name or name.strip().upper() in ("UNKNOWN", "NONE", ""):
            return self._license_expression("NOASSERTION")
        # Not an SPDX id/expression: model it as a CustomLicense so the exact
        # string survives round-tripping.
        return self._custom_license(name)

    def _license_expression(self, expr):
        key = f"expr:{expr}"
        if key not in self.licenses:
            le = self.new(
                spdx.simplelicensing_LicenseExpression,
                self.iri("LicenseExpression", expr),
            )
            le.simplelicensing_licenseExpression = expr
            self.licenses[key] = le
        return self.licenses[key]

    def _custom_license(self, name):
        key = f"custom:{name}"
        if key not in self.licenses:
            ref = "LicenseRef-" + re.sub(r"[^0-9A-Za-z.\-]+", "-", name).strip("-")[:60]
            ref = ref or "LicenseRef-custom"
            cl = self.new(
                spdx.expandedlicensing_CustomLicense,
                self.iri("License", f"{ref}-{len(self.licenses)}"),
            )
            cl.name = name
            cl.simplelicensing_licenseText = name
            self.licenses[key] = cl
        return self.licenses[key]

    # -- extensions (lossless CycloneDX property carry-over) ---------------- #

    def properties_extension(self, properties):
        if not properties:
            return None
        ext = spdx.extension_CdxPropertiesExtension()
        entries = []
        for prop in properties:
            entry = spdx.extension_CdxPropertyEntry()
            entry.extension_cdxPropName = prop.get("name", "")
            entry.extension_cdxPropValue = prop.get("value", "")
            entries.append(entry)
        ext.extension_cdxProperty = entries
        return ext

    # -- packages ----------------------------------------------------------- #

    def build_package(self, comp):
        ref = comp.get("bom-ref") or comp.get("purl") or comp.get("name")
        pkg = self.new(spdx.software_Package, self.iri("Package", ref))
        pkg.name = comp.get("name", "")
        if comp.get("version"):
            pkg.software_packageVersion = comp["version"]

        purpose = PURPOSE_MAP.get(comp.get("type"))
        if purpose is not None:
            pkg.software_primaryPurpose = purpose

        if comp.get("description"):
            pkg.description = comp["description"]

        purl = comp.get("purl")
        if purl:
            pkg.software_packageUrl = purl
            eid = spdx.ExternalIdentifier()
            eid.externalIdentifierType = spdx.ExternalIdentifierType.packageUrl
            eid.identifier = purl
            pkg.externalIdentifier = [eid]

        if comp.get("cpe"):
            cpe = spdx.ExternalIdentifier()
            cpe.externalIdentifierType = (
                spdx.ExternalIdentifierType.cpe23
                if comp["cpe"].startswith("cpe:2.3")
                else spdx.ExternalIdentifierType.cpe22
            )
            cpe.identifier = comp["cpe"]
            existing = list(pkg.externalIdentifier)
            existing.append(cpe)
            pkg.externalIdentifier = existing

        supplier = (comp.get("supplier") or {}).get("name")
        if supplier:
            pkg.suppliedBy = self.organization(supplier)

        hashes = []
        for h in comp.get("hashes", []):
            alg = HASH_MAP.get(h.get("alg"))
            if alg is None:
                continue
            hobj = spdx.Hash()
            hobj.algorithm = alg
            hobj.hashValue = h.get("content", "")
            hashes.append(hobj)
        if hashes:
            pkg.verifiedUsing = hashes

        ext = self.properties_extension(comp.get("properties"))
        if ext is not None:
            pkg.extension = [ext]

        self.ref_to_pkg[ref] = pkg

        # licenses -> hasDeclaredLicense relationship(s)
        lic_targets = [self.license_element(e) for e in comp.get("licenses", [])]
        lic_targets = [x for x in lic_targets if x is not None]
        if lic_targets:
            rel = self.new(spdx.Relationship, self.seq_iri("Relationship"))
            rel.from_ = pkg
            rel.relationshipType = spdx.RelationshipType.hasDeclaredLicense
            rel.to = lic_targets

        return pkg

    # -- dependencies ------------------------------------------------------- #

    def build_dependencies(self):
        count = 0
        for dep in self.cdx.get("dependencies", []):
            src = self.ref_to_pkg.get(dep.get("ref"))
            if src is None:
                continue
            targets = [self.ref_to_pkg[d] for d in dep.get("dependsOn", []) if d in self.ref_to_pkg]
            if targets:
                rel = self.new(spdx.Relationship, self.seq_iri("Relationship"))
                rel.from_ = src
                rel.relationshipType = spdx.RelationshipType.dependsOn
                rel.to = targets
                rel.completeness = spdx.RelationshipCompleteness.complete
                count += 1
            for prov in dep.get("provides", []):
                target = self.ref_to_pkg.get(prov)
                if target is not None:
                    rel = self.new(spdx.Relationship, self.seq_iri("Relationship"))
                    rel.from_ = src
                    rel.relationshipType = spdx.RelationshipType.hasProvidedDependency
                    rel.to = [target]
                    count += 1
        return count

    # -- vulnerabilities ---------------------------------------------------- #

    def build_vulnerability(self, vuln):
        vid = vuln.get("id", "vuln")
        v = self.new(spdx.security_Vulnerability, self.iri("Vulnerability", vid))
        v.name = vid
        if vuln.get("description"):
            v.description = vuln["description"]
        if vuln.get("detail"):
            v.summary = vuln["detail"][:200]
        pub = parse_dt(vuln.get("published"))
        if pub:
            v.security_publishedTime = pub
        mod = parse_dt(vuln.get("updated"))
        if mod:
            v.security_modifiedTime = mod
        wdr = parse_dt(vuln.get("rejected"))
        if wdr:
            v.security_withdrawnTime = wdr

        # id -> ExternalIdentifier (cve / other)
        eid = spdx.ExternalIdentifier()
        if vid.upper().startswith("CVE-"):
            eid.externalIdentifierType = spdx.ExternalIdentifierType.cve
            eid.identifierLocator = [f"https://www.cve.org/CVERecord?id={vid}"]
        else:
            eid.externalIdentifierType = spdx.ExternalIdentifierType.securityOther
        eid.identifier = vid
        source = vuln.get("source") or {}
        if source.get("name"):
            eid.issuingAuthority = source["name"]
        v.externalIdentifier = [eid]

        # cwes + advisories + source url -> ExternalRef
        refs = []
        for cwe in vuln.get("cwes", []):
            r = spdx.ExternalRef()
            r.externalRefType = spdx.ExternalRefType.cwe
            r.locator = [f"https://cwe.mitre.org/data/definitions/{cwe}.html"]
            refs.append(r)
        if source.get("url"):
            r = spdx.ExternalRef()
            r.externalRefType = spdx.ExternalRefType.securityAdvisory
            r.locator = [source["url"]]
            r.comment = f"Source: {source.get('name', '')}".strip()
            refs.append(r)
        for adv in vuln.get("advisories", []):
            if not adv.get("url"):
                continue
            r = spdx.ExternalRef()
            r.externalRefType = spdx.ExternalRefType.securityAdvisory
            r.locator = [adv["url"]]
            if adv.get("title"):
                r.comment = adv["title"]
            refs.append(r)
        if refs:
            v.externalRef = refs

        return v

    @staticmethod
    def _severity_from_score(score):
        """Fallback CVSS v3/v4 qualitative severity when the source omits it."""
        if score >= 9.0:
            return spdx.security_CvssSeverityType.critical
        if score >= 7.0:
            return spdx.security_CvssSeverityType.high
        if score >= 4.0:
            return spdx.security_CvssSeverityType.medium
        if score > 0.0:
            return spdx.security_CvssSeverityType.low
        return spdx.security_CvssSeverityType.none

    def build_assessments(self, vuln, vulnerability):
        """Emit CVSS + VEX assessment relationships for a vulnerability."""
        affected_pkgs = []
        status_by_pkg = {}
        for aff in vuln.get("affects", []):
            pkg = self.ref_to_pkg.get(aff.get("ref"))
            if pkg is None:
                continue
            affected_pkgs.append(pkg)
            versions = aff.get("versions") or [{}]
            status = next((vv.get("status") for vv in versions if vv.get("status")), "affected")
            status_by_pkg[id(pkg)] = (pkg, status)

        recommendation = vuln.get("recommendation")
        analysis = vuln.get("analysis") or {}

        # --- CVSS ratings -> Cvss*VulnAssessmentRelationship --------------- #
        # These relationships require a score, a vector string, a non-empty `to`
        # (and a severity for v3/v4); ratings lacking those are captured as notes.
        severity_notes = []
        for rating in vuln.get("ratings", []):
            method = (rating.get("method") or "").lower()
            rsource = (rating.get("source") or {}).get("name", "")
            if method in ("cvssv2",):
                cls, has_sev = spdx.security_CvssV2VulnAssessmentRelationship, False
            elif method in ("cvssv3", "cvssv31", "cvssv3.1"):
                cls, has_sev = spdx.security_CvssV3VulnAssessmentRelationship, True
            elif method in ("cvssv4",):
                cls, has_sev = spdx.security_CvssV4VulnAssessmentRelationship, True
            else:
                cls, has_sev = None, False

            score = rating.get("score")
            vector = rating.get("vector")
            if cls is None or score is None or not vector or not affected_pkgs:
                # Not a usable CVSS vector (e.g. a distro's own severity label):
                # keep the qualitative rating as a note on the vulnerability.
                if rating.get("severity"):
                    severity_notes.append(f"{rsource}: {rating['severity']}".strip(": "))
                continue

            try:
                score = float(score)
            except (TypeError, ValueError):
                if rating.get("severity"):
                    severity_notes.append(f"{rsource}: {rating['severity']}".strip(": "))
                continue

            rel = self.new(cls, self.seq_iri("Assessment"))
            rel.from_ = vulnerability
            rel.relationshipType = spdx.RelationshipType.hasAssessmentFor
            rel.to = affected_pkgs
            rel.security_score = score
            rel.security_vectorString = vector
            if has_sev:
                sev = SEVERITY_MAP.get((rating.get("severity") or "").lower())
                rel.security_severity = sev if sev is not None else self._severity_from_score(score)
            if rsource:
                rel.comment = f"CVSS rating from {rsource} ({rating.get('method')})"

        if severity_notes:
            note = "Qualitative severity ratings: " + "; ".join(severity_notes)
            vulnerability.comment = (
                f"{vulnerability.comment}\n{note}" if vulnerability.comment else note
            )

        # --- VEX / affected-status statements ------------------------------ #
        # Analysis state (if present) is a document-wide VEX statement; otherwise
        # fall back to the per-affects status Trivy records.
        analysis_state = (analysis.get("state") or "").lower()
        justification = JUSTIFICATION_MAP.get((analysis.get("justification") or "").lower())
        detail = analysis.get("detail")
        responses = analysis.get("response") or []

        for pkg, status in status_by_pkg.values():
            state = analysis_state or status.lower()
            cls, rel_type = VEX_STATE.get(state, VEX_STATE["affected"])
            rel = self.new(cls, self.seq_iri("Assessment"))
            rel.from_ = vulnerability
            rel.relationshipType = rel_type
            rel.to = [pkg]
            rel.security_assessedElement = pkg
            if detail:
                rel.security_statusNotes = detail

            if cls is spdx.security_VexNotAffectedVulnAssessmentRelationship:
                if justification is not None:
                    rel.security_justificationType = justification
                if responses:
                    rel.security_impactStatement = "; ".join(responses)
            elif cls is spdx.security_VexAffectedVulnAssessmentRelationship:
                # actionStatement is required on this relationship type.
                rel.security_actionStatement = (
                    recommendation
                    or "No remediation action statement was provided in the source SBOM."
                )


# --------------------------------------------------------------------------- #

    def convert(self):
        self.build_creation_info()

        # Root component (the scanned artifact / image).
        meta_comp = self.cdx.get("metadata", {}).get("component")
        root_pkg = self.build_package(meta_comp) if meta_comp else None

        # All components.
        for comp in self.cdx.get("components", []):
            self.build_package(comp)

        dep_count = self.build_dependencies()

        # Vulnerabilities + assessments.
        vuln_count = 0
        for vuln in self.cdx.get("vulnerabilities", []):
            velem = self.build_vulnerability(vuln)
            self.build_assessments(vuln, velem)
            vuln_count += 1

        # SBOM element grouping (software artifacts only).
        pkg_elems = list(self.ref_to_pkg.values())
        sbom = self.new(spdx.software_Sbom, self.iri("Sbom", "sbom"))
        sbom.name = (meta_comp or {}).get("name", "CycloneDX SBOM")
        sbom.software_sbomType = [spdx.software_SbomType.analyzed]
        sbom.element = pkg_elems
        sbom.rootElement = [root_pkg] if root_pkg else pkg_elems
        sbom.profileConformance = [
            spdx.ProfileIdentifierType.core,
            spdx.ProfileIdentifierType.software,
            spdx.ProfileIdentifierType.security,
            spdx.ProfileIdentifierType.simpleLicensing,
            spdx.ProfileIdentifierType.expandedLicensing,
            spdx.ProfileIdentifierType.extension,
        ]

        doc = self.new(spdx.SpdxDocument, self.iri("Document", "document"))
        doc.name = sbom.name
        doc.rootElement = [sbom]
        doc.profileConformance = list(sbom.profileConformance)
        nm = spdx.NamespaceMap()
        nm.prefix = "cdx2spdx"
        nm.namespace = self.ns + "/"
        doc.namespaceMap = [nm]

        return {
            "objects": self.objects,
            "packages": len(pkg_elems),
            "dependencies": dep_count,
            "vulnerabilities": vuln_count,
        }


def serialize(objects, pretty=True):
    objset = spdx.SHACLObjectSet()
    for obj in objects:
        objset.add(obj)
    serializer = spdx.JSONLDSerializer()
    buf = io.BytesIO()
    serializer.write(objset, buf)
    data = buf.getvalue()
    if pretty:
        data = json.dumps(json.loads(data), indent=2, ensure_ascii=False).encode("utf-8")
    return data


def main(argv=None):
    ap = argparse.ArgumentParser(description="Convert a CycloneDX 1.7 SBOM to SPDX 3.0.1 JSON-LD.")
    ap.add_argument("input", help="Path to the CycloneDX JSON file")
    ap.add_argument("-o", "--output", help="Output path (default: <input>.spdx3.json)")
    ap.add_argument("--namespace", help="SPDX document namespace IRI (default derived from serialNumber)")
    ap.add_argument("--compact", action="store_true", help="Emit compact JSON instead of pretty-printed")
    args = ap.parse_args(argv)

    with open(args.input, "r", encoding="utf-8") as fh:
        cdx = json.load(fh)

    fmt = cdx.get("bomFormat")
    if fmt != "CycloneDX":
        print(f"warning: input bomFormat is {fmt!r}, expected 'CycloneDX'", file=sys.stderr)

    converter = Converter(cdx, namespace=args.namespace)
    result = converter.convert()

    output = args.output or re.sub(r"(\.cdx)?\.json$", "", args.input) + ".spdx3.json"
    data = serialize(result["objects"], pretty=not args.compact)
    with open(output, "wb") as fh:
        fh.write(data)

    print(
        f"Wrote {output}\n"
        f"  elements       : {len(result['objects'])}\n"
        f"  packages       : {result['packages']}\n"
        f"  dependency rels: {result['dependencies']}\n"
        f"  vulnerabilities: {result['vulnerabilities']}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
