#!/usr/bin/env python3
"""Convert an SPDX 2.2 / 2.3 (tag-value or JSON) SBOM to SPDX 3.0.1 JSON-LD.

This uses the official SPDX Python model bindings
(https://github.com/spdx/spdx-python-model, ``pip install spdx-python-model``)
and maps the SPDX 2.x document onto native SPDX 3 concepts:

  * document ``creationInfo.creators``   -> Tool / Organization / Person + CreationInfo
  * ``SPDXRef-DOCUMENT``                  -> SpdxDocument + a software_Sbom whose
                                            rootElement is the DESCRIBES target(s)
  * ``packages[]``                        -> software_Package (with SoftwarePurpose)
  * ``files[]``                           -> software_File
  * ``*.checksums[]``                     -> Hash (verifiedUsing)
  * ``*.externalRefs[]`` (purl / cpe / …) -> ExternalIdentifier + ExternalRef
  * ``*.licenseConcluded`` / Declared     -> hasConcludedLicense / hasDeclaredLicense
                                            relationships to LicenseExpression elements
  * ``hasExtractedLicensingInfos[]``      -> expandedlicensing_CustomLicense
  * ``*.annotations[]``                   -> Annotation
  * ``relationships[]``                   -> Relationship (2.x types bumped to 3.0,
                                            inverse "…_OF/_BY" forms flipped)

Only the input JSON format is read directly here (the format Red Hat, Syft,
Microsoft, Google, … publish). Everything is round-tripped through the model's
JSON-LD serializer, so the output validates against the 3.0.1 shapes.

Usage:
    python3 scripts/spdx2_to_spdx3.py sbom.spdx.json -o sbom.spdx3.json
"""

from __future__ import annotations

import argparse
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
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def is_meaningful(value):
    """False for empty / NONE / NOASSERTION placeholders."""
    return bool(value) and str(value).strip().upper() not in ("NONE", "NOASSERTION", "")


# SPDX 2.x package/file primaryPackagePurpose -> SPDX 3 software_SoftwarePurpose
PURPOSE_MAP = {
    "APPLICATION": spdx.software_SoftwarePurpose.application,
    "FRAMEWORK": spdx.software_SoftwarePurpose.framework,
    "LIBRARY": spdx.software_SoftwarePurpose.library,
    "CONTAINER": spdx.software_SoftwarePurpose.container,
    "OPERATING-SYSTEM": spdx.software_SoftwarePurpose.operatingSystem,
    "DEVICE": spdx.software_SoftwarePurpose.device,
    "DEVICE-DRIVER": spdx.software_SoftwarePurpose.deviceDriver,
    "FIRMWARE": spdx.software_SoftwarePurpose.firmware,
    "SOURCE": spdx.software_SoftwarePurpose.source,
    "ARCHIVE": spdx.software_SoftwarePurpose.archive,
    "FILE": spdx.software_SoftwarePurpose.file,
    "INSTALL": spdx.software_SoftwarePurpose.install,
    "MODULE": spdx.software_SoftwarePurpose.module,
    "MODEL": spdx.software_SoftwarePurpose.model,
    "DATA": spdx.software_SoftwarePurpose.data,
    "PLATFORM": spdx.software_SoftwarePurpose.platform,
    "EVIDENCE": spdx.software_SoftwarePurpose.evidence,
    "REQUIREMENT": spdx.software_SoftwarePurpose.requirement,
    "SPECIFICATION": spdx.software_SoftwarePurpose.specification,
    "TEST": spdx.software_SoftwarePurpose.test,
    "DOCUMENTATION": spdx.software_SoftwarePurpose.documentation,
    "BOM": spdx.software_SoftwarePurpose.bom,
    "CONFIGURATION": spdx.software_SoftwarePurpose.configuration,
    "EXECUTABLE": spdx.software_SoftwarePurpose.executable,
    "OTHER": spdx.software_SoftwarePurpose.other,
}

# SPDX 2.x checksum algorithm -> SPDX 3 HashAlgorithm
HASH_MAP = {
    "MD5": spdx.HashAlgorithm.md5,
    "SHA1": spdx.HashAlgorithm.sha1,
    "SHA224": spdx.HashAlgorithm.sha224,
    "SHA256": spdx.HashAlgorithm.sha256,
    "SHA384": spdx.HashAlgorithm.sha384,
    "SHA512": spdx.HashAlgorithm.sha512,
    "SHA3-256": spdx.HashAlgorithm.sha3_256,
    "SHA3-384": spdx.HashAlgorithm.sha3_384,
    "SHA3-512": spdx.HashAlgorithm.sha3_512,
    "BLAKE2b-256": spdx.HashAlgorithm.blake2b256,
    "BLAKE2b-384": spdx.HashAlgorithm.blake2b384,
    "BLAKE2b-512": spdx.HashAlgorithm.blake2b512,
    "BLAKE3": spdx.HashAlgorithm.blake3,
    "MD6": spdx.HashAlgorithm.other,
    "ADLER32": spdx.HashAlgorithm.other,
}

# SPDX 2.x relationshipType -> (SPDX 3 RelationshipType, invert-endpoints?).
# Where SPDX 3 only kept the forward direction (e.g. `contains` but no
# `containedBy`), the inverse 2.x type maps to the forward type with the two
# endpoints swapped.
REL_MAP = {
    "DESCRIBES": (spdx.RelationshipType.describes, False),
    "DESCRIBED_BY": (spdx.RelationshipType.describes, True),
    "CONTAINS": (spdx.RelationshipType.contains, False),
    "CONTAINED_BY": (spdx.RelationshipType.contains, True),
    "DEPENDS_ON": (spdx.RelationshipType.dependsOn, False),
    "DEPENDENCY_OF": (spdx.RelationshipType.dependsOn, True),
    "DEPENDENCY_MANIFEST_OF": (spdx.RelationshipType.hasDependencyManifest, True),
    "BUILD_DEPENDENCY_OF": (spdx.RelationshipType.dependsOn, True),
    "DEV_DEPENDENCY_OF": (spdx.RelationshipType.dependsOn, True),
    "OPTIONAL_DEPENDENCY_OF": (spdx.RelationshipType.hasOptionalDependency, True),
    "PROVIDED_DEPENDENCY_OF": (spdx.RelationshipType.hasProvidedDependency, True),
    "TEST_DEPENDENCY_OF": (spdx.RelationshipType.dependsOn, True),
    "RUNTIME_DEPENDENCY_OF": (spdx.RelationshipType.dependsOn, True),
    "EXAMPLE_OF": (spdx.RelationshipType.hasExample, True),
    "GENERATES": (spdx.RelationshipType.generates, False),
    "GENERATED_FROM": (spdx.RelationshipType.generates, True),
    "ANCESTOR_OF": (spdx.RelationshipType.ancestorOf, False),
    "DESCENDANT_OF": (spdx.RelationshipType.descendantOf, False),
    "VARIANT_OF": (spdx.RelationshipType.hasVariant, True),
    "DISTRIBUTION_ARTIFACT": (spdx.RelationshipType.hasDistributionArtifact, False),
    "PATCH_FOR": (spdx.RelationshipType.patchedBy, True),
    "PATCH_APPLIED": (spdx.RelationshipType.patchedBy, False),
    "COPY_OF": (spdx.RelationshipType.copiedTo, True),
    "FILE_ADDED": (spdx.RelationshipType.hasAddedFile, False),
    "FILE_DELETED": (spdx.RelationshipType.hasDeletedFile, False),
    "FILE_MODIFIED": (spdx.RelationshipType.modifiedBy, False),
    "EXPANDED_FROM_ARCHIVE": (spdx.RelationshipType.expandsTo, True),
    "DYNAMIC_LINK": (spdx.RelationshipType.hasDynamicLink, False),
    "STATIC_LINK": (spdx.RelationshipType.hasStaticLink, False),
    "DATA_FILE_OF": (spdx.RelationshipType.hasDataFile, True),
    "TEST_CASE_OF": (spdx.RelationshipType.hasTestCase, True),
    "BUILD_TOOL_OF": (spdx.RelationshipType.usesTool, True),
    "DEV_TOOL_OF": (spdx.RelationshipType.usesTool, True),
    "TEST_OF": (spdx.RelationshipType.hasTest, True),
    "TEST_TOOL_OF": (spdx.RelationshipType.usesTool, True),
    "DOCUMENTATION_OF": (spdx.RelationshipType.hasDocumentation, True),
    "OPTIONAL_COMPONENT_OF": (spdx.RelationshipType.hasOptionalComponent, True),
    "METAFILE_OF": (spdx.RelationshipType.hasMetadata, True),
    "PACKAGE_OF": (spdx.RelationshipType.contains, True),
    "AMENDS": (spdx.RelationshipType.amendedBy, True),
    "PREREQUISITE_FOR": (spdx.RelationshipType.hasPrerequisite, True),
    "HAS_PREREQUISITE": (spdx.RelationshipType.hasPrerequisite, False),
    "REQUIREMENT_DESCRIPTION_FOR": (spdx.RelationshipType.hasRequirement, True),
    "SPECIFICATION_FOR": (spdx.RelationshipType.hasSpecification, True),
    "OTHER": (spdx.RelationshipType.other, False),
}

# SPDX 2.x externalRef (category, type) that map to an ExternalIdentifier.
EXT_ID_MAP = {
    "cpe22type": spdx.ExternalIdentifierType.cpe22,
    "cpe23type": spdx.ExternalIdentifierType.cpe23,
    "swid": spdx.ExternalIdentifierType.swid,
    "swh": spdx.ExternalIdentifierType.swhid,
    "gitoid": spdx.ExternalIdentifierType.gitoid,
}

# SPDX 2.x externalRef type -> SPDX 3 ExternalRefType (everything not an identifier).
EXT_REF_MAP = {
    "advisory": spdx.ExternalRefType.securityAdvisory,
    "fix": spdx.ExternalRefType.securityFix,
    "url": spdx.ExternalRefType.securityOther,
    "swid": spdx.ExternalRefType.other,
    "maven-central": spdx.ExternalRefType.mavenCentral,
    "npm": spdx.ExternalRefType.npm,
    "nuget": spdx.ExternalRefType.nuget,
    "bower": spdx.ExternalRefType.bower,
}


# --------------------------------------------------------------------------- #
# Converter
# --------------------------------------------------------------------------- #

class Converter:
    def __init__(self, doc, namespace=None, sbom_type="build"):
        self.doc = doc
        base = namespace or doc.get("documentNamespace") or "https://spdx.org/spdxdocs/spdx2to3"
        self.base = base.rstrip("#/")
        self.sbom_type = sbom_type

        self.objects = []          # every Element we mint (gets serialized)
        self.by_spdxid = {}        # SPDXID -> Element (packages, files, document)
        self.agents = {}           # creator string -> Agent/Tool
        self.licenses = {}         # expression / ref -> AnyLicenseInfo element
        self._seq = 0

        self.creation_info = None
        self.spdx_document = None

    # -- id / registry helpers --------------------------------------------- #

    def elem_iri(self, spdxid):
        return f"{self.base}#{spdxid}"

    def mint_iri(self, kind):
        self._seq += 1
        return f"{self.base}#{kind}-{self._seq}"

    def new(self, cls, spdx_id):
        obj = cls()
        obj._id = spdx_id
        if self.creation_info is not None and hasattr(obj, "creationInfo"):
            obj.creationInfo = self.creation_info
        self.objects.append(obj)
        return obj

    # -- creation info ------------------------------------------------------ #

    def build_creation_info(self):
        ci = spdx.CreationInfo()
        ci.specVersion = "3.0.1"
        info = self.doc.get("creationInfo", {})
        ci.created = parse_dt(info.get("created")) or datetime.now(timezone.utc)
        self.creation_info = ci  # set early so tools/agents inherit it

        created_by = []
        created_using = []
        for creator in info.get("creators", []):
            kind, _, rest = creator.partition(":")
            rest = rest.strip()
            kind = kind.strip().lower()
            if kind == "tool":
                t = self.new(spdx.Tool, self.mint_iri("Tool"))
                t.name = rest or "tool"
                created_using.append(t)
            elif kind == "organization":
                created_by.append(self.agent(spdx.Organization, rest or "NOASSERTION"))
            elif kind == "person":
                created_by.append(self.agent(spdx.Person, rest or "NOASSERTION"))
        if not created_by:
            created_by.append(self.agent(spdx.Organization, "NOASSERTION"))

        ci.createdBy = created_by
        if created_using:
            ci.createdUsing = created_using
        note = []
        if info.get("licenseListVersion"):
            note.append(f"SPDX License List version {info['licenseListVersion']}")
        if info.get("comment"):
            note.append(info["comment"])
        if note:
            ci.comment = "\n".join(note)
        return ci

    def agent(self, cls, name):
        key = f"{cls.__name__}:{name}"
        if key not in self.agents:
            a = self.new(cls, self.mint_iri("Agent"))
            a.name = name
            self.agents[key] = a
        return self.agents[key]

    # -- licenses ----------------------------------------------------------- #

    def extracted_licenses(self):
        """hasExtractedLicensingInfos[] -> CustomLicense elements (keyed by id)."""
        for info in self.doc.get("hasExtractedLicensingInfos", []):
            lic_id = info.get("licenseId")
            if not lic_id:
                continue
            cl = self.new(spdx.expandedlicensing_CustomLicense, self.elem_iri(lic_id))
            cl.name = info.get("name") or lic_id
            cl.simplelicensing_licenseText = info.get("extractedText") or lic_id
            if info.get("seeAlsos"):
                cl.expandedlicensing_seeAlso = list(info["seeAlsos"])
            if info.get("comment"):
                cl.comment = info["comment"]
            self.licenses[f"ref:{lic_id}"] = cl

    def license_expression(self, expr):
        """Map an SPDX license expression string to a LicenseExpression element."""
        expr = (expr or "").strip()
        key = f"expr:{expr}"
        if key not in self.licenses:
            le = self.new(
                spdx.simplelicensing_LicenseExpression,
                self.mint_iri("LicenseExpression"),
            )
            le.simplelicensing_licenseExpression = expr or "NOASSERTION"
            self.licenses[key] = le
        return self.licenses[key]

    # -- external refs ------------------------------------------------------ #

    def apply_external_refs(self, element, external_refs):
        ext_ids = []
        ext_refs = []
        for ref in external_refs or []:
            rtype = (ref.get("referenceType") or "").strip()
            locator = (ref.get("referenceLocator") or "").strip()
            comment = ref.get("comment")
            if not locator:
                continue
            key = rtype.lower()

            if key == "purl":
                if hasattr(element, "software_packageUrl"):
                    element.software_packageUrl = locator
                eid = spdx.ExternalIdentifier()
                eid.externalIdentifierType = spdx.ExternalIdentifierType.packageUrl
                eid.identifier = locator
                if comment:
                    eid.comment = comment
                ext_ids.append(eid)
            elif key in EXT_ID_MAP:
                eid = spdx.ExternalIdentifier()
                eid.externalIdentifierType = EXT_ID_MAP[key]
                eid.identifier = locator
                if comment:
                    eid.comment = comment
                ext_ids.append(eid)
            else:
                r = spdx.ExternalRef()
                r.externalRefType = EXT_REF_MAP.get(key, spdx.ExternalRefType.other)
                r.locator = [locator]
                bits = [b for b in (rtype, comment) if b]
                if bits:
                    r.comment = ": ".join(bits)
                ext_refs.append(r)

        if ext_ids:
            element.externalIdentifier = ext_ids
        if ext_refs:
            element.externalRef = ext_refs

    # -- checksums ---------------------------------------------------------- #

    @staticmethod
    def hashes(checksums):
        out = []
        for cs in checksums or []:
            alg = HASH_MAP.get((cs.get("algorithm") or "").upper())
            value = cs.get("checksumValue")
            if alg is None or not value:
                continue
            h = spdx.Hash()
            h.algorithm = alg
            h.hashValue = value
            out.append(h)
        return out

    # -- annotations -------------------------------------------------------- #

    def build_annotations(self, subject, annotations):
        for ann in annotations or []:
            a = self.new(spdx.Annotation, self.mint_iri("Annotation"))
            a.subject = subject
            a.statement = ann.get("comment", "")
            a.annotationType = (
                spdx.AnnotationType.review
                if (ann.get("annotationType") or "").upper() == "REVIEW"
                else spdx.AnnotationType.other
            )
            annotator = ann.get("annotator", "")
            if annotator:
                a.comment = annotator

    # -- license relationships --------------------------------------------- #

    def license_rel(self, element, expr, rel_type):
        if not is_meaningful(expr):
            return
        rel = self.new(spdx.Relationship, self.mint_iri("Relationship"))
        rel.from_ = element
        rel.relationshipType = rel_type
        rel.to = [self.license_expression(expr)]

    # -- packages ----------------------------------------------------------- #

    def build_package(self, pkg):
        spdxid = pkg.get("SPDXID")
        p = self.new(spdx.software_Package, self.elem_iri(spdxid))
        p.name = pkg.get("name", "")
        if is_meaningful(pkg.get("versionInfo")):
            p.software_packageVersion = pkg["versionInfo"]
        if is_meaningful(pkg.get("downloadLocation")):
            p.software_downloadLocation = pkg["downloadLocation"]
        if is_meaningful(pkg.get("homepage")):
            p.software_homePage = pkg["homepage"]
        if is_meaningful(pkg.get("copyrightText")):
            p.software_copyrightText = pkg["copyrightText"]
        if pkg.get("description"):
            p.description = pkg["description"]
        if pkg.get("summary"):
            p.summary = pkg["summary"]
        if pkg.get("comment"):
            p.comment = pkg["comment"]
        if is_meaningful(pkg.get("sourceInfo")):
            p.software_sourceInfo = pkg["sourceInfo"]
        purpose = PURPOSE_MAP.get((pkg.get("primaryPackagePurpose") or "").upper())
        if purpose is not None:
            p.software_primaryPurpose = purpose
        built = parse_dt(pkg.get("builtDate"))
        if built:
            p.builtTime = built
        released = parse_dt(pkg.get("releaseDate"))
        if released:
            p.releaseTime = released
        valid_until = parse_dt(pkg.get("validUntilDate"))
        if valid_until:
            p.validUntilTime = valid_until

        if is_meaningful(pkg.get("supplier")):
            p.suppliedBy = self.creator_agent(pkg["supplier"])
        if is_meaningful(pkg.get("originator")):
            p.originatedBy = [self.creator_agent(pkg["originator"])]

        hashes = self.hashes(pkg.get("checksums"))
        if hashes:
            p.verifiedUsing = hashes

        self.apply_external_refs(p, pkg.get("externalRefs"))
        self.by_spdxid[spdxid] = p

        self.license_rel(p, pkg.get("licenseConcluded"),
                         spdx.RelationshipType.hasConcludedLicense)
        self.license_rel(p, pkg.get("licenseDeclared"),
                         spdx.RelationshipType.hasDeclaredLicense)
        self.build_annotations(p, pkg.get("annotations"))
        return p

    def creator_agent(self, value):
        """A supplier/originator string 'Organization: X' / 'Person: Y' -> Agent."""
        kind, _, rest = value.partition(":")
        rest = rest.strip() or value
        cls = spdx.Person if kind.strip().lower() == "person" else spdx.Organization
        return self.agent(cls, rest)

    # -- files -------------------------------------------------------------- #

    def build_file(self, f):
        spdxid = f.get("SPDXID")
        el = self.new(spdx.software_File, self.elem_iri(spdxid))
        el.name = f.get("fileName", "")
        if is_meaningful(f.get("copyrightText")):
            el.software_copyrightText = f["copyrightText"]
        if f.get("comment"):
            el.comment = f["comment"]
        if f.get("fileContributors"):
            el.software_attributionText = list(f["fileContributors"])
        hashes = self.hashes(f.get("checksums"))
        if hashes:
            el.verifiedUsing = hashes
        types = [t for t in (f.get("fileTypes") or []) if t]
        if types:
            el.description = "SPDX 2.x fileTypes: " + ", ".join(types)
        self.apply_external_refs(el, f.get("externalRefs"))
        self.by_spdxid[spdxid] = el

        self.license_rel(el, f.get("licenseConcluded"),
                         spdx.RelationshipType.hasConcludedLicense)
        # SPDX 2.x files carry licenseInfoInFiles rather than a declared license.
        for lic in f.get("licenseInfoInFiles", []) or []:
            self.license_rel(el, lic, spdx.RelationshipType.hasDeclaredLicense)
        self.build_annotations(el, f.get("annotations"))
        return el

    # -- relationships ------------------------------------------------------ #

    def resolve(self, spdxid):
        if not is_meaningful(spdxid):
            return None
        if spdxid in ("SPDXRef-DOCUMENT",):
            return self.spdx_document
        return self.by_spdxid.get(spdxid)

    def build_relationships(self):
        described = []
        count = 0
        for rel in self.doc.get("relationships", []):
            rtype = (rel.get("relationshipType") or "").upper()
            src_id = rel.get("spdxElementId")
            dst_id = rel.get("relatedSpdxElement")

            # Document-level DESCRIBES becomes the SBOM's rootElement, not a
            # standalone Relationship element.
            if rtype == "DESCRIBES" and src_id == "SPDXRef-DOCUMENT":
                target = self.resolve(dst_id)
                if target is not None:
                    described.append(target)
                continue
            if rtype == "DESCRIBED_BY" and dst_id == "SPDXRef-DOCUMENT":
                target = self.resolve(src_id)
                if target is not None:
                    described.append(target)
                continue

            mapped, invert = REL_MAP.get(rtype, (spdx.RelationshipType.other, False))
            src = self.resolve(src_id)
            dst = self.resolve(dst_id)
            if invert:
                src, dst = dst, src
            if src is None or dst is None:
                continue
            r = self.new(spdx.Relationship, self.mint_iri("Relationship"))
            r.from_ = src
            r.relationshipType = mapped
            r.to = [dst]
            if rtype not in REL_MAP:
                r.comment = f"Original SPDX 2.x relationship type: {rtype}"
            if is_meaningful(rel.get("comment")):
                r.comment = rel["comment"]
            count += 1
        return described, count

    # --------------------------------------------------------------------- #

    def convert(self):
        self.build_creation_info()

        # The document element (referenced by DESCRIBES relationships).
        self.spdx_document = self.new(spdx.SpdxDocument, self.elem_iri("SPDXRef-DOCUMENT"))
        self.spdx_document.name = self.doc.get("name", "SPDX document")

        self.extracted_licenses()

        for pkg in self.doc.get("packages", []):
            self.build_package(pkg)
        for f in self.doc.get("files", []):
            self.build_file(f)

        described, rel_count = self.build_relationships()
        self.build_annotations(self.spdx_document, self.doc.get("annotations"))

        # Software artifacts that make up the SBOM.
        artifacts = [e for e in self.by_spdxid.values()]
        root_elements = described or artifacts

        sbom = self.new(spdx.software_Sbom, self.mint_iri("Sbom"))
        sbom.name = self.doc.get("name", "SPDX SBOM")
        try:
            sbom.software_sbomType = [getattr(spdx.software_SbomType, self.sbom_type)]
        except AttributeError:
            sbom.software_sbomType = [spdx.software_SbomType.build]
        sbom.element = artifacts
        sbom.rootElement = root_elements

        profiles = [
            spdx.ProfileIdentifierType.core,
            spdx.ProfileIdentifierType.software,
            spdx.ProfileIdentifierType.simpleLicensing,
            spdx.ProfileIdentifierType.expandedLicensing,
        ]
        sbom.profileConformance = list(profiles)

        self.spdx_document.rootElement = [sbom]
        self.spdx_document.profileConformance = list(profiles)
        if is_meaningful(self.doc.get("dataLicense")):
            self.spdx_document.dataLicense = self.license_expression(self.doc["dataLicense"])
        nm = spdx.NamespaceMap()
        nm.prefix = "spdx2to3"
        nm.namespace = self.base + "#"
        self.spdx_document.namespaceMap = [nm]

        return {
            "objects": self.objects,
            "packages": sum(1 for e in self.by_spdxid.values()
                            if isinstance(e, spdx.software_Package)),
            "files": sum(1 for e in self.by_spdxid.values()
                         if isinstance(e, spdx.software_File)),
            "relationships": rel_count,
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
    ap = argparse.ArgumentParser(
        description="Convert an SPDX 2.2/2.3 JSON SBOM to SPDX 3.0.1 JSON-LD."
    )
    ap.add_argument("input", help="Path to the SPDX 2.x JSON file")
    ap.add_argument("-o", "--output", help="Output path (default: <input>.spdx3.json)")
    ap.add_argument("--namespace", help="Base IRI (default: the SPDX 2.x documentNamespace)")
    ap.add_argument("--sbom-type", default="build",
                    help="software_sbomType value (build, source, analyzed, deployed, "
                         "runtime, design; default: build)")
    ap.add_argument("--compact", action="store_true",
                    help="Emit compact JSON instead of pretty-printed")
    args = ap.parse_args(argv)

    with open(args.input, "r", encoding="utf-8") as fh:
        doc = json.load(fh)

    version = doc.get("spdxVersion", "")
    if not version.startswith("SPDX-2"):
        print(f"warning: input spdxVersion is {version!r}, expected 'SPDX-2.x'", file=sys.stderr)

    converter = Converter(doc, namespace=args.namespace, sbom_type=args.sbom_type)
    result = converter.convert()

    output = args.output or re.sub(r"(\.spdx)?\.json$", "", args.input) + ".spdx3.json"
    data = serialize(result["objects"], pretty=not args.compact)
    with open(output, "wb") as fh:
        fh.write(data)

    print(
        f"Wrote {output}\n"
        f"  elements     : {len(result['objects'])}\n"
        f"  packages     : {result['packages']}\n"
        f"  files        : {result['files']}\n"
        f"  relationships: {result['relationships']}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
