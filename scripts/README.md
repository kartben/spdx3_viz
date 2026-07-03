# CycloneDX to SPDX 3 converter

[`cyclonedx_to_spdx3.py`](cyclonedx_to_spdx3.py) converts a CycloneDX 1.7 SBOM
(as produced by e.g. Trivy) into an **SPDX 3.0.1** JSON-LD document, built on the
official [`spdx-python-model`](https://github.com/spdx/spdx-python-model) bindings.

It aims to preserve as much of the source document as possible (including
vulnerability / VEX information) by mapping it onto native SPDX 3 concepts rather
than dumping everything into free-text properties.

## Usage

```bash
python3 -m pip install -r scripts/requirements.txt

python3 scripts/cyclonedx_to_spdx3.py bom.cdx.json -o bom.spdx3.json
```

Options:

| flag | meaning |
| --- | --- |
| `-o, --output` | Output path (default: `<input>.spdx3.json`) |
| `--namespace`  | SPDX document namespace IRI (default derived from the CycloneDX `serialNumber`) |
| `--compact`    | Emit compact JSON instead of pretty-printed |

## Mapping

| CycloneDX | SPDX 3.0.1 |
| --- | --- |
| `metadata.tools.components[]` | `Tool` (referenced from `CreationInfo.createdUsing`) |
| tool `manufacturer` / `metadata.component.supplier` | `Organization` (`CreationInfo.createdBy`) |
| `metadata.component` | root `software_Package`, used as the SBOM `rootElement` |
| `components[]` | `software_Package` with a `software_SoftwarePurpose` from the component `type` |
| `components[].purl` | `ExternalIdentifier(packageUrl)` + `software_packageUrl` |
| `components[].cpe` | `ExternalIdentifier(cpe22 / cpe23)` |
| `components[].supplier` | `suppliedBy` → `Organization` |
| `components[].hashes[]` | `Hash` (`verifiedUsing`) |
| `components[].licenses[].license.id` / `.expression` | `simplelicensing_LicenseExpression` via `hasDeclaredLicense` |
| `components[].licenses[].license.name` (non-SPDX) | `expandedlicensing_CustomLicense` via `hasDeclaredLicense` |
| `components[].properties[]` (e.g. Trivy metadata) | `extension_CdxPropertiesExtension` (lossless) |
| `dependencies[].dependsOn` | `Relationship(dependsOn)` (`completeness = complete`) |
| `dependencies[].provides` | `Relationship(hasProvidedDependency)` |
| `vulnerabilities[]` | `security_Vulnerability` |
| `vulnerabilities[].id` | `ExternalIdentifier(cve / securityOther)` |
| `vulnerabilities[].cwes[]` | `ExternalRef(cwe)` |
| `vulnerabilities[].advisories[]` / `.source` | `ExternalRef(securityAdvisory)` |
| `vulnerabilities[].ratings[]` (CVSS v2/v3/v3.1/v4) | `security_Cvss{V2,V3,V4}VulnAssessmentRelationship` (`hasAssessmentFor`) |
| `vulnerabilities[].ratings[]` (severity only, no vector) | recorded as a note on the `security_Vulnerability` |
| `vulnerabilities[].affects[]` (VEX status) | `security_Vex{Affected,NotAffected,Fixed,UnderInvestigation}VulnAssessmentRelationship` |
| `vulnerabilities[].recommendation` | VEX `security_actionStatement` |
| `.analysis` (`state` / `justification` / `response` / `detail`) | VEX status class + `security_justificationType` / `security_impactStatement` / `security_statusNotes` |

### Notes

* Because most VEX/assessment relationships require a non-empty `to`, assessments
  are only emitted for vulnerabilities whose `affects[]` reference known
  components.
* CVSS relationships require a score **and** a vector string; ratings that carry
  only a qualitative severity label (e.g. a distro's own rating) are preserved as
  a note on the vulnerability instead of being dropped.
* The output validates by round-tripping through the model's `JSONLDDeserializer`.

## Declared profiles

`core`, `software`, `security`, `simpleLicensing`, `expandedLicensing`, `extension`.
