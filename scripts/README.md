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

| flag           | meaning                                                                         |
| -------------- | ------------------------------------------------------------------------------- |
| `-o, --output` | Output path (default: `<input>.spdx3.json`)                                     |
| `--namespace`  | SPDX document namespace IRI (default derived from the CycloneDX `serialNumber`) |
| `--compact`    | Emit compact JSON instead of pretty-printed                                     |

## Mapping

| CycloneDX                                                       | SPDX 3.0.1                                                                                            |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `metadata.tools.components[]`                                   | `Tool` (referenced from `CreationInfo.createdUsing`)                                                  |
| tool `manufacturer` / `metadata.component.supplier`             | `Organization` (`CreationInfo.createdBy`)                                                             |
| `metadata.component`                                            | root `software_Package`, used as the SBOM `rootElement`                                               |
| `components[]`                                                  | `software_Package` with a `software_SoftwarePurpose` from the component `type`                        |
| `components[].purl`                                             | `ExternalIdentifier(packageUrl)` + `software_packageUrl`                                              |
| `components[].cpe`                                              | `ExternalIdentifier(cpe22 / cpe23)`                                                                   |
| `components[].supplier`                                         | `suppliedBy` → `Organization`                                                                         |
| `components[].hashes[]`                                         | `Hash` (`verifiedUsing`)                                                                              |
| `components[].licenses[].license.id` / `.expression`            | `simplelicensing_LicenseExpression` via `hasDeclaredLicense`                                          |
| `components[].licenses[].license.name` (non-SPDX)               | `expandedlicensing_CustomLicense` via `hasDeclaredLicense`                                            |
| `components[].properties[]` (e.g. Trivy metadata)               | `extension_CdxPropertiesExtension` (lossless)                                                         |
| `dependencies[].dependsOn`                                      | `Relationship(dependsOn)` (`completeness = complete`)                                                 |
| `dependencies[].provides`                                       | `Relationship(hasProvidedDependency)`                                                                 |
| `vulnerabilities[]`                                             | `security_Vulnerability`                                                                              |
| `vulnerabilities[].id`                                          | `ExternalIdentifier(cve / securityOther)`                                                             |
| `vulnerabilities[].cwes[]`                                      | `ExternalRef(cwe)`                                                                                    |
| `vulnerabilities[].advisories[]` / `.source`                    | `ExternalRef(securityAdvisory)`                                                                       |
| `vulnerabilities[].ratings[]` (CVSS v2/v3/v3.1/v4)              | `security_Cvss{V2,V3,V4}VulnAssessmentRelationship` (`hasAssessmentFor`)                              |
| `vulnerabilities[].ratings[]` (severity only, no vector)        | recorded as a note on the `security_Vulnerability`                                                    |
| `vulnerabilities[].affects[]` (VEX status)                      | `security_Vex{Affected,NotAffected,Fixed,UnderInvestigation}VulnAssessmentRelationship`               |
| `vulnerabilities[].recommendation`                              | VEX `security_actionStatement`                                                                        |
| `.analysis` (`state` / `justification` / `response` / `detail`) | VEX status class + `security_justificationType` / `security_impactStatement` / `security_statusNotes` |

### Notes

- Because most VEX/assessment relationships require a non-empty `to`, assessments
  are only emitted for vulnerabilities whose `affects[]` reference known
  components.
- CVSS relationships require a score **and** a vector string; ratings that carry
  only a qualitative severity label (e.g. a distro's own rating) are preserved as
  a note on the vulnerability instead of being dropped.
- The output validates by round-tripping through the model's `JSONLDDeserializer`.

## Declared profiles

`core`, `software`, `security`, `simpleLicensing`, `expandedLicensing`, `extension`.

# Releasing

Releases are cut by the [`Release`](../.github/workflows/release.yml) GitHub
Actions workflow, which wraps [`release.mjs`](release.mjs). The version lives in
`package.json` as `X.Y.Z-dev` while in development, and changelog notes collect
under `## Unreleased` in [`CHANGELOG.md`](../CHANGELOG.md).

## From CI (the usual way)

1. Actions tab → **Release** → **Run workflow**.
2. Pick a **bump**: `auto` (ship the current `-dev` as `X.Y.Z`), `patch`,
   `minor`, `major`, or `explicit` (then fill in **version**, e.g. `1.2.0`).
3. Run. The workflow runs the full CI gate, then in one go: sets the version,
   dates the `## Unreleased` section, tags `vX.Y.Z`, reopens the next `-dev`
   cycle, pushes both commits and the tag to `main`, and publishes a GitHub
   Release, and deploy the tagged release to GitHub Pages. (The push to `main`
   does not trigger deploy-pages when performed by `GITHUB_TOKEN`; the release
   workflow calls the Pages deploy directly. Manual releases via the GitHub UI
   are handled by the `release: published` trigger in deploy-pages.yml.)

> The workflow pushes to `main`. If `main` is protected, allow the
> `github-actions[bot]` actor to push (or run the release from a maintainer PAT).

## Locally (same steps by hand)

```bash
node scripts/release.mjs resolve  minor        # preview release + next dev version
node scripts/release.mjs prepare  minor        # version + dated changelog (the tagged commit)
#   git commit ... && git tag vX.Y.Z
node scripts/release.mjs bump-dev              # reopen the next -dev cycle
node scripts/release.mjs notes    X.Y.Z        # print notes for a GitHub Release body
```

Add `--dry-run` to `prepare` / `bump-dev` to preview without writing files.
