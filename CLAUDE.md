# CLAUDE.md — CLaaS (Cyntinel) Project

> **Project:** CLaaS (Compliance as a Service) — aka Cyntinel  
> **Purpose:** NIST RMF automation, analytics, and reporting platform built on Qlik Sense Enterprise  
> **Focus:** NIST OSCAL integration into Qlik Sense Server

---

## Project Overview

CLaaS is a federal cybersecurity and GRC (Governance, Risk, and Compliance) platform that provides a **single pane of glass** for NIST Risk Management Framework (RMF) workflows. It automates the ingestion, normalization, visualization, and reporting of security tool scan data against NIST 800-53 controls, and generates OSCAL-compliant documentation artifacts.

### Core Capabilities

- **Scan Data Ingestion:** Nessus, Burp Suite, Fortify, and other security scanner outputs
- **RMF Analytics:** Rogue host detection, vulnerability POA&M tracking, control compliance views
- **OSCAL Documentation Generation:** System Security Plans (SSP) and other OSCAL artifacts
- **Compliance Dashboards:** NIST 800-53 control family coverage, risk scoring, and status reporting

---

## Architecture

### Applications

CLaaS consists of **two Qlik Sense applications**:

| App | Purpose |
|-----|---------|
| **CLaaS App** | Primary RMF/GRC analytics and reporting interface; OSCAL output; dashboards for compliance, vulnerability, and host analysis |
| **QVD Generator App** | ETL layer; ingests raw scan data, normalizes to NIST control mappings, and produces QVD (Qlik View Data) files consumed by the CLaaS App |

### Data Flow

```
Security Tools (Nessus, Burp, Fortify, etc.)
        ↓
  QVD Generator App  (Qlik Sense — ETL / normalization)
        ↓
      QVD Files      (normalized, NIST 800-53 mapped)
        ↓
    CLaaS App        (Qlik Sense — analytics, dashboards, OSCAL generation)
        ↓
  OSCAL Artifacts    (SSP, POA&M, etc.) + GRC Dashboards
```

### Infrastructure

| Component | Value |
|-----------|-------|
| **Development Server** | `https://cyntinel-dev.ad.cyntinel.net` |
| **Hosting** | AWS |
| **Platform** | Qlik Sense Enterprise (Server) |
| **SensorOps CM URL** | `http://cyntinel-dev.ad.cyntinel.net:4040/repositories` |

---

## Development Environment & Tooling

### Source Control — Git (Local) + SensorOps (CM Tool)

**Local git repo:** `k:\Documents\GitHub\QOSCAL`
- Initialized April 2026; identity set to `Art Clomera <arthur.clomera@gmail.com>` (local only)
- Contains: `CLaaS Scripts/`, `CLAUDE.md`, and the NIST OSCAL submodule (`OSCAL/`)
- NIST OSCAL is tracked as a **git submodule** pinned to `v1.2.1` — run `git submodule update --init --recursive` after cloning
- To update the OSCAL submodule to a newer release: `cd OSCAL && git fetch && git checkout <tag> && cd .. && git add OSCAL && git commit`

**SensorOps (CM Tool):** `http://cyntinel-dev.ad.cyntinel.net:4040/repositories`
- Authoritative CM tool for deployed CLaaS artifacts on the Qlik Sense server
- All load scripts, OSCAL templates, and data connection configs that are deployed to the dev/prod server are version-controlled here
- Treat SensorOps as the source of truth for **deployed** artifact versions

### Agile / Project Management — Azure DevOps

- **Organization:** `https://dev.azure.com/ipkeys`
- **Project:** `CLaaS Development`
- **Wiki:** `https://dev.azure.com/ipkeys/CLaaS%20Development/_wiki/wikis/CLaaS.wiki/1/CLaaS-Wiki`
- Use Azure DevOps for sprint planning, work items, bug tracking, and feature backlogs
- Always reference the ADO Wiki before implementing new OSCAL schema mappings or RMF workflow changes — architecture decisions and data dictionaries are documented there

### Qlik Sense Development

- Development happens against the dev server: `https://cyntinel-dev.ad.cyntinel.net`
- Use **Qlik Sense Business Intelligence Client (web UI)** for sheet/visualization development
- Use the **Qlik Sense Dev Hub** for extensions and mashups if applicable
- Load scripts (`.qvs`) and data connection configs are the primary code artifacts — keep them in SensorOps

---

## NIST OSCAL Integration

This is the primary technical focus area. All OSCAL work must conform to the **NIST OSCAL specification** and be implemented in a way that Qlik Sense can generate or consume the output.

### OSCAL Artifacts in Scope

| Artifact | OSCAL Layer | CLaaS Role |
|----------|-------------|------------|
| System Security Plan (SSP) | `system-security-plan` | Primary generated output from CLaaS App |
| Plan of Action & Milestones (POA&M) | `plan-of-action-and-milestones` | Driven by vulnerability scan findings |
| Assessment Results | `assessment-results` | Mapped from scanner findings to controls |
| Component Definition | `component-definition` | System component inventory from scan data |

### OSCAL Format Standards

- **Preferred serialization:** JSON (for programmatic generation within Qlik); XML as secondary export
- **OSCAL version:** Current stable release is `v1.2.1` — cloned locally at `OSCAL/`; reference `https://pages.nist.gov/OSCAL` for spec
- **Schema validation:** All generated OSCAL must validate against official NIST OSCAL JSON Schema before delivery; local schemas are at `OSCAL/src/metaschema/`
- **UUID generation:** Every OSCAL object requires a RFC 4122 UUID; generate deterministically where possible to support idempotent re-generation from the same scan data

### NIST 800-53 Control Mapping

- The canonical control catalog is NIST SP 800-53 Rev 5
- Control IDs follow the format: `AC-1`, `AC-2(1)`, etc.
- The QVD Generator App is responsible for mapping scanner plugin IDs / CVEs to control IDs
- Maintain a **control mapping table** in SensorOps that links:
  - Scanner finding type → CWE/CVE → NIST 800-53 control(s)
  - Nessus Plugin ID → control mapping
  - Fortify category → control mapping
  - Burp finding type → control mapping

### OSCAL Generation Pattern in Qlik

Since Qlik Sense does not natively output OSCAL, generation is handled via one of these patterns:

1. **Server-Side Script Export:** Qlik load script generates structured data → exported as JSON via NPrinting or a Qlik REST connector → post-processed into OSCAL schema
2. **Inline JavaScript Extension:** A Qlik Sense extension (mashup/widget) assembles OSCAL JSON client-side from chart data and triggers a browser download
3. **Backend API Bridge:** A lightweight API endpoint (Python/Node) receives structured data from Qlik via REST and returns a valid OSCAL document

> **Current preferred approach:** Document the chosen pattern in the Azure DevOps Wiki before implementing. Confirm with the team which pattern is in use for each artifact type.

---

## Data Sources & Ingestion

### Supported Scanners

| Tool | Data Format | Notes |
|------|-------------|-------|
| **Nessus** | `.nessus` XML | Primary vulnerability scanner; plugin IDs map to controls |
| **Burp Suite** | XML export | Web application findings (DAST) |
| **Fortify** | FPR / XML | Static analysis (SAST); maps to CWE then to 800-53 |
| **RHACS** | CSV | Red Hat Advanced Cluster Security; container vulnerability findings |
| **Prisma Cloud** | CSV | Container/cloud vulnerability findings; similar schema to RHACS |

### Ingestion Rules (QVD Generator App)

- All raw scan files should be staged in a designated S3 bucket or UNC path accessible to the Qlik Sense server
- The QVD Generator load script must:
  1. Parse scanner output to a normalized schema
  2. Apply the control mapping table
  3. Deduplicate findings by host + plugin/finding ID
  4. Write QVD files with consistent field names (see field naming conventions below)
  5. Stamp each QVD with ingestion timestamp and source scanner metadata

### Field Naming Conventions

Use consistent field names across all QVDs to enable JOINs in the CLaaS App. These are the **actual field names used in the load scripts** (not logical aliases):

| Field | Type | Description |
|-------|------|-------------|
| `IP Address` | String | Target IP address (space in name — always bracket: `[IP Address]`) |
| `ProgramHostID` | String | Composite key: `vProject` & IP/hostname |
| `HostKeyID` | String | MAC address used as hardware identity key |
| `VulID` | String | Scanner-native finding or plugin ID |
| `CVE_ID` | String | CVE identifier (RHACS/Prisma); Nessus uses `CVE` field directly |
| `SeverityID` | String | `Very High`, `High`, `Medium`, `Low`, `Info` |
| `STIG_Severity` | String | `CAT I`, `CAT II`, `CAT III`, `Info` (Nessus/STIG only) |
| `Control_Temp` | String | Mapped NIST 800-53 control (intermediate field; renamed to `Control` in CLaaS App) |
| `Source` | String | `Nessus`, `Burp`, `CheckList`, `SCAP` (added by QVDLoader) |
| `Scan Date` | Date | Date of the scan (space in name — always bracket: `[Scan Date]`) |
| `STATUS` | String | `Open`, `Closed` — Nessus derives this from most-recent scan per IP |
| `ProgramVulID` | String | `vProject` & `VulID` composite |
| `CVSS Score` | Number | CVSS v3 base score |
| `Synopsis` | String | Plugin output / finding detail |
| `Recommendation` | String | Solution & see-also combined |
| `POAMRequired` | Boolean | Whether a POA&M entry is needed |

> **Note:** `RawConcat1` is a deduplication key built as `vProject & date([Scan Date],'YYYYMMDD') & [IP Address] & SeverityID & VulID`. Always use `date(field,'YYYYMMDD')` syntax — **not** `date(field&'YYYYMMDD')`.

---

## QVD Generator Script Architecture

### Script Directory

All load scripts live in `CLaaS Scripts/`. The canonical production version as of the last review is **v3.2.4** (`Nessus QVD Loader v3.2.4.qvs`). Older versioned files (`v3.2.1.7`, `v3.2.1.5`, `v3.2.2 ART/CHRIS/BOTH`) are retained for reference but should not be used in production.

### Router Tables (must be populated before scanner subs run)

| Table | Purpose |
|-------|---------|
| `QVDFilesRouter` | Maps each `FileType` to its QVD table name, source name field, and store path |
| `GlobalFromBStatements` | Maps `FileType` + `Designation` to FROM-clause suffix expressions (e.g., XML table paths) |
| `StorePaths` | Maps `FileType` to the `lib://` store path for each QVD |
| `SourceFileRouter` | Maps `FileType` to source file path, scan date FROMB, and file pattern |

### Subroutine Library

These subs must be loaded (via `$(Include=...)`) before any scanner section runs:

| Sub | File | Purpose |
|-----|------|---------|
| `GenerateFROMBs(FromB, FromBBaseTable [,URLIS])` | `SubsCommonToAllQVDs v3.2.1.7+.qvs` | Builds numbered `vFROMB01`…`vFROMBNN` variables from a router table |
| `OrganizeSourceFilesByScanDate(...)` | `SubsCommonToAllQVDs v3.2.1.7+.qvs` | Sorts source files by scan date; produces `TEMP_FilesByDateSorted` |
| `SafeConcat(vTargetTable, vSourceTable)` | `Safe Concat.qvs` | Renames or concatenates a temp table into a main table safely |
| `DropATable(tableName)` | *(main script)* | Drops a table only if it exists |
| `StoreATable(tableName, path, dropFlag)` | *(main script)* | Stores a QVD and optionally drops the source table |
| `CreateSortTable(src, dest, orderBy)` | *(main script)* | Creates a sorted copy of a table |

> **Important:** Always load `SubsCommonToAllQVDs v3.2.1.7+.qvs` (3-parameter version of `GenerateFROMBs`), not `v3.2.1.7.qvs` (2-parameter). Burp, RHACS, and Prisma pass a SharePoint URLIS as the third argument.

### Scanner Sub Pattern

Each scanner follows this structure inside `Sub ScannerName(vProject)`:

1. Bail out early if `$(vNumberOfNewXXXFiles) = 0`
2. Populate `FromBRouter` from `GlobalFromBStatements` for the file type
3. Call `OrganizeSourceFilesByScanDate(...)` → produces `TEMP_FilesByDateSorted`
4. Loop `for filerow=0 to NoOfRows('TEMP_FilesByDateSorted')-1` (**always use `TEMP_FilesByDateSorted`, not the QVD table**)
5. Inside loop: call `GenerateFROMBs`, load `_Temp` tables, safe-concat into main tables
6. After loop: derive `STATUS` (Open/Closed) from most-recent scan date per IP
7. Store all QVDs via router; drop `_UniqueSource` and folder-file temp tables

### Source Switch

| `vSourceSwitch` | Meaning |
|-----------------|---------|
| `0` | Local file system (FROMA = file path) |
| `1` | SharePoint via connector (FROMA = `lib://connector/...`) |

### QVDs Produced per Nessus File

| QVD Table Variable | Content |
|--------------------|---------|
| `$(NessusQVDTable)` | Core vulnerability findings |
| `$(NessusPPSMQVDTable)` | Port/Protocol/Service/MAC (network inventory) |
| `$(NessusSoftwareQVDTable)` | Installed software (plugins 20811/22869) |
| `$(NessusCPEQVDTable)` | CPE hardware/app/OS classification (only created if CPE data present) |
| `$(NessusComplianceQVDTable)` | Policy Compliance family results |
| `$(NessusPluginStatusFamilyQVDTable)` | Plugin family enable/disable status |
| `$(NessusPluginStatusPreferencesQVDTable)` | Per-plugin preference settings |

---

## RMF Analytics Views

The CLaaS App must support the following analytical views:

### Compliance Views

- **Control Family Heatmap:** Coverage and open finding counts by 800-53 control family (AC, AU, CA, CM, etc.)
- **Control Detail Drilldown:** Per-control status, mapped findings, and responsible system components
- **System Boundary Compliance Score:** Aggregate score per system or authorization boundary

### Vulnerability & Risk Views

- **Rogue Host Detection:** Hosts appearing in scan data that are not in the authorized system inventory
- **Vulnerability POA&M Dashboard:** Open findings requiring POA&M entries; aging, severity trending
- **CVE/CWE Cross-Reference:** Link from CVE/CWE back to impacted controls and affected hosts

### OSCAL Documentation Views

- **SSP Readiness:** Completeness indicators for SSP sections (system description, control implementations, etc.)
- **Assessment Evidence:** Mapping of scan findings to assessment objectives
- **POA&M Export:** Filterable POA&M table exportable to OSCAL JSON

---

## Coding & Scripting Standards

### Qlik Load Script (.qvs)

- Use `//` comments to document each section; include purpose, inputs, and outputs at the top of each script block
- Use `LET` and `SET` for variables; prefix with context (e.g., `v_ScanDate`, `v_ControlFamily`)
- Qualify all field names in JOINs using explicit table aliases
- Always include a `NoConcatenate` on new `LOAD` statements to prevent accidental concatenation
- Use `STORE ... INTO [path].qvd (qvd)` with a descriptive filename that includes the data domain and date stamp where appropriate
- Include error handling via `$(ScriptError)` checks after critical `LOAD` statements

### Known Script Patterns & Pitfalls

Mistakes found during the April 2026 script review — do not repeat these:

| Pattern | Wrong | Correct |
|---------|-------|---------|
| File loop counter | `NoOfRows('$(BurpQVDTable)')` | `NoOfRows('TEMP_FilesByDateSorted')` |
| Date format in key field | `date([Scan Date]&'YYYYMMDD')` | `date([Scan Date],'YYYYMMDD')` |
| Table label with variable | `$(NessusComplianceQVDTable)_Temp:` | `[$(NessusComplianceQVDTable)_Temp]:` |
| Second load into named table | bare `Load ...` | `Concatenate (TableName) Load ...` |
| TableNumber check | `TableNumber(MyTable)` | `TableNumber('MyTable')` |
| Scanner LOOKUP key | `LOOKUP(...,'RHACS',...)` in Prisma sub | `LOOKUP(...,'Prisma',...)` |
| vSourceFileField in Prisma | LOOKUP line commented out | Must be active; `vSourceFileField` used in SP loop |
| FromBRouter in Prisma | creation block commented out | Must be created before `GenerateFROMBs` call |

**Safe concat pattern** — always use this when merging a `_Temp` table into a main table:
```qvs
IF Alt(NoOfRows('$(MyTable)_Temp'), -1) > -1 THEN
  IF Alt(NoOfRows('$(MyTable)'), -1) = -1 THEN
    RENAME TABLE [$(MyTable)_Temp] TO [$(MyTable)];
  ELSE
    CONCATENATE ([$(MyTable)]) LOAD * RESIDENT [$(MyTable)_Temp];
    DROP TABLE [$(MyTable)_Temp];
  END IF
END IF
```

**STATUS derivation pattern** — always needed after loading all Nessus files:
```qvs
Call CreateSortTable('$(NessusQVDTable)','TEMP_NessusByIpByDate','[IP Address] asc, [Scan Date] desc');
TEMP_ScanDateIPStatus:
NoConcatenate Load [IP Address], [Scan Date], 'Open' as STATUS
  Resident TEMP_NessusByIpByDate Where [IP Address]<>Previous([IP Address]);
Concatenate (TEMP_ScanDateIPStatus)                            // ← required prefix
Load [IP Address], [Scan Date], 'Closed' as STATUS
  Resident TEMP_NessusByIpByDate
  Where [IP Address]=Previous([IP Address]) and [Scan Date]<>Previous([Scan Date]);
left join ([$(NessusQVDTable)]) Load * Resident TEMP_ScanDateIPStatus;
```

### OSCAL JSON Generation

- Validate every generated document against the NIST OSCAL JSON Schema
- Use deterministic UUIDs (UUIDv5 with a project namespace) for recurring entities (systems, components, controls)
- Never hardcode OSCAL catalog UUIDs; reference the official NIST catalog identifiers
- All `last-modified` timestamps must be in RFC 3339 format (`YYYY-MM-DDTHH:MM:SSZ`)

### Version Control

**Local git (QOSCAL repo):**
- Commit messages: `[TYPE] Short description` where TYPE is `FEAT`, `FIX`, `REFACTOR`, `DOCS`, `DATA`
- Branch naming: `feature/short-description`, `fix/issue-number-description`

**SensorOps:**
- Follow the same commit message convention when checking artifacts into SensorOps
- Tag releases that correspond to ADO sprint completions

---

## Security & Compliance Constraints

- **No PII or classified data** on the development server — use sanitized/synthetic scan data for dev and testing
- **Authentication:** Qlik Sense is enterprise-deployed; use Active Directory (AD) authentication — dev AD domain is `cyntinel-dev.ad.cyntinel.net`
- **Data in transit:** All connections to the Qlik Sense server must use HTTPS; confirm TLS 1.2+ is enforced
- **OSCAL outputs** may contain sensitive system descriptions — handle generated artifacts as CUI (Controlled Unclassified Information) in production contexts
- **AWS posture:** Follow least-privilege IAM for any Lambda, S3, or EC2 resources backing the ingestion pipeline

---

## Key References

| Resource | URL |
|----------|-----|
| CLaaS Wiki (Azure DevOps) | `https://dev.azure.com/ipkeys/CLaaS%20Development/_wiki/wikis/CLaaS.wiki/1/CLaaS-Wiki` |
| SensorOps (CM) | `http://cyntinel-dev.ad.cyntinel.net:4040/repositories` |
| Development Server | `https://cyntinel-dev.ad.cyntinel.net` |
| NIST OSCAL Spec | `https://pages.nist.gov/OSCAL` |
| NIST OSCAL GitHub | `https://github.com/usnistgov/OSCAL` |
| NIST 800-53 Rev 5 | `https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final` |
| OSCAL JSON Schema | `https://github.com/usnistgov/OSCAL/tree/main/json/schema` |

---

## Common Tasks for Claude

When assisting with CLaaS development, follow these patterns:

### "Generate OSCAL for a finding"
Map the actual script field names (`VulID`, `CVE`/`CVE_ID`, `Control_Temp`, `SeverityID`, `STATUS`, `CVSS Score`) to the appropriate OSCAL `assessment-results` or `plan-of-action-and-milestones` structure. Use the field naming conventions table above. Validate JSON against the local schemas at `OSCAL/src/metaschema/`.

### "Write a Qlik load script"
Follow the `.qvs` standards above. Ask for the source data format, target QVD name, and which fields from the naming convention table are applicable before writing.

### "Debug a control mapping issue"
First check the control mapping table in SensorOps for the relevant scanner source. Verify whether the finding has a CVE/CWE, and trace through the mapping chain: scanner ID → CWE/CVE → 800-53 control.

### "Generate an SSP section"
Reference the OSCAL `system-security-plan` schema. Pull system metadata from the CLaaS App data model. Map control implementations from the compliance view data. Output valid OSCAL JSON and note which fields require manual completion by the system owner.

### "Debug a QVD Generator script issue"
1. Check that the correct subroutine file is included (`SubsCommonToAllQVDs v3.2.1.7+.qvs`, not the 2-param version)
2. Verify router tables (`QVDFilesRouter`, `GlobalFromBStatements`, `StorePaths`, `SourceFileRouter`) exist and contain the relevant `FileType` row
3. Confirm the file loop uses `NoOfRows('TEMP_FilesByDateSorted')`, not the QVD table
4. Check that `FromBRouter` is created inside the sub before `GenerateFROMBs` is called
5. Verify `vSourceFileField` is set via LOOKUP (not commented out) before it is used
6. Review the safe-concat pattern around all `_Temp` → main table merges

### "Add a new scanner source"
1. Define the raw schema from the scanner export format
2. Create a new `Sub ScannerName(vProject)` following the established pattern (see `RHACS.qvs` as the simplest CSV example)
3. Add a `FileType` row to `QVDFilesRouter`, `GlobalFromBStatements`, `StorePaths`, and `SourceFileRouter`
4. Add the file type to `OrganizeSourceFilesByScanDate`'s `if/elseif` chain for date extraction
5. Extend the control mapping table in SensorOps
6. Update the CLaaS App data model if new fields are introduced
7. Document the new source in the Azure DevOps Wiki
