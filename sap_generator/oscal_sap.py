"""
OSCAL Security Assessment Plan (SAP) document builder.

Produces a conformant OSCAL v1.2.1 assessment-plan JSON structure from
:class:`~sap_generator.assessment_model.AssessmentData` (QVD-derived) and
:class:`~sap_generator.assessment_model.AssessmentConfig` (user-supplied).

Document structure
------------------
metadata
    Title, roles, parties.  Two parties are created: the system owner
    organisation and the assessor organisation.

import-ssp
    Reference to the SSP under assessment.  The href is user-supplied
    via ``--ssp-href``; it defaults to a placeholder reminder string.

local-definitions
    components      — Nessus scanner tool component.
    activities      — One 'TEST' activity for automated vulnerability
                      scanning.  When a Compliance QVD was provided, a
                      second 'TEST' activity for policy compliance
                      scanning is also included.

terms-and-conditions
    Parts for: rules-of-engagement, methodology, assumptions.

reviewed-controls
    control-selections          — include-controls list built from unique
                                  NIST 800-53 control IDs in Control_Temp.
    control-objective-selections — one objective per control (``{id}_obj``).

assessment-subjects
    One entry per unique host IP (type: component).  Each subject's UUID
    matches the deterministic UUID the SSP generator produces for the same
    host, enabling cross-document linkage.

assessment-assets
    Components: Nessus scanner tool (mirrors local-definitions/components).
    Platforms: one platform entry per assessment subject (host).

tasks
    One task per unique scan date, each associated with the automated-scan
    activity and listing all subjects scanned on that date.  Falls back to
    a single 'Automated Vulnerability Scan' task when no date data exists.

back-matter
    Resource entries for the QVD source files.

References
----------
- OSCAL AP metaschema: OSCAL/src/metaschema/oscal_assessment-plan_metaschema.xml
- OSCAL assessment-common metaschema: oscal_assessment-common_metaschema.xml
- NIST SP 800-18 Rev 1 (SAP guidance)
- OSCAL specification: https://pages.nist.gov/OSCAL
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from .assessment_model import AssessmentConfig, AssessmentData
from poam_generator.uuid_utils import det_uuid, rand_uuid

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OSCAL_VERSION = "1.2.1"
_NS_OSCAL = "http://csrc.nist.gov/ns/oscal"
_NS_FEDRAMP = "https://fedramp.gov/ns/oscal"

# Deterministic UUIDs for the Nessus scanner tool (stable across runs)
_NESSUS_TOOL_UUID = det_uuid("component:tool:tenable-nessus")

# Activity UUIDs
_ACT_VULN_SCAN_UUID = det_uuid("activity:automated-vulnerability-scan")
_ACT_COMPLIANCE_SCAN_UUID = det_uuid("activity:automated-compliance-scan")


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _to_rfc3339(iso_date: Optional[str]) -> Optional[str]:
    if not iso_date:
        return None
    return f"{iso_date}T00:00:00Z"


# ---------------------------------------------------------------------------
# metadata
# ---------------------------------------------------------------------------

def _metadata(config: AssessmentConfig) -> dict:
    owner_uuid = det_uuid(f"party:{config.org_name}")
    assessor_uuid = det_uuid(f"party:{config.assessor_name}")

    roles = [{"id": r["id"], "title": r["title"]} for r in config.roles]

    return {
        "title": f"Security Assessment Plan — {config.system_name}",
        "last-modified": _now(),
        "version": config.version,
        "oscal-version": OSCAL_VERSION,
        "roles": roles,
        "parties": [
            {
                "uuid": owner_uuid,
                "type": "organization",
                "name": config.org_name,
                "remarks": "System owner organisation.",
            },
            {
                "uuid": assessor_uuid,
                "type": "organization",
                "name": config.assessor_name,
                "remarks": "Assessment organisation (3PAO or government assessor).",
            },
        ],
        "responsible-parties": [
            {
                "role-id": "prepared-by",
                "party-uuids": [assessor_uuid],
            },
            {
                "role-id": "assessor",
                "party-uuids": [assessor_uuid],
            },
            {
                "role-id": "system-owner",
                "party-uuids": [owner_uuid],
            },
        ],
        "remarks": (
            "This SAP was generated by the CLaaS OSCAL SAP Generator from "
            "Nessus QVD scan data.  Sections marked 'REQUIRED' must be "
            "completed by the assessor before submission."
        ),
    }


# ---------------------------------------------------------------------------
# import-ssp
# ---------------------------------------------------------------------------

def _import_ssp(config: AssessmentConfig) -> dict:
    return {
        "href": config.ssp_href,
        "remarks": (
            "Reference to the System Security Plan (SSP) for the system "
            "under assessment.  Update href to the correct relative or "
            "absolute path before submission."
        ),
    }


# ---------------------------------------------------------------------------
# local-definitions — scanner tool component + activities
# ---------------------------------------------------------------------------

def _nessus_tool_component() -> dict:
    return {
        "uuid": _NESSUS_TOOL_UUID,
        "type": "tool",
        "title": "Tenable Nessus Professional",
        "description": (
            "Automated vulnerability scanner used to identify security "
            "findings and policy compliance results on target hosts. "
            "Findings are mapped to NIST SP 800-53 Rev 5 controls by the "
            "CLaaS QVD Generator App."
        ),
        "props": [
            {"name": "tool-type",    "value": "vulnerability-scanner", "ns": _NS_OSCAL},
            {"name": "vendor",       "value": "Tenable, Inc.",          "ns": _NS_OSCAL},
            {"name": "scan-method",  "value": "authenticated",          "ns": _NS_OSCAL},
        ],
        "status": {"state": "operational"},
        "responsible-roles": [
            {"role-id": "assessor"},
        ],
    }


def _vuln_scan_activity() -> dict:
    """Automated vulnerability scan — OSCAL 'TEST' activity."""
    return {
        "uuid": _ACT_VULN_SCAN_UUID,
        "title": "Automated Vulnerability Scan",
        "description": (
            "Authenticated Nessus vulnerability scan of all hosts within "
            "the system authorization boundary.  Plugin findings are mapped "
            "to NIST SP 800-53 Rev 5 controls by the CLaaS QVD Generator."
        ),
        "props": [
            {"name": "method", "value": "TEST", "ns": _NS_OSCAL},
        ],
        "steps": [
            {
                "uuid": det_uuid("step:vuln-scan:configure"),
                "title": "Configure Scan Policy",
                "description": (
                    "Configure Nessus scan policy with credentialed settings "
                    "targeting hosts within the authorization boundary."
                ),
            },
            {
                "uuid": det_uuid("step:vuln-scan:execute"),
                "title": "Execute Credentialed Scan",
                "description": (
                    "Run authenticated Nessus scan against in-scope hosts. "
                    "Collect plugin output for all severity levels."
                ),
            },
            {
                "uuid": det_uuid("step:vuln-scan:export"),
                "title": "Export and Ingest Scan Results",
                "description": (
                    "Export scan results as .nessus XML. "
                    "Ingest into CLaaS QVD Generator to produce normalised QVD files "
                    "with NIST 800-53 control mappings."
                ),
            },
        ],
        "related-controls": {
            "description": "Controls reviewed by automated vulnerability scan.",
        },
    }


def _compliance_scan_activity() -> dict:
    """Policy compliance scan — OSCAL 'TEST' activity."""
    return {
        "uuid": _ACT_COMPLIANCE_SCAN_UUID,
        "title": "Automated Policy Compliance Scan",
        "description": (
            "Nessus Policy Compliance family plugin scan producing STIG / "
            "CIS benchmark results.  Results map to NIST SP 800-53 Rev 5 "
            "controls via the CLaaS compliance QVD."
        ),
        "props": [
            {"name": "method", "value": "TEST", "ns": _NS_OSCAL},
        ],
        "steps": [
            {
                "uuid": det_uuid("step:compliance-scan:configure"),
                "title": "Configure Compliance Audit Policy",
                "description": (
                    "Load applicable DISA STIG or CIS benchmark audit file "
                    "into the Nessus compliance scan policy."
                ),
            },
            {
                "uuid": det_uuid("step:compliance-scan:execute"),
                "title": "Execute Compliance Scan",
                "description": (
                    "Run compliance scan against in-scope hosts. "
                    "Collect PASSED/FAILED/WARNING results for each check."
                ),
            },
        ],
    }


def _local_definitions(has_compliance: bool) -> dict:
    activities = [_vuln_scan_activity()]
    if has_compliance:
        activities.append(_compliance_scan_activity())

    return {
        "components": [_nessus_tool_component()],
        "activities": activities,
    }


# ---------------------------------------------------------------------------
# terms-and-conditions
# ---------------------------------------------------------------------------

def _terms_and_conditions(config: AssessmentConfig) -> dict:
    parts = [
        {
            "uuid": det_uuid(f"part:roe:{config.system_name}"),
            "name": "rules-of-engagement",
            "title": "Rules of Engagement",
            "prose": config.rules_of_engagement,
        },
        {
            "uuid": det_uuid(f"part:methodology:{config.system_name}"),
            "name": "methodology",
            "title": "Assessment Methodology",
            "prose": config.methodology,
        },
        {
            "uuid": det_uuid(f"part:assumptions:{config.system_name}"),
            "name": "assumptions",
            "title": "Assumptions",
            "prose": config.assumptions,
        },
    ]
    return {"parts": parts}


# ---------------------------------------------------------------------------
# reviewed-controls
# ---------------------------------------------------------------------------

def _reviewed_controls(data: AssessmentData, config: AssessmentConfig) -> dict:
    """
    Build reviewed-controls from the unique control IDs in the QVD data.

    Each control ID from Control_Temp becomes an include-controls entry.
    A matching control-objective-selections entry references the primary
    objective for that control (``{control-id}_obj``).
    """
    include_controls = [
        {"control-id": cid} for cid in data.unique_controls
    ]
    include_objectives = [
        {"objective-id": f"{cid}_obj"} for cid in data.unique_controls
    ]

    return {
        "description": (
            f"Controls reviewed during the CLaaS automated vulnerability "
            f"and compliance scan assessment of {config.system_name}. "
            f"Control list is derived from the NIST 800-53 control mappings "
            f"in the CLaaS Nessus QVD."
        ),
        "control-selections": [
            {
                "description": (
                    "NIST SP 800-53 Rev 5 controls identified in CLaaS scan data "
                    "via the Control_Temp field mapping."
                ),
                "include-controls": include_controls,
            }
        ],
        "control-objective-selections": [
            {
                "description": (
                    "Primary assessment objectives for each reviewed control, "
                    "derived from the NIST SP 800-53A Rev 5 assessment procedures."
                ),
                "include-objectives": include_objectives,
            }
        ],
    }


# ---------------------------------------------------------------------------
# assessment-subjects
# ---------------------------------------------------------------------------

def _assessment_subjects(data: AssessmentData, config: AssessmentConfig) -> list[dict]:
    """
    One assessment-subject entry per unique host IP.

    The subject-uuid matches what the SSP generator produces for the same
    host (det_uuid('inventory:<ip>')), enabling SAP ↔ SSP cross-referencing.
    """
    subjects_by_date: dict[str, list[dict]] = defaultdict(list)

    for host in data.system_data.hosts:
        ref = {
            "subject-uuid": det_uuid(f"inventory:{host.ip_address}"),
            "type": "inventory-item",
            "props": [
                {"name": "ipv4-address", "value": host.ip_address, "ns": _NS_OSCAL},
            ],
            "remarks": (
                f"Host {host.ip_address}. "
                f"Credentialed: {host.credentialed_scan}. "
                f"Scan date: {host.scan_date or 'unknown'}."
            ),
        }
        if host.os_name:
            ref["props"].append(
                {"name": "operating-system", "value": host.os_name, "ns": _NS_OSCAL}
            )
        bucket = host.scan_date or "all"
        subjects_by_date[bucket].append(ref)

    # Emit one assessment-subject block covering all hosts
    all_refs = [ref for refs in subjects_by_date.values() for ref in refs]
    return [
        {
            "type": "inventory-item",
            "description": (
                f"All hosts within the {config.system_name} authorization boundary "
                f"identified by the CLaaS Nessus vulnerability scan. "
                f"Total hosts: {len(all_refs)}."
            ),
            "props": [
                {
                    "name": "scan-type",
                    "value": "Nessus",
                    "ns": _NS_OSCAL,
                }
            ],
            "include-subjects": all_refs,
        }
    ]


# ---------------------------------------------------------------------------
# assessment-assets
# ---------------------------------------------------------------------------

def _assessment_assets(data: AssessmentData) -> dict:
    """
    Nessus scanner as the primary assessment tool.
    Platforms list one entry per unique host IP.
    """
    platforms = [
        {
            "uuid": det_uuid(f"platform:{h.ip_address}"),
            "title": h.ip_address,
            "props": [
                {"name": "ipv4-address",  "value": h.ip_address,       "ns": _NS_OSCAL},
                {"name": "asset-type",    "value": "computing-device",  "ns": _NS_OSCAL},
            ],
            "uses-components": [
                {"component-uuid": _NESSUS_TOOL_UUID}
            ],
        }
        for h in data.system_data.hosts
    ]

    return {
        "components": [_nessus_tool_component()],
        "assessment-platforms": platforms,
    }


# ---------------------------------------------------------------------------
# tasks
# ---------------------------------------------------------------------------

def _subjects_for_date(
    data: AssessmentData, scan_date: Optional[str]
) -> list[dict]:
    """Return subject-reference list for hosts scanned on *scan_date*."""
    hosts = (
        [h for h in data.system_data.hosts if h.scan_date == scan_date]
        if scan_date
        else data.system_data.hosts
    )
    return [
        {
            "subject-uuid": det_uuid(f"inventory:{h.ip_address}"),
            "type": "inventory-item",
        }
        for h in hosts
    ]


def _scan_task(
    scan_date: Optional[str],
    task_index: int,
    data: AssessmentData,
    has_compliance: bool,
) -> dict:
    """Build one OSCAL task for a single scan date."""
    label = scan_date or "undated"
    task_uuid = det_uuid(f"task:scan:{label}:{task_index}")

    timing: dict = {}
    if scan_date:
        timing = {"on-date": {"date": f"{scan_date}T00:00:00Z"}}

    subjects = _subjects_for_date(data, scan_date)

    associated_activities = [
        {
            "activity-uuid": _ACT_VULN_SCAN_UUID,
            "subjects": subjects,
        }
    ]
    if has_compliance:
        associated_activities.append(
            {
                "activity-uuid": _ACT_COMPLIANCE_SCAN_UUID,
                "subjects": subjects,
            }
        )

    task: dict = {
        "uuid": task_uuid,
        "type": "action",
        "title": (
            f"Automated Nessus Scan — {scan_date}"
            if scan_date
            else "Automated Nessus Scan"
        ),
        "description": (
            f"Credentialed Nessus vulnerability scan "
            f"{'on ' + scan_date if scan_date else ''}. "
            f"Hosts scanned: {len(subjects)}."
        ),
        "associated-activities": associated_activities,
        "responsible-roles": [
            {"role-id": "assessor"},
        ],
    }

    if timing:
        task["timing"] = timing

    return task


def _tasks(
    data: AssessmentData,
    config: AssessmentConfig,
    has_compliance: bool,
) -> list[dict]:
    """Build the task list — one task per unique scan date."""
    if data.unique_scan_dates:
        return [
            _scan_task(d, i, data, has_compliance)
            for i, d in enumerate(data.unique_scan_dates)
        ]
    # No date data: single placeholder task
    return [_scan_task(None, 0, data, has_compliance)]


# ---------------------------------------------------------------------------
# back-matter
# ---------------------------------------------------------------------------

def _back_matter(
    nessus_path: str,
    ppsm_path: Optional[str],
    software_path: Optional[str],
    compliance_path: Optional[str],
) -> dict:
    resources = [
        {
            "uuid": det_uuid(f"resource:sap-nessus-qvd:{nessus_path}"),
            "title": "Nessus Main QVD",
            "description": "CLaaS Nessus vulnerability findings QVD — primary scan evidence source.",
            "rlinks": [{"href": nessus_path}],
        }
    ]
    if ppsm_path:
        resources.append(
            {
                "uuid": det_uuid(f"resource:sap-ppsm-qvd:{ppsm_path}"),
                "title": "Nessus PPSM QVD",
                "description": "Port/Protocol/Service/MAC network inventory QVD.",
                "rlinks": [{"href": ppsm_path}],
            }
        )
    if software_path:
        resources.append(
            {
                "uuid": det_uuid(f"resource:sap-software-qvd:{software_path}"),
                "title": "Nessus Software QVD",
                "description": "Installed software inventory QVD.",
                "rlinks": [{"href": software_path}],
            }
        )
    if compliance_path:
        resources.append(
            {
                "uuid": det_uuid(f"resource:sap-compliance-qvd:{compliance_path}"),
                "title": "Nessus Compliance QVD",
                "description": "Policy Compliance family results QVD.",
                "rlinks": [{"href": compliance_path}],
            }
        )
    return {"resources": resources}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_sap(
    data: AssessmentData,
    config: AssessmentConfig,
    *,
    nessus_path: str = "",
    ppsm_path: Optional[str] = None,
    software_path: Optional[str] = None,
    compliance_path: Optional[str] = None,
) -> dict:
    """
    Build a complete OSCAL SAP document from QVD-derived data and config.

    Args:
        data:            :class:`AssessmentData` loaded from QVD files.
        config:          :class:`AssessmentConfig` with assessment metadata.
        nessus_path:     Source QVD path for back-matter reference.
        ppsm_path:       Optional PPSM QVD path.
        software_path:   Optional Software QVD path.
        compliance_path: Optional Compliance QVD path.

    Returns:
        A dict that serialises directly to a valid OSCAL SAP JSON document.
    """
    has_compliance = bool(compliance_path and data.system_data.compliance)

    return {
        "assessment-plan": {
            "uuid": rand_uuid(),
            "metadata": _metadata(config),
            "import-ssp": _import_ssp(config),
            "local-definitions": _local_definitions(has_compliance),
            "terms-and-conditions": _terms_and_conditions(config),
            "reviewed-controls": _reviewed_controls(data, config),
            "assessment-subjects": _assessment_subjects(data, config),
            "assessment-assets": _assessment_assets(data),
            "tasks": _tasks(data, config, has_compliance),
            "back-matter": _back_matter(
                nessus_path, ppsm_path, software_path, compliance_path
            ),
        }
    }


def write_sap(sap: dict, output_path: str) -> None:
    """
    Serialise a SAP dict to a JSON file.

    Args:
        sap:         Dict returned by :func:`build_sap`.
        output_path: Destination file path (created or overwritten).
    """
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(sap, fh, indent=2, ensure_ascii=False)


def sap_summary(sap: dict) -> dict:
    """
    Return a brief summary dict for logging/display.

    Args:
        sap: Dict returned by :func:`build_sap`.

    Returns:
        Dict with counts of reviewed controls, subjects, and tasks.
    """
    root = sap["assessment-plan"]
    rc = root.get("reviewed-controls", {})
    subj = root.get("assessment-subjects", [])
    tasks = root.get("tasks", [])

    # count controls in the first selection
    selections = rc.get("control-selections", [{}])
    control_count = len(selections[0].get("include-controls", []))

    # count subjects across all subject blocks
    subject_count = sum(
        len(s.get("include-subjects", []))
        for s in subj
    )

    return {
        "document_uuid":    root["uuid"],
        "oscal_version":    root["metadata"]["oscal-version"],
        "system_name":      root["metadata"]["title"],
        "reviewed_controls": control_count,
        "assessment_subjects": subject_count,
        "tasks":            len(tasks),
    }
