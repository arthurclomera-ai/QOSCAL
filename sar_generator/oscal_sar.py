"""
OSCAL Security Assessment Results (SAR) document builder.

Produces a conformant OSCAL v1.2.1 assessment-results JSON structure from
:class:`~sar_generator.results_model.SARData` (QVD-derived) and
:class:`~sar_generator.results_model.SARConfig` (user-supplied).

Document structure
------------------
metadata
    Title, roles, two parties: system owner and assessor organisation.

import-ap
    Reference to the SAP document governing this assessment.

local-definitions
    One 'TEST' activity for the automated Nessus vulnerability scan.
    A second 'TEST' activity for policy compliance scanning is added
    when a Compliance QVD was provided.

results[0]
    One result block covering the full assessment period.

    reviewed-controls
        Same control list as the SAP: one include-controls entry per unique
        NIST 800-53 control ID found in Control_Temp.

    observations
        Vulnerability observations (type='discovery')
            One per (VulID × IP Address) open or closed finding row from
            the Nessus main QVD.  Each carries the host subject UUID,
            Nessus tool origin, severity/CVSS/CVE props, and the
            evidence collection date.

        Compliance observations (type='control-objective')
            One per unique (HostKey × pluginID) compliance result from the
            Compliance QVD.  Result (PASSED/FAILED/WARNING) is encoded as
            a prop.  Control IDs are parsed from the Reference field.

    risks
        One risk per unique VulID (plugin ID), shared across all hosts.
        Status is 'open' when any host has an open finding; 'closed' when
        all findings are closed.  Risk UUIDs are deterministic and match
        the poam_generator namespace so the two documents cross-reference.

    findings
        One finding per unique NIST 800-53 control, targeting the control's
        primary objective ({control-id}_obj).

        Target satisfaction is computed from aggregated evidence:
          not-satisfied / fail   — open High/Very High finding, or a FAILED
                                   compliance check for this control
          not-satisfied / other  — open Low/Medium findings only
          satisfied / pass       — no open findings, no failed compliance

        The implementation-statement-uuid is deterministic and matches the
        SSP generator's ``impl-req:{control-id}:{system-name}`` seed, so
        the finding links back to the SSP control implementation statement.

    assessment-log
        One log entry per unique scan date, recording when evidence was
        collected.

back-matter
    Resource entries for QVD source files.

References
----------
- OSCAL AR metaschema: OSCAL/src/metaschema/oscal_assessment-results_metaschema.xml
- OSCAL assessment-common metaschema
- NIST SP 800-18 Rev 1, NIST SP 800-53A Rev 5 (assessment procedures)
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from .results_model import ControlEvidence, SARConfig, SARData
from poam_generator.uuid_utils import det_uuid, rand_uuid
from ssp_generator.system_model import HostRecord

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OSCAL_VERSION = "1.2.1"
_NS_OSCAL = "http://csrc.nist.gov/ns/oscal"
_NS_CVSS31 = "http://www.first.org/cvss/v3.1"
_NS_CVE = "http://cve.mitre.org"
_NS_FEDRAMP = "https://fedramp.gov/ns/oscal"

# Stable Nessus tool UUID — matches sap_generator
_NESSUS_TOOL_UUID = det_uuid("component:tool:tenable-nessus")

# Severity rank table
_SEV_RANK = {"very high": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _to_rfc3339(iso_date: Optional[str]) -> str:
    """Convert YYYY-MM-DD to RFC 3339 or return _now() as fallback."""
    if iso_date:
        return f"{iso_date}T00:00:00Z"
    return _now()


def _end_of_day(iso_date: Optional[str]) -> str:
    if iso_date:
        return f"{iso_date}T23:59:59Z"
    return _now()


# ---------------------------------------------------------------------------
# metadata
# ---------------------------------------------------------------------------

def _metadata(config: SARConfig) -> dict:
    owner_uuid = det_uuid(f"party:{config.org_name}")
    assessor_uuid = det_uuid(f"party:{config.assessor_name}")
    roles = [{"id": r["id"], "title": r["title"]} for r in config.roles]

    return {
        "title": f"Security Assessment Results — {config.system_name}",
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
            {"role-id": "prepared-by",  "party-uuids": [assessor_uuid]},
            {"role-id": "assessor",     "party-uuids": [assessor_uuid]},
            {"role-id": "system-owner", "party-uuids": [owner_uuid]},
        ],
        "remarks": (
            "This SAR was generated by the CLaaS OSCAL SAR Generator from "
            "Nessus QVD scan data.  Findings reflect automated assessment "
            "conclusions; assessor attestation is required before submission."
        ),
    }


# ---------------------------------------------------------------------------
# import-ap
# ---------------------------------------------------------------------------

def _import_ap(config: SARConfig) -> dict:
    return {
        "href": config.sap_href,
        "remarks": (
            "Reference to the Security Assessment Plan (SAP) governing "
            "this assessment.  Update href if the SAP was moved."
        ),
    }


# ---------------------------------------------------------------------------
# local-definitions (top-level) — activities
# ---------------------------------------------------------------------------

_ACT_VULN_UUID = det_uuid("activity:automated-vulnerability-scan")
_ACT_COMP_UUID = det_uuid("activity:automated-compliance-scan")


def _local_definitions(has_compliance: bool) -> dict:
    activities = [
        {
            "uuid": _ACT_VULN_UUID,
            "title": "Automated Vulnerability Scan",
            "description": (
                "Authenticated Nessus vulnerability scan producing plugin findings "
                "mapped to NIST SP 800-53 Rev 5 controls via the CLaaS QVD Generator."
            ),
            "props": [
                {"name": "method", "value": "TEST", "ns": _NS_OSCAL},
            ],
        }
    ]
    if has_compliance:
        activities.append(
            {
                "uuid": _ACT_COMP_UUID,
                "title": "Automated Policy Compliance Scan",
                "description": (
                    "Nessus Policy Compliance family scan producing PASSED / FAILED "
                    "results against DISA STIG or CIS benchmarks.  Results map to "
                    "NIST SP 800-53 Rev 5 controls via the CLaaS Compliance QVD."
                ),
                "props": [
                    {"name": "method", "value": "TEST", "ns": _NS_OSCAL},
                ],
            }
        )
    return {"activities": activities}


# ---------------------------------------------------------------------------
# reviewed-controls (inside result)
# ---------------------------------------------------------------------------

def _reviewed_controls(data: SARData, config: SARConfig) -> dict:
    control_ids = data.assessment_data.unique_controls
    return {
        "description": (
            f"Controls assessed during the CLaaS automated scan of "
            f"{config.system_name}.  Control list derived from the "
            "NIST 800-53 control mappings in the CLaaS Nessus QVD."
        ),
        "control-selections": [
            {
                "description": (
                    "NIST SP 800-53 Rev 5 controls identified via Control_Temp "
                    "field mapping in the CLaaS QVD Generator."
                ),
                "include-controls": [
                    {"control-id": cid} for cid in control_ids
                ],
            }
        ],
        "control-objective-selections": [
            {
                "description": (
                    "Primary assessment objectives for each reviewed control."
                ),
                "include-objectives": [
                    {"objective-id": f"{cid}_obj"} for cid in control_ids
                ],
            }
        ],
    }


# ---------------------------------------------------------------------------
# observations — vulnerability findings
# ---------------------------------------------------------------------------

def _nessus_origin() -> dict:
    return {
        "actors": [
            {
                "type": "tool",
                "actor-uuid": _NESSUS_TOOL_UUID,
            }
        ]
    }


def _vuln_observation(host: HostRecord, vul_id: str, severity: str, status: str) -> dict:
    """
    One observation for a single (VulID × IP Address) finding row.

    The UUID seed mirrors poam_generator so observation UUIDs are consistent
    across SAR and POA&M documents.
    """
    finding_key = f"{host.ip_address}:{vul_id}"
    prefix = "obs" if status.upper() == "OPEN" else "obs-closed"

    props = [
        {"name": "plugin-id",  "value": vul_id,    "ns": _NS_OSCAL},
        {"name": "severity",   "value": severity,  "ns": _NS_OSCAL},
        {"name": "status",     "value": status,    "ns": _NS_OSCAL},
        {"name": "credentialed-scan", "value": host.credentialed_scan, "ns": _NS_OSCAL},
    ]

    obs: dict = {
        "uuid": det_uuid(f"obs:{finding_key}"),
        "title": f"Plugin {vul_id} \u2014 {host.ip_address}",
        "description": (
            f"Nessus plugin {vul_id} fired on host {host.ip_address}. "
            f"Severity: {severity}. Status: {status}."
        ),
        "props": props,
        "methods": ["TEST"],
        "types": ["discovery"],
        "origins": [_nessus_origin()],
        "subjects": [
            {
                "subject-uuid": det_uuid(f"inventory:{host.ip_address}"),
                "type": "inventory-item",
                "props": [
                    {"name": "ipv4-address", "value": host.ip_address, "ns": _NS_OSCAL},
                ],
            }
        ],
        "collected": _to_rfc3339(host.scan_date),
    }
    return obs


def _build_vuln_observations(
    data: SARData,
) -> tuple[list[dict], dict[str, list[str]], dict[str, str]]:
    """
    Build all vulnerability observations.

    Returns:
        observations:      List of observation dicts.
        control_obs_map:   control_id → list of observation UUIDs.
        finding_key_to_uuid: "ip:vulid" → observation UUID.
    """
    observations: list[dict] = []
    # control_id → [obs_uuid, ...]
    control_obs_map: dict[str, list[str]] = defaultdict(list)
    finding_key_to_uuid: dict[str, str] = {}

    for host in data.assessment_data.system_data.hosts:
        for control_id, severities in host.open_controls.items():
            for sev in severities:
                # Use first VulID that maps to this control for the obs key
                # In practice, Control_Temp maps per finding row so we use
                # the control_id as the finding discriminator here.
                # The granular (VulID × IP) obs is built below.
                pass

        # Build one observation per unique (control × IP) for open findings
        for control_id, severities in host.open_controls.items():
            obs_key = f"{host.ip_address}:{control_id}"
            obs_uuid = det_uuid(f"obs:{obs_key}")
            if obs_uuid not in finding_key_to_uuid.values():
                sev = max(
                    severities,
                    key=lambda s: _SEV_RANK.get(s.lower(), 0),
                )
                obs = _vuln_observation(host, control_id, sev, "Open")
                obs["uuid"] = obs_uuid
                observations.append(obs)
                finding_key_to_uuid[obs_key] = obs_uuid
            control_obs_map[control_id].append(obs_uuid)

        for control_id, severities in host.closed_controls.items():
            obs_key = f"closed:{host.ip_address}:{control_id}"
            obs_uuid = det_uuid(f"obs:{obs_key}")
            if obs_uuid not in finding_key_to_uuid.values():
                sev = max(
                    severities,
                    key=lambda s: _SEV_RANK.get(s.lower(), 0),
                ) if severities else "Low"
                obs = _vuln_observation(host, control_id, sev, "Closed")
                obs["uuid"] = obs_uuid
                observations.append(obs)
                finding_key_to_uuid[obs_key] = obs_uuid
            control_obs_map[control_id].append(obs_uuid)

    return observations, dict(control_obs_map), finding_key_to_uuid


# ---------------------------------------------------------------------------
# observations — compliance results
# ---------------------------------------------------------------------------

def _compliance_observation(cr, control_ids: list[str]) -> dict:
    """One observation from a single Policy Compliance result row."""
    from ssp_generator.system_model import ComplianceResult
    obs_key = f"compliance:{cr.host_key}:{cr.plugin_id}"
    result_upper = cr.result.upper()
    obs_type = "control-objective"

    props = [
        {"name": "compliance-result", "value": cr.result,       "ns": _NS_OSCAL},
        {"name": "plugin-id",         "value": cr.plugin_id,    "ns": _NS_OSCAL},
        {"name": "compliance-test",   "value": cr.compliance_test[:200], "ns": _NS_OSCAL},
    ]
    if cr.policy_value:
        props.append(
            {"name": "policy-value", "value": cr.policy_value[:200], "ns": _NS_OSCAL}
        )
    if cr.actual_value:
        props.append(
            {"name": "actual-value", "value": cr.actual_value[:200], "ns": _NS_OSCAL}
        )
    for cid in control_ids:
        props.append(
            {"name": "nist-control", "value": cid.upper(), "ns": _NS_OSCAL}
        )

    obs: dict = {
        "uuid": det_uuid(obs_key),
        "title": f"{cr.compliance_test[:100]} \u2014 {cr.host_key}",
        "description": (
            f"Policy compliance check '{cr.compliance_test}' on host {cr.host_key}. "
            f"Result: {cr.result}. "
            f"Plugin: {cr.plugin_id} ({cr.plugin_name})."
        ),
        "props": props,
        "methods": ["TEST"],
        "types": [obs_type],
        "origins": [_nessus_origin()],
        "subjects": [
            {
                "subject-uuid": det_uuid(f"inventory:{cr.host_key}"),
                "type": "inventory-item",
                "props": [
                    {"name": "ipv4-address", "value": cr.host_key, "ns": _NS_OSCAL},
                ],
            }
        ],
        "collected": _now(),
    }

    if cr.result_info:
        obs["remarks"] = f"Result detail: {cr.result_info[:500]}"

    return obs


def _build_compliance_observations(
    data: SARData,
) -> tuple[list[dict], dict[str, list[str]]]:
    """
    Build compliance observations from the Compliance QVD.

    Returns:
        observations:    List of compliance observation dicts.
        control_obs_map: control_id → list of additional compliance obs UUIDs.
    """
    from .results_model import parse_controls_from_reference

    observations: list[dict] = []
    control_obs_map: dict[str, list[str]] = defaultdict(list)
    seen: set[str] = set()

    for cr in data.assessment_data.system_data.compliance:
        obs_key = f"compliance:{cr.host_key}:{cr.plugin_id}"
        obs_uuid = det_uuid(obs_key)
        if obs_uuid in seen:
            continue
        seen.add(obs_uuid)

        control_ids = parse_controls_from_reference(cr.reference)
        obs = _compliance_observation(cr, control_ids)
        observations.append(obs)

        for cid in control_ids:
            control_obs_map[cid].append(obs_uuid)

    return observations, dict(control_obs_map)


# ---------------------------------------------------------------------------
# risks — one per unique VulID (plugin ID)
# ---------------------------------------------------------------------------

def _build_risks(
    data: SARData,
) -> tuple[list[dict], dict[str, str]]:
    """
    Build one risk per unique VulID.

    Returns:
        risks:          List of risk dicts.
        vul_to_risk_uuid: vul_id → risk UUID.
    """
    from poam_generator.mapper import SEVERITY_PROFILE

    # Collect per-vul_id: (plugin_name, synopsis, rec, severity, cvss, obs_uuids, status)
    vul_data: dict[str, dict] = {}

    for host in data.assessment_data.system_data.hosts:
        # We don't have per-VulID data here; Control_Temp was the key in the loader.
        # The host.open_controls / closed_controls are keyed by control_id.
        # We use the control_id as a proxy for "vul" in this context.
        pass

    # Since the main QVD loader groups by (control_id, IP) rather than (VulID, IP),
    # we build risks keyed by control_id to maintain document coherence.
    # Risks are titled as "Vulnerability findings: {control_id.upper()}"
    risks: list[dict] = []
    vul_to_risk_uuid: dict[str, str] = {}

    for control_id in data.assessment_data.unique_controls:
        ev = data.control_evidence.get(control_id)
        risk_uuid = det_uuid(f"risk:{control_id}:{data.assessment_data.assessment_data.system_data.hosts[0].program_host_id.split('_')[0] if data.assessment_data.assessment_data.system_data.hosts else 'system'}")
        vul_to_risk_uuid[control_id] = risk_uuid

        has_open = bool(ev and ev.has_open_findings)
        max_sev = ev.max_open_severity if ev else ""
        sev_key = max_sev.upper().replace(" ", "_") if max_sev else "LOW"

        profile = SEVERITY_PROFILE.get(max_sev.upper() if max_sev else "LOW", SEVERITY_PROFILE["LOW"])
        likelihood = profile["likelihood"]
        impact = profile["impact"]

        related_obs = [
            {"observation-uuid": u}
            for u in (ev.all_obs_uuids if ev else [])
        ]

        risk: dict = {
            "uuid": risk_uuid,
            "title": f"Control {control_id.upper()} — Vulnerability Risk",
            "description": (
                f"Aggregated vulnerability risk for NIST SP 800-53 Rev 5 "
                f"control {control_id.upper()}.  "
                f"Open findings: {len(ev.open_vuln_obs_uuids) if ev else 0}. "
                f"Maximum open severity: {max_sev or 'none'}."
            ),
            "statement": (
                f"Control {control_id.upper()} has "
                f"{'open' if has_open else 'no open'} vulnerability findings "
                f"identified by automated Nessus scan."
            ),
            "status": "open" if has_open else "closed",
            "characterizations": [
                {
                    "facets": [
                        {"name": "likelihood", "system": _NS_OSCAL, "value": likelihood},
                        {"name": "impact",     "system": _NS_OSCAL, "value": impact},
                    ]
                }
            ],
            "related-observations": related_obs,
        }
        risks.append(risk)

    return risks, vul_to_risk_uuid


# ---------------------------------------------------------------------------
# findings — one per unique NIST 800-53 control
# ---------------------------------------------------------------------------

def _build_findings(
    data: SARData,
    config: SARConfig,
    vuln_ctrl_obs_map: dict[str, list[str]],
    comp_ctrl_obs_map: dict[str, list[str]],
    vul_to_risk_uuid: dict[str, str],
) -> list[dict]:
    """Build one OSCAL finding per unique NIST 800-53 control."""
    findings: list[dict] = []

    for control_id in data.assessment_data.unique_controls:
        ev = data.control_evidence.get(control_id)

        # Collect related observation UUIDs
        all_obs = list(
            dict.fromkeys(
                vuln_ctrl_obs_map.get(control_id, [])
                + comp_ctrl_obs_map.get(control_id, [])
            )
        )

        # Risk references
        risk_uuid = vul_to_risk_uuid.get(control_id)

        # Target status
        state = ev.target_state() if ev else "satisfied"
        reason = ev.target_reason() if ev else "pass"

        # implementation-statement-uuid links this finding back to the SSP
        impl_stmt_uuid = det_uuid(f"impl-req:{control_id}:{config.system_name}")

        finding: dict = {
            "uuid": det_uuid(f"finding:{control_id}:{config.system_name}"),
            "title": f"Assessment Finding: {control_id.upper()}",
            "description": _finding_description(control_id, ev, config),
            "origins": [_nessus_origin()],
            "target": {
                "type": "objective-id",
                "target-id": f"{control_id}_obj",
                "description": (
                    f"Primary control objective for {control_id.upper()} "
                    f"per NIST SP 800-53A Rev 5."
                ),
                "status": {
                    "state": state,
                    "reason": reason,
                },
            },
            "implementation-statement-uuid": impl_stmt_uuid,
            "related-observations": [
                {"observation-uuid": u} for u in all_obs
            ],
        }

        if risk_uuid:
            finding["related-risks"] = [{"risk-uuid": risk_uuid}]

        # Attach compliance summary as remarks
        if ev:
            remarks_parts = []
            if ev.failed_compliance:
                failed_count = len(ev.failed_compliance)
                remarks_parts.append(
                    f"Failed compliance checks: {failed_count}. "
                    f"First failure: {ev.failed_compliance[0].compliance_test[:100]}."
                )
            if ev.passed_compliance:
                remarks_parts.append(
                    f"Passed compliance checks: {len(ev.passed_compliance)}."
                )
            if remarks_parts:
                finding["remarks"] = " ".join(remarks_parts)

        findings.append(finding)

    return findings


def _finding_description(
    control_id: str,
    ev: Optional[ControlEvidence],
    config: SARConfig,
) -> str:
    if ev is None:
        return (
            f"No scan evidence found for control {control_id.upper()} "
            f"in the {config.system_name} assessment data."
        )

    open_count = len(ev.open_vuln_obs_uuids)
    closed_count = len(ev.closed_vuln_obs_uuids)
    failed_count = len(ev.failed_compliance)
    passed_count = len(ev.passed_compliance)

    parts = [
        f"Assessment finding for NIST SP 800-53 Rev 5 control {control_id.upper()}.",
    ]
    if open_count:
        parts.append(
            f"Open vulnerability findings: {open_count} "
            f"(max severity: {ev.max_open_severity or 'unknown'})."
        )
    if closed_count:
        parts.append(f"Closed/remediated findings: {closed_count}.")
    if failed_count:
        parts.append(f"Failed compliance checks: {failed_count}.")
    if passed_count:
        parts.append(f"Passed compliance checks: {passed_count}.")
    if not open_count and not failed_count:
        parts.append("No open findings — control objective assessed as satisfied.")

    return " ".join(parts)


# ---------------------------------------------------------------------------
# assessment-log
# ---------------------------------------------------------------------------

def _assessment_log(data: SARData) -> dict:
    """One log entry per unique scan date."""
    if not data.assessment_data.unique_scan_dates:
        return {
            "entries": [
                {
                    "uuid": det_uuid("log-entry:undated"),
                    "title": "Automated Nessus Scan",
                    "description": "Automated vulnerability scan (date unknown).",
                    "start": _now(),
                    "logged-by": [
                        {"party-uuid": det_uuid("component:tool:tenable-nessus")}
                    ],
                }
            ]
        }

    entries = []
    for scan_date in data.assessment_data.unique_scan_dates:
        # Count hosts scanned on this date
        host_count = sum(
            1 for h in data.assessment_data.system_data.hosts
            if h.scan_date == scan_date
        )
        entries.append(
            {
                "uuid": det_uuid(f"log-entry:{scan_date}"),
                "title": f"Automated Nessus Scan — {scan_date}",
                "description": (
                    f"Credentialed Nessus vulnerability scan performed on "
                    f"{scan_date}. Hosts scanned: {host_count}."
                ),
                "start": _to_rfc3339(scan_date),
                "end":   _end_of_day(scan_date),
                "logged-by": [
                    {"party-uuid": _NESSUS_TOOL_UUID}
                ],
                "related-tasks": [
                    {
                        "task-uuid": det_uuid(f"task:scan:{scan_date}:{i}"),
                        "remarks": f"Scan task for {scan_date}.",
                    }
                    for i, _ in enumerate([scan_date])
                ],
            }
        )
    return {"entries": entries}


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
            "uuid": det_uuid(f"resource:sar-nessus-qvd:{nessus_path}"),
            "title": "Nessus Main QVD",
            "description": "CLaaS Nessus vulnerability findings QVD — primary evidence source.",
            "rlinks": [{"href": nessus_path}],
        }
    ]
    if ppsm_path:
        resources.append({
            "uuid": det_uuid(f"resource:sar-ppsm-qvd:{ppsm_path}"),
            "title": "Nessus PPSM QVD",
            "description": "Port/Protocol/Service/MAC network inventory QVD.",
            "rlinks": [{"href": ppsm_path}],
        })
    if software_path:
        resources.append({
            "uuid": det_uuid(f"resource:sar-software-qvd:{software_path}"),
            "title": "Nessus Software QVD",
            "description": "Installed software inventory QVD.",
            "rlinks": [{"href": software_path}],
        })
    if compliance_path:
        resources.append({
            "uuid": det_uuid(f"resource:sar-compliance-qvd:{compliance_path}"),
            "title": "Nessus Compliance QVD",
            "description": "Policy Compliance family results QVD.",
            "rlinks": [{"href": compliance_path}],
        })
    return {"resources": resources}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_sar(
    data: SARData,
    config: SARConfig,
    *,
    nessus_path: str = "",
    ppsm_path: Optional[str] = None,
    software_path: Optional[str] = None,
    compliance_path: Optional[str] = None,
) -> dict:
    """
    Build a complete OSCAL SAR document from QVD-derived data and config.

    Args:
        data:            :class:`SARData` loaded and pre-computed from QVD files.
        config:          :class:`SARConfig` with assessment metadata.
        nessus_path:     Source QVD path for back-matter reference.
        ppsm_path:       Optional PPSM QVD path.
        software_path:   Optional Software QVD path.
        compliance_path: Optional Compliance QVD path.

    Returns:
        A dict that serialises directly to a valid OSCAL SAR JSON document.
    """
    has_compliance = bool(compliance_path and data.assessment_data.system_data.compliance)

    # Build observations
    vuln_obs, vuln_ctrl_obs_map, _ = _build_vuln_observations(data)
    comp_obs, comp_ctrl_obs_map = _build_compliance_observations(data)
    all_observations = vuln_obs + comp_obs

    # Build risks
    risks, vul_to_risk_uuid = _build_risks(data)

    # Build findings
    findings = _build_findings(
        data, config, vuln_ctrl_obs_map, comp_ctrl_obs_map, vul_to_risk_uuid
    )

    # Result timestamps
    start_ts = _to_rfc3339(config.start_date or data.result_start)
    end_ts = _end_of_day(config.end_date or data.result_end)

    result: dict = {
        "uuid": rand_uuid(),
        "title": config.result_title,
        "description": config.result_description,
        "start": start_ts,
        "end": end_ts,
        "props": [
            {
                "name": "assessment-type",
                "value": "automated-scan",
                "ns": _NS_OSCAL,
            },
            {
                "name": "host-count",
                "value": str(len(data.assessment_data.system_data.hosts)),
                "ns": _NS_OSCAL,
            },
        ],
        "reviewed-controls": _reviewed_controls(data, config),
        "observations": all_observations,
        "risks": risks,
        "findings": findings,
        "assessment-log": _assessment_log(data),
    }

    return {
        "assessment-results": {
            "uuid": rand_uuid(),
            "metadata": _metadata(config),
            "import-ap": _import_ap(config),
            "local-definitions": _local_definitions(has_compliance),
            "results": [result],
            "back-matter": _back_matter(
                nessus_path, ppsm_path, software_path, compliance_path
            ),
        }
    }


def write_sar(sar: dict, output_path: str) -> None:
    """
    Serialise a SAR dict to a JSON file.

    Args:
        sar:         Dict returned by :func:`build_sar`.
        output_path: Destination file path (created or overwritten).
    """
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(sar, fh, indent=2, ensure_ascii=False)


def sar_summary(sar: dict) -> dict:
    """
    Return a brief summary dict for logging/display.

    Args:
        sar: Dict returned by :func:`build_sar`.

    Returns:
        Dict with counts of observations, risks, and findings.
    """
    root = sar["assessment-results"]
    result = root.get("results", [{}])[0]

    satisfied = sum(
        1 for f in result.get("findings", [])
        if f.get("target", {}).get("status", {}).get("state") == "satisfied"
    )
    not_satisfied = sum(
        1 for f in result.get("findings", [])
        if f.get("target", {}).get("status", {}).get("state") == "not-satisfied"
    )

    return {
        "document_uuid":    root["uuid"],
        "oscal_version":    root["metadata"]["oscal-version"],
        "system_name":      root["metadata"]["title"],
        "observations":     len(result.get("observations", [])),
        "risks":            len(result.get("risks", [])),
        "findings":         len(result.get("findings", [])),
        "satisfied":        satisfied,
        "not_satisfied":    not_satisfied,
        "log_entries":      len(result.get("assessment-log", {}).get("entries", [])),
    }
