"""
OSCAL Plan of Action & Milestones (POA&M) document builder.

Produces a conformant OSCAL v1.2.1 POA&M JSON structure from a list of
:class:`~poam_generator.mapper.Finding` objects.

Document structure
------------------
One **observation** per (VulID × IP Address) finding  →  records the scan
evidence: what was found, on which host, on what date.

One **risk** per unique VulID  →  characterises the vulnerability class
(likelihood, impact, CVSS) and specifies the three standard CLaaS milestones
as remediation tasks.  The same risk is shared by all hosts where that
plugin fired, so risk-level data is not duplicated.

One **poam-item** per (VulID × IP Address) finding  →  links the observation
and the shared risk, carries the scheduled completion date, and is the
primary artefact reviewers and system owners act on.

References
----------
- OSCAL POA&M metaschema: OSCAL/src/metaschema/oscal_poam_metaschema.xml
- NIST SP 800-30 Rev 1 (risk characterisation vocabulary)
- OSCAL specification: https://pages.nist.gov/OSCAL
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from .mapper import Finding
from .uuid_utils import det_uuid, rand_uuid

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OSCAL_VERSION = "1.2.1"

# OSCAL namespace URIs used in characterisation facet 'system' attributes
_NS_OSCAL = "http://csrc.nist.gov/ns/oscal"
_NS_CVSS31 = "http://www.first.org/cvss/v3.1"
_NS_CVE = "http://cve.mitre.org"


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    """Current UTC time as RFC 3339 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rfc3339(d) -> Optional[str]:
    """Convert a date/datetime to RFC 3339 string, or None if *d* is None."""
    if d is None:
        return None
    from datetime import date as _date
    if isinstance(d, _date):
        return d.strftime("%Y-%m-%dT00:00:00Z")
    return str(d)


# ---------------------------------------------------------------------------
# Sub-builders
# ---------------------------------------------------------------------------

def _metadata(title: str, version: str, party_uuid: str, party_name: str) -> dict:
    return {
        "title": title,
        "last-modified": _now(),
        "version": version,
        "oscal-version": OSCAL_VERSION,
        "roles": [
            {"id": "prepared-by",  "title": "CLaaS Automated System"},
            {"id": "asset-owner",  "title": "System Owner"},
            {"id": "risk-assessor", "title": "Security Assessor"},
        ],
        "parties": [
            {
                "uuid": party_uuid,
                "type": "organization",
                "name": party_name,
            }
        ],
        "responsible-parties": [
            {
                "role-id": "prepared-by",
                "party-uuids": [party_uuid],
            }
        ],
    }


def _observation(f: Finding) -> dict:
    """Build one OSCAL observation for a single finding row."""
    props = [
        {"name": "plugin-id",        "value": f.vul_id,         "ns": _NS_OSCAL},
        {"name": "severity",         "value": f.severity_id,    "ns": _NS_OSCAL},
        {"name": "stig-severity",    "value": f.stig_severity,  "ns": _NS_OSCAL},
        {"name": "nist-control",     "value": f.control_temp,   "ns": _NS_OSCAL},
        {"name": "credentialed-scan","value": f.credentialed_scan, "ns": _NS_OSCAL},
    ]

    if f.cvss_score is not None:
        props.append({
            "name": "cvss-v3-base-score",
            "value": str(round(f.cvss_score, 1)),
            "ns": _NS_CVSS31,
        })

    if f.cve:
        props.append({"name": "cve-id", "value": f.cve, "ns": _NS_CVE})

    obs: dict = {
        "uuid": det_uuid(f"obs:{f.finding_key}"),
        "title": f"{f.plugin_name} \u2014 {f.ip_address}",
        "description": (
            f.synopsis
            or f"No synopsis available for plugin {f.vul_id} on {f.ip_address}."
        ),
        "props": props,
        "methods": ["TEST"],
        "types": ["discovery"],
        "subjects": [
            {
                "subject-uuid": det_uuid(f"host:{f.ip_address}"),
                "type": "component",
                "title": f.ip_address,
                "props": [
                    {"name": "host-ip",        "value": f.ip_address,       "ns": _NS_OSCAL},
                    {"name": "program-host-id", "value": f.program_host_id, "ns": _NS_OSCAL},
                    {"name": "mac-address",    "value": f.host_key_id,      "ns": _NS_OSCAL},
                ],
            }
        ],
        "collected": _rfc3339(f.scan_date) or _now(),
    }

    if f.source_file:
        obs["relevant-evidence"] = [
            {
                "href": f"#source-file",
                "description": f"Nessus scan file: {f.source_file}",
                "props": [
                    {"name": "source-file", "value": f.source_file, "ns": _NS_OSCAL}
                ],
            }
        ]

    return obs


def _risk(
    vul_id: str,
    plugin_name: str,
    synopsis: str,
    recommendation: str,
    severity_id: str,
    likelihood: str,
    impact: str,
    cvss_score: Optional[float],
    deadline,
) -> dict:
    """Build one OSCAL risk for a unique vulnerability (keyed by VulID)."""
    characterisation_facets = [
        {"name": "likelihood", "system": _NS_OSCAL, "value": likelihood},
        {"name": "impact",     "system": _NS_OSCAL, "value": impact},
    ]

    if cvss_score is not None:
        characterisation_facets.append({
            "name": "score",
            "system": _NS_CVSS31,
            "value": str(round(cvss_score, 1)),
        })

    # Three standard CLaaS remediation milestones (mirrors QVD Loader milestone text)
    tasks = [
        {
            "uuid": det_uuid(f"task:m1:{vul_id}"),
            "type": "milestone",
            "title": "Milestone 1: Test Environment Remediation",
            "description": (
                "Apply remediation step in test environment and "
                "validate closure of finding."
            ),
        },
        {
            "uuid": det_uuid(f"task:m2:{vul_id}"),
            "type": "milestone",
            "title": "Milestone 2: Functional Testing",
            "description": (
                "Functionally test system with remediation step included."
            ),
        },
        {
            "uuid": det_uuid(f"task:m3:{vul_id}"),
            "type": "milestone",
            "title": "Milestone 3: CCB Approval and Production Deployment",
            "description": (
                "Present solution to CCB for approval and deploy "
                "remediation step to production."
            ),
        },
    ]

    risk: dict = {
        "uuid": det_uuid(f"risk:{vul_id}"),
        "title": plugin_name,
        "description": synopsis or f"Vulnerability identified by scanner plugin {vul_id}.",
        "statement": (
            f"Plugin {vul_id} \u2014 Severity: {severity_id}. "
            + (synopsis[:500] if synopsis else "See finding details.")
        ),
        "status": "open",
        "characterizations": [{"facets": characterisation_facets}],
        "remediations": [
            {
                "uuid": det_uuid(f"remediation:{vul_id}"),
                "lifecycle": "planned",
                "title": f"Remediate: {plugin_name}",
                "description": recommendation or "Apply vendor-recommended remediation.",
                "tasks": tasks,
            }
        ],
        # related-observations is populated by build_poam() after all rows are processed
        "related-observations": [],
    }

    if deadline:
        risk["deadline"] = _rfc3339(deadline)

    return risk


def _poam_item(f: Finding, obs_uuid: str, risk_uuid: str) -> dict:
    """Build one OSCAL poam-item linking a specific observation and risk."""
    return {
        "uuid": det_uuid(f"poam:{f.finding_key}"),
        "title": f"{f.plugin_name} \u2014 {f.ip_address}",
        "description": (
            f"Open finding: {f.plugin_name} (Plugin {f.vul_id}) "
            f"on host {f.ip_address}. "
            f"Severity: {f.severity_id}. "
            f"NIST Control: {f.control_temp or 'TBD'}."
        ),
        "props": [
            {
                "name": "scheduled-completion-date",
                "value": _rfc3339(f.deadline) or "TBD",
                "ns": _NS_OSCAL,
            },
            {
                "name": "stig-severity",
                "value": f.stig_severity,
                "ns": _NS_OSCAL,
            },
            {
                "name": "plugin-correlation-key",
                "value": f.plugin_correlation_key,
                "ns": _NS_OSCAL,
            },
        ],
        "related-observations": [{"observation-uuid": obs_uuid}],
        "related-risks": [{"risk-uuid": risk_uuid}],
        "remarks": (
            f"Scan Date: {f.scan_date or 'Unknown'}. "
            f"Credentialed Scan: {f.credentialed_scan}. "
            f"CVE: {f.cve or 'N/A'}. "
            f"CVSS v3 Base Score: {f.cvss_score if f.cvss_score is not None else 'N/A'}."
        ),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_poam(
    findings: list[Finding],
    *,
    system_name: str = "CLaaS Target System",
    system_id: Optional[str] = None,
    party_name: str = "CLaaS Organization",
    version: str = "1.0",
) -> dict:
    """Build a complete OSCAL POA&M document from a list of Findings.

    Args:
        findings:    List of :class:`~poam_generator.mapper.Finding` objects.
                     Typically all open, non-Info findings from one QVD.
        system_name: Human-readable name of the assessed system.  Used in the
                     document title and to generate a deterministic system UUID
                     when *system_id* is not provided.
        system_id:   Explicit UUID for the assessed system.  Generated
                     deterministically from *system_name* when omitted.
        party_name:  Name of the responsible organisation (metadata party).
        version:     Document version string (default ``"1.0"``).

    Returns:
        A dict that serialises directly to a valid OSCAL POA&M JSON document.
    """
    if system_id is None:
        system_id = det_uuid(f"system:{system_name}")

    party_uuid = det_uuid(f"party:{party_name}")

    observations: list[dict] = []
    risks_by_vul: dict[str, dict] = {}   # vul_id → risk dict
    poam_items: list[dict] = []

    for f in findings:
        # --- Observation (one per host+finding) ---
        obs = _observation(f)
        observations.append(obs)

        # --- Risk (one per unique VulID, shared across hosts) ---
        if f.vul_id not in risks_by_vul:
            risks_by_vul[f.vul_id] = _risk(
                vul_id=f.vul_id,
                plugin_name=f.plugin_name,
                synopsis=f.synopsis,
                recommendation=f.recommendation,
                severity_id=f.severity_id,
                likelihood=f.oscal_likelihood,
                impact=f.oscal_impact,
                cvss_score=f.cvss_score,
                deadline=f.deadline,
            )

        # Link this observation to the shared risk
        risks_by_vul[f.vul_id]["related-observations"].append(
            {"observation-uuid": obs["uuid"]}
        )

        # --- POA&M item (one per host+finding) ---
        poam_items.append(
            _poam_item(f, obs["uuid"], risks_by_vul[f.vul_id]["uuid"])
        )

    return {
        "plan-of-action-and-milestones": {
            "uuid": rand_uuid(),
            "metadata": _metadata(
                title=f"POA&M \u2014 {system_name}",
                version=version,
                party_uuid=party_uuid,
                party_name=party_name,
            ),
            "system-id": {
                "identifier-type": "https://ietf.org/rfc/rfc4122",
                "id": system_id,
            },
            "observations": observations,
            "risks": list(risks_by_vul.values()),
            "poam-items": poam_items,
        }
    }


def write_poam(poam: dict, output_path: str) -> None:
    """Serialise a POA&M dict to a JSON file.

    Args:
        poam:        Dict returned by :func:`build_poam`.
        output_path: Destination file path (created or overwritten).
    """
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(poam, fh, indent=2, ensure_ascii=False)


def poam_summary(poam: dict) -> dict:
    """Return a brief summary dict for logging/display purposes.

    Args:
        poam: Dict returned by :func:`build_poam`.

    Returns:
        Dict with counts of observations, risks, and poam-items.
    """
    root = poam["plan-of-action-and-milestones"]
    return {
        "document_uuid": root["uuid"],
        "oscal_version": root["metadata"]["oscal-version"],
        "observations": len(root.get("observations", [])),
        "risks": len(root.get("risks", [])),
        "poam_items": len(root.get("poam-items", [])),
    }
