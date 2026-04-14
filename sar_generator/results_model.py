"""
Data model for the CLaaS SAR generator.

Classes
-------
SARConfig
    User-supplied assessment metadata.  Everything that cannot be derived
    from QVD data lives here.

ControlEvidence
    Aggregated scan evidence for a single NIST 800-53 control across all
    hosts and compliance results.  Used by the SAR builder to compute
    the finding-target satisfaction state.

SARData
    Wraps AssessmentData and pre-computes per-control evidence, compliance
    control mappings, and the date range for the result block.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from sap_generator.assessment_model import AssessmentData
from ssp_generator.system_model import ComplianceResult, HostRecord


# ---------------------------------------------------------------------------
# Compliance reference field parser
# ---------------------------------------------------------------------------

# Nessus Policy Compliance Reference field examples:
#   "800-53|AC-2\nCCI-000016"
#   "NIST-800-53|SI-2\nCCI-002605"
#   "800-53|AC-2(1)\nCCI-000015"
_REF_CONTROL_RE = re.compile(
    r"800-53\|([A-Z]{2,3}-\d+(?:\(\d+\))?)",
    re.IGNORECASE,
)


def parse_controls_from_reference(reference: str) -> list[str]:
    """
    Extract normalised NIST 800-53 control IDs from a Nessus compliance
    Reference field value.

    Args:
        reference: Raw string from the Compliance QVD 'Reference' column.

    Returns:
        List of lowercase control IDs, e.g. ["ac-2", "ac-2(1)"].
        Empty list if no control IDs are found.
    """
    return [m.group(1).lower() for m in _REF_CONTROL_RE.finditer(reference)]


# ---------------------------------------------------------------------------
# Per-control evidence container
# ---------------------------------------------------------------------------

@dataclass
class ControlEvidence:
    """
    Aggregated evidence for one NIST 800-53 control.

    Attributes:
        control_id:           Normalised lowercase control ID.
        open_vuln_obs_uuids:  Observation UUIDs for open vulnerability findings.
        closed_vuln_obs_uuids: Observation UUIDs for closed vulnerability findings.
        risk_uuids:           Risk UUIDs for all VulIDs mapped to this control.
        failed_compliance:    ComplianceResult objects with result != 'PASSED'.
        passed_compliance:    ComplianceResult objects with result == 'PASSED'.
        max_open_severity:    Highest open finding severity (Very High > High > ...).
    """
    control_id: str
    open_vuln_obs_uuids: list[str] = field(default_factory=list)
    closed_vuln_obs_uuids: list[str] = field(default_factory=list)
    risk_uuids: list[str] = field(default_factory=list)
    failed_compliance: list[ComplianceResult] = field(default_factory=list)
    passed_compliance: list[ComplianceResult] = field(default_factory=list)
    max_open_severity: str = ""

    @property
    def all_obs_uuids(self) -> list[str]:
        return self.open_vuln_obs_uuids + self.closed_vuln_obs_uuids

    @property
    def has_open_critical(self) -> bool:
        return self.max_open_severity.lower() in ("very high", "high")

    @property
    def has_open_findings(self) -> bool:
        return bool(self.open_vuln_obs_uuids)

    @property
    def has_failed_compliance(self) -> bool:
        return bool(self.failed_compliance)

    def target_state(self) -> str:
        """OSCAL finding-target status state: 'satisfied' | 'not-satisfied'."""
        if self.has_open_findings or self.has_failed_compliance:
            return "not-satisfied"
        return "satisfied"

    def target_reason(self) -> str:
        """OSCAL finding-target status reason: 'pass' | 'fail' | 'other'."""
        if self.has_open_critical or self.has_failed_compliance:
            return "fail"
        if self.has_open_findings:
            return "other"   # open Low/Medium only — partial
        return "pass"


# ---------------------------------------------------------------------------
# User-supplied SAR configuration
# ---------------------------------------------------------------------------

@dataclass
class SARConfig:
    """
    All assessment metadata that cannot be derived from scan data.
    """
    # --- Identity ---
    system_name: str = "CLaaS Target System"
    system_name_short: str = ""
    org_name: str = "CLaaS Organization"
    assessor_name: str = "REQUIRED — Assessment Organization"
    version: str = "1.0"

    # --- SAP reference (REQUIRED) ---
    sap_href: str = (
        "REQUIRED — Provide path/URI to the SAP document, "
        "e.g. '../sap/sap.json'"
    )

    # --- Assessment date range ---
    # When None, derived from the earliest/latest scan dates in the QVD data.
    start_date: Optional[str] = None   # "YYYY-MM-DD"
    end_date: Optional[str] = None     # "YYYY-MM-DD"

    # --- Result title / description ---
    result_title: str = "CLaaS Automated Assessment Results"
    result_description: str = (
        "Assessment results generated by the CLaaS automated vulnerability "
        "and compliance scan pipeline.  Observations, risks, and findings "
        "are derived from Nessus QVD scan data ingested by the CLaaS QVD "
        "Generator App."
    )

    # --- Baseline profile (must match SSP and SAP) ---
    baseline_profile_href: str = (
        "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
        "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_HIGH-baseline_profile.json"
    )

    # --- Roles ---
    roles: list[dict] = field(
        default_factory=lambda: [
            {"id": "prepared-by",         "title": "SAR Preparer"},
            {"id": "assessor",            "title": "Security Assessor"},
            {"id": "assessment-lead",     "title": "Assessment Lead"},
            {"id": "system-owner",        "title": "System Owner"},
            {"id": "authorizing-official","title": "Authorizing Official"},
        ]
    )


# ---------------------------------------------------------------------------
# SAR-specific aggregate data
# ---------------------------------------------------------------------------

# Severity rank for ordering and comparison
_SEV_RANK = {"very high": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class SARData:
    """
    Wraps AssessmentData and pre-computes per-control evidence containers,
    compliance control mappings, and result date range.

    Attributes:
        assessment_data:   Source data loaded from QVD files.
        control_evidence:  Mapping of control_id → ControlEvidence.
        result_start:      ISO date string of earliest scan date (or None).
        result_end:        ISO date string of latest scan date (or None).
    """
    assessment_data: AssessmentData
    control_evidence: dict[str, ControlEvidence] = field(default_factory=dict)
    result_start: Optional[str] = None
    result_end: Optional[str] = None

    @classmethod
    def from_assessment_data(
        cls,
        data: AssessmentData,
        config: SARConfig,
    ) -> "SARData":
        """
        Build a SARData from AssessmentData by computing per-control evidence.

        The observation UUID scheme mirrors that used in poam_generator so
        that UUIDs are consistent across SAR and POA&M documents.
        """
        from poam_generator.uuid_utils import det_uuid

        evidence: dict[str, ControlEvidence] = {}

        # --- Vulnerability finding evidence ---
        for host in data.system_data.hosts:
            for control_id, severities in host.open_controls.items():
                ev = evidence.setdefault(control_id, ControlEvidence(control_id))
                for sev in severities:
                    # Observation UUID matches poam_generator scheme: obs:<ip>:<vulid>
                    # We approximate with a control-level observation UUID here;
                    # the fine-grained per-finding obs UUID is built in oscal_sar.py
                    # but we record the risk UUID (per VulID) immediately.
                    obs_uuid = det_uuid(f"obs:{host.ip_address}:{control_id}")
                    if obs_uuid not in ev.open_vuln_obs_uuids:
                        ev.open_vuln_obs_uuids.append(obs_uuid)
                    # Track highest severity
                    rank = _SEV_RANK.get(sev.lower(), 0)
                    curr_rank = _SEV_RANK.get(ev.max_open_severity.lower(), -1)
                    if rank > curr_rank:
                        ev.max_open_severity = sev

            for control_id, _ in host.closed_controls.items():
                ev = evidence.setdefault(control_id, ControlEvidence(control_id))
                obs_uuid = det_uuid(f"obs-closed:{host.ip_address}:{control_id}")
                if obs_uuid not in ev.closed_vuln_obs_uuids:
                    ev.closed_vuln_obs_uuids.append(obs_uuid)

        # --- Compliance evidence ---
        for cr in data.system_data.compliance:
            control_ids = parse_controls_from_reference(cr.reference)
            for cid in control_ids:
                ev = evidence.setdefault(cid, ControlEvidence(cid))
                if cr.result.upper() == "PASSED":
                    ev.passed_compliance.append(cr)
                else:
                    ev.failed_compliance.append(cr)

        # --- Date range ---
        dates = data.unique_scan_dates
        start = config.start_date or (dates[0] if dates else None)
        end = config.end_date or (dates[-1] if dates else None)

        return cls(
            assessment_data=data,
            control_evidence=evidence,
            result_start=start,
            result_end=end,
        )
