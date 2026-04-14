"""
Data model for the CLaaS SAP generator.

Classes
-------
AssessmentConfig
    User-supplied assessment metadata (CLI args / JSON config).
    Everything that cannot be derived from QVD data lives here.

ScanTask
    One unique scan event derived from the Nessus QVD, keyed by
    (scan_date, source_file).  Becomes an OSCAL task.

AssessmentData
    Extends SystemData with SAP-specific aggregations:
    - unique_scan_dates: sorted list of distinct scan dates
    - unique_controls:   sorted list of normalised NIST 800-53 control IDs
    - unique_ips:        sorted list of distinct host IP addresses
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ssp_generator.system_model import SystemData


# ---------------------------------------------------------------------------
# User-supplied assessment configuration
# ---------------------------------------------------------------------------

@dataclass
class AssessmentConfig:
    """
    All assessment metadata that cannot be derived from scan data.

    Fields marked "REQUIRED — update" must be filled in before submitting
    the SAP for review.
    """

    # --- Identity ---
    system_name: str = "CLaaS Target System"
    system_name_short: str = ""
    assessment_id: Optional[str] = None    # Deterministic UUID when None
    org_name: str = "CLaaS Organization"   # System owner organisation
    assessor_name: str = "REQUIRED — Third-Party Assessment Organization"
    version: str = "1.0"

    # --- SSP reference (REQUIRED) ---
    ssp_href: str = (
        "REQUIRED — Provide relative or absolute path/URI to the system SSP, "
        "e.g. '../ssp/ssp.json'"
    )

    # --- Assessment schedule ---
    start_date: Optional[str] = None    # "YYYY-MM-DD"
    end_date: Optional[str] = None      # "YYYY-MM-DD"

    # --- Terms & conditions (REQUIRED — update before submission) ---
    rules_of_engagement: str = (
        "REQUIRED — Describe the rules of engagement for this assessment, "
        "including any restrictions on testing scope, timing, and methods."
    )
    methodology: str = (
        "This assessment uses automated vulnerability scanning (Tenable Nessus) "
        "to identify findings mapped to NIST SP 800-53 Rev 5 controls.  "
        "Findings are ingested and normalised by the CLaaS QVD Generator App "
        "and validated against the system authorization boundary."
    )
    assumptions: str = (
        "1. Scan data was collected from within the authorization boundary.\n"
        "2. Credentialed scan results are preferred over uncredentialed results.\n"
        "3. All hosts in scan data are within the system authorization boundary."
    )

    # --- Baseline profile (must match the SSP) ---
    baseline_profile_href: str = (
        "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
        "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_HIGH-baseline_profile.json"
    )

    # --- Roles (prepended to OSCAL metadata) ---
    roles: list[dict] = field(
        default_factory=lambda: [
            {"id": "prepared-by",        "title": "SAP Preparer"},
            {"id": "assessor",           "title": "Security Assessor"},
            {"id": "assessment-lead",    "title": "Assessment Lead"},
            {"id": "system-owner",       "title": "System Owner"},
            {"id": "authorizing-official","title": "Authorizing Official"},
        ]
    )


# ---------------------------------------------------------------------------
# SAP-specific derived data
# ---------------------------------------------------------------------------

@dataclass
class AssessmentData:
    """
    Wraps SystemData and pre-computes SAP-specific aggregations.

    Attributes:
        system_data:      Loaded QVD data (hosts, ports, software, compliance).
        unique_scan_dates: Sorted list of ISO date strings from Scan Date field.
        unique_controls:  Sorted normalised NIST control IDs across all hosts.
        unique_ips:       Sorted list of host IP addresses.
        source_files:     Unique source .nessus filenames (if present in QVD).
    """
    system_data: SystemData
    unique_scan_dates: list[str] = field(default_factory=list)
    unique_controls: list[str] = field(default_factory=list)
    unique_ips: list[str] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)

    @classmethod
    def from_system_data(cls, data: SystemData) -> "AssessmentData":
        """Build an AssessmentData from a loaded SystemData."""
        dates: set[str] = set()
        ips: set[str] = set()
        controls: set[str] = set()

        for h in data.hosts:
            ips.add(h.ip_address)
            if h.scan_date:
                dates.add(h.scan_date)
            controls.update(h.open_controls.keys())
            controls.update(h.closed_controls.keys())

        return cls(
            system_data=data,
            unique_scan_dates=sorted(dates),
            unique_controls=sorted(controls),
            unique_ips=sorted(ips),
        )
