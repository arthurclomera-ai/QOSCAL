"""
Data model for the CLaaS SSP generator.

Classes
-------
SystemConfig
    User-supplied system metadata (CLI args / JSON config file).
    Everything that cannot be derived from QVD data lives here.

HostRecord
    One unique host IP from the Nessus main QVD, with associated
    finding summary used to compute control-implementation status.

PortEntry
    One port/protocol/service row from the PPSM QVD.

SoftwareEntry
    One installed-software row from the Software QVD.

ComplianceResult
    One Policy Compliance result row from the Compliance QVD.

SystemData
    Aggregate container passed to the SSP builder.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# NIST 800-53 control ID pattern (AC-1, SI-3, AC-2(1), etc.)
# ---------------------------------------------------------------------------
_CONTROL_RE = re.compile(r"^[A-Z]{2,3}-\d+(\(\d+\))?$")


def is_nist_control(value: str) -> bool:
    """Return True if *value* looks like a NIST 800-53 control ID."""
    return bool(_CONTROL_RE.match(value.strip().upper()))


def normalise_control_id(value: str) -> str:
    """Return lowercase OSCAL-style control ID, e.g. 'ac-1', 'si-3(1)'."""
    return value.strip().lower()


# ---------------------------------------------------------------------------
# User-supplied system configuration
# ---------------------------------------------------------------------------

@dataclass
class InformationType:
    """A single SP 800-60 information type entry."""
    title: str = "Federal Information"
    description: str = (
        "Information processed, stored, or transmitted by this system. "
        "Update to reference the applicable SP 800-60 Vol II information type."
    )
    # SP 800-60 Vol II identifier, e.g. "C.2.4.1"
    sp800_60_id: str = ""
    confidentiality_impact: str = "moderate"   # low | moderate | high
    integrity_impact: str = "moderate"
    availability_impact: str = "moderate"


@dataclass
class SystemConfig:
    """
    All system metadata that cannot be derived from scan data.

    Every field has a sensible default so the generator can produce a
    working (but incomplete) SSP with only a system name and org name.
    Fields marked "REQUIRED — update" must be filled in before submitting
    the SSP for review.
    """
    # --- Identity ---
    system_name: str = "CLaaS Target System"
    system_name_short: str = ""          # Acronym; derived from system_name if blank
    system_id: Optional[str] = None      # Deterministic UUID when None
    org_name: str = "CLaaS Organization"
    version: str = "1.0"

    # --- Narrative (REQUIRED — update before ATO submission) ---
    system_description: str = (
        "REQUIRED — Provide a complete system description per NIST SP 800-18 §2.1. "
        "Include system purpose, boundaries, and operational environment."
    )
    boundary_description: str = (
        "REQUIRED — Describe the authorization boundary including all hardware, "
        "software, and interfaces within the system boundary."
    )

    # --- Security categorisation (FIPS 199) ---
    # Allowed: "low" | "moderate" | "high"
    confidentiality_impact: str = "moderate"
    integrity_impact: str = "moderate"
    availability_impact: str = "moderate"

    # Overall sensitivity level; defaults to highest of C/I/A
    @property
    def security_sensitivity_level(self) -> str:
        order = {"low": 0, "moderate": 1, "high": 2}
        levels = [
            self.confidentiality_impact,
            self.integrity_impact,
            self.availability_impact,
        ]
        return max(levels, key=lambda x: order.get(x.lower(), 0))

    # --- Authorization status ---
    # Allowed OSCAL values: "operational" | "under-development" |
    #   "under-major-modification" | "disposition" | "other"
    authorization_status: str = "operational"
    date_authorized: Optional[str] = None    # "YYYY-MM-DD" or None

    # --- Baseline profile ---
    # URL of the NIST 800-53 Rev 5 profile to import.
    # Default: HIGH baseline from NIST OSCAL content repository.
    baseline_profile_href: str = (
        "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
        "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_HIGH-baseline_profile.json"
    )

    # --- Information types ---
    information_types: list[InformationType] = field(
        default_factory=lambda: [InformationType()]
    )

    # --- Roles ---
    # Each entry: {"id": "role-id", "title": "Role Title"}
    roles: list[dict] = field(
        default_factory=lambda: [
            {"id": "system-owner",         "title": "System Owner"},
            {"id": "authorizing-official", "title": "Authorizing Official"},
            {"id": "system-poc-management","title": "System POC Management"},
            {"id": "system-poc-technical", "title": "System POC Technical"},
            {"id": "prepared-by",          "title": "CLaaS Automated System"},
        ]
    )


# ---------------------------------------------------------------------------
# QVD-derived data
# ---------------------------------------------------------------------------

@dataclass
class HostRecord:
    """
    One unique host from the Nessus main QVD.

    open_controls maps control_id → list of severity strings for all open
    findings mapped to that control on this host.
    """
    ip_address: str
    program_host_id: str = ""
    host_key_id: str = ""          # MAC address
    scan_date: Optional[str] = None
    credentialed_scan: str = "FALSE"
    os_name: str = ""              # Populated from PPSM tag data if available
    netbios_name: str = ""         # Populated from PPSM tag data if available
    # control_id (normalised lowercase) → list of SeverityID strings
    open_controls: dict[str, list[str]] = field(default_factory=dict)
    # control_id → list of SeverityID strings for closed findings
    closed_controls: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class PortEntry:
    """One port/protocol/service row from the PPSM QVD."""
    host_key_id: str    # MAC address (HostKeyID)
    ip_address: str     # from 'host-ip' tag
    port: str
    protocol: str       # tcp | udp | icmp
    svc_name: str
    scan_date: Optional[str] = None


@dataclass
class SoftwareEntry:
    """One installed-software row from the Software QVD."""
    ip_address: str
    program_host_id: str
    host_key_id: str
    software: str        # Software name (without version)
    software_key: str    # Software name + version string
    scan_date: Optional[str] = None


@dataclass
class ComplianceResult:
    """One Policy Compliance result from the Compliance QVD."""
    host_key: str           # Host IP (HostKey field)
    plugin_id: str
    plugin_name: str
    compliance_test: str    # "Compliance Test" field
    result: str             # PASSED | FAILED | WARNING | ERROR
    result_info: str
    solution: str
    reference: str          # NIST control reference embedded by Nessus
    policy_value: str
    actual_value: str


@dataclass
class SystemData:
    """Aggregate of all QVD-loaded data passed to the SSP builder."""
    hosts: list[HostRecord] = field(default_factory=list)
    ports: list[PortEntry] = field(default_factory=list)
    software: list[SoftwareEntry] = field(default_factory=list)
    compliance: list[ComplianceResult] = field(default_factory=list)

    # Derived: set of all unique normalised control IDs seen across all QVDs
    @property
    def all_control_ids(self) -> set[str]:
        ids: set[str] = set()
        for h in self.hosts:
            ids.update(h.open_controls.keys())
            ids.update(h.closed_controls.keys())
        return ids
