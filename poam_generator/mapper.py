"""
Maps a filtered Nessus QVD DataFrame to strongly-typed Finding objects.

Each Finding encapsulates one (VulID × IP Address) row and provides
computed properties used by the OSCAL builder:

  - oscal_likelihood / oscal_impact  →  NIST SP 800-30 Rev 1 terms
  - deadline                         →  scan_date + severity-based day offset
  - cve                              →  CVE ID if CVE_CorrelationKey is a real CVE
  - finding_key                      →  stable "ip:vulid" deduplication key
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Optional

import pandas as pd

# ---------------------------------------------------------------------------
# Severity → OSCAL risk characterisation + remediation deadline
#
# Likelihood / impact values follow NIST SP 800-30 Rev 1 vocabulary.
# Deadline offsets follow DoD RMF / DISA STIG guidance:
#   CAT I  (Very High / High) : 30 / 90 days
#   CAT II (Medium)           : 180 days
#   CAT III (Low)             : 365 days
# ---------------------------------------------------------------------------
SEVERITY_PROFILE: dict[str, dict] = {
    "VERY HIGH": {
        "likelihood": "very-high",
        "impact": "very-high",
        "deadline_days": 30,
        "risk_level": "critical",
    },
    "HIGH": {
        "likelihood": "high",
        "impact": "high",
        "deadline_days": 90,
        "risk_level": "high",
    },
    "MEDIUM": {
        "likelihood": "moderate",
        "impact": "moderate",
        "deadline_days": 180,
        "risk_level": "moderate",
    },
    "LOW": {
        "likelihood": "low",
        "impact": "low",
        "deadline_days": 365,
        "risk_level": "low",
    },
}

# Qlik date serial epoch: days since 1899-12-30 (identical to Excel)
_QLIK_EPOCH = date(1899, 12, 30)


@dataclass
class Finding:
    """A single open vulnerability finding from the Nessus QVD."""

    # Core identifiers
    vul_id: str
    plugin_name: str
    ip_address: str
    program_host_id: str
    host_key_id: str          # MAC address

    # Classification
    severity_id: str          # e.g. "High"
    stig_severity: str        # e.g. "CAT I"
    control_temp: str         # NIST 800-53 control, e.g. "SI-3"

    # Vulnerability detail
    cvss_score: Optional[float]
    cve_correlation_key: str  # CVE-YYYY-NNNN or Nessus_NNNN fallback
    plugin_correlation_key: str
    synopsis: str
    recommendation: str

    # Metadata
    scan_date: Optional[date]
    status: str               # "Open" | "Closed"
    credentialed_scan: str    # "TRUE" | "FALSE"
    source_file: str          # original .nessus filename

    # ------------------------------------------------------------------
    # Computed properties
    # ------------------------------------------------------------------

    @property
    def severity_key(self) -> str:
        """Normalised upper-case severity for lookup in SEVERITY_PROFILE."""
        return self.severity_id.upper().strip()

    @property
    def _profile(self) -> dict:
        return SEVERITY_PROFILE.get(self.severity_key, SEVERITY_PROFILE["LOW"])

    @property
    def oscal_likelihood(self) -> str:
        return self._profile["likelihood"]

    @property
    def oscal_impact(self) -> str:
        return self._profile["impact"]

    @property
    def deadline(self) -> Optional[date]:
        """Scheduled completion date = scan_date + severity-based offset."""
        if self.scan_date:
            return self.scan_date + timedelta(days=self._profile["deadline_days"])
        return None

    @property
    def finding_key(self) -> str:
        """Stable deduplication key: ``"<ip>:<vul_id>"``."""
        return f"{self.ip_address}:{self.vul_id}"

    @property
    def cve(self) -> Optional[str]:
        """Return a real CVE ID, or None if the key is a Nessus-native fallback."""
        k = self.cve_correlation_key.upper()
        if k.startswith("CVE-"):
            return self.cve_correlation_key
        return None


# ---------------------------------------------------------------------------
# DataFrame → Finding helpers
# ---------------------------------------------------------------------------

def _str(row: pd.Series, col: str, default: str = "") -> str:
    val = row.get(col, default)
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return default
    return str(val).strip()


def _float(row: pd.Series, col: str) -> Optional[float]:
    val = row.get(col)
    try:
        f = float(val)
        return None if pd.isna(f) else f
    except (TypeError, ValueError):
        return None


def _parse_date(row: pd.Series, col: str = "Scan Date") -> Optional[date]:
    """Parse a date from a QVD row.

    pyqvd may decode QVD dates as:
      - pandas Timestamp (modern pyqvd)
      - numeric Qlik serial (days since 1899-12-30)
      - ISO string ("YYYY-MM-DD")
    """
    val = row.get(col)
    if val is None:
        return None

    # pandas Timestamp
    try:
        ts = pd.Timestamp(val)
        if not pd.isna(ts):
            return ts.date()
    except Exception:
        pass

    # Qlik date serial number
    try:
        days = int(float(val))
        return _QLIK_EPOCH + timedelta(days=days)
    except (TypeError, ValueError):
        pass

    return None


def _detect_source_field(columns: list[str]) -> str:
    """Return the source-file column name from the QVD column list.

    The CLaaS QVD Generator uses a dynamic name from QVDFilesRouter
    (typically ``File_Nessus``).  Fall back to empty string if not found.
    """
    candidates = [c for c in columns if c.startswith("File_") or "SourceFile" in c]
    return candidates[0] if candidates else ""


def df_to_findings(df: pd.DataFrame) -> list[Finding]:
    """Convert a filtered Nessus QVD DataFrame into a list of :class:`Finding` objects.

    Args:
        df: DataFrame returned by
            :func:`~poam_generator.qvd_reader.load_nessus_findings`.

    Returns:
        List of Finding objects, one per DataFrame row.
    """
    source_field = _detect_source_field(df.columns.tolist())
    findings: list[Finding] = []

    for _, row in df.iterrows():
        findings.append(
            Finding(
                vul_id=_str(row, "VulID"),
                plugin_name=_str(row, "pluginName", "Unknown Finding"),
                ip_address=_str(row, "IP Address"),
                program_host_id=_str(row, "ProgramHostID"),
                host_key_id=_str(row, "HostKeyID"),
                severity_id=_str(row, "SeverityID", "Low"),
                stig_severity=_str(row, "STIG_Severity"),
                control_temp=_str(row, "Control_Temp"),
                cvss_score=_float(row, "CVSS Score"),
                cve_correlation_key=_str(row, "CVE_CorrelationKey"),
                plugin_correlation_key=_str(row, "PluginCorrelationKey"),
                synopsis=_str(row, "Synopsis"),
                recommendation=_str(row, "Recommendation"),
                scan_date=_parse_date(row),
                status=_str(row, "STATUS", "Open"),
                credentialed_scan=_str(row, "Credentialed_Scan", "FALSE"),
                source_file=_str(row, source_field) if source_field else "",
            )
        )

    return findings
