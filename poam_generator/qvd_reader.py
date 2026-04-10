"""
QVD file reader for CLaaS scanner data.

Wraps pyqvd to load Nessus (and future scanner) QVD files into pandas
DataFrames, then applies standard filters so only POA&M-eligible rows
reach the OSCAL builder.

Install dependency:
    pip install pyqvd
"""

from __future__ import annotations

import pandas as pd

try:
    from pyqvd import QvdTable  # type: ignore

    _PYQVD_AVAILABLE = True
except ImportError:
    _PYQVD_AVAILABLE = False

# ---------------------------------------------------------------------------
# Severity values that warrant a POA&M entry (Info is excluded)
# Values are matched case-insensitively against the QVD SeverityID field.
# ---------------------------------------------------------------------------
POAM_SEVERITIES = {"very high", "high", "medium", "low"}

# ---------------------------------------------------------------------------
# QVD column names written by the CLaaS QVD Generator App (v3.2.4).
# The source-file field name is dynamic (set by QVDFilesRouter), so it is
# detected at runtime rather than hard-coded here.
# ---------------------------------------------------------------------------
EXPECTED_COLUMNS = {
    "IP Address",
    "ProgramHostID",
    "VulID",
    "pluginName",
    "Synopsis",
    "Recommendation",
    "SeverityID",
    "STIG_Severity",
    "Control_Temp",
    "CVSS Score",
    "CVE_CorrelationKey",
    "PluginCorrelationKey",
    "HostKeyID",
    "Scan Date",
    "STATUS",
    "Credentialed_Scan",
}


def _check_pyqvd() -> None:
    if not _PYQVD_AVAILABLE:
        raise ImportError(
            "pyqvd is required to read QVD files.\n"
            "Install it with:  pip install pyqvd"
        )


def read_qvd(path: str) -> pd.DataFrame:
    """Read any QVD file and return its full contents as a DataFrame.

    Args:
        path: Absolute or relative path to the ``.qvd`` file.

    Returns:
        pandas DataFrame with one row per QVD record.

    Raises:
        ImportError: If pyqvd is not installed.
        FileNotFoundError: If *path* does not exist.
        Exception: For any QVD parse error propagated from pyqvd.
    """
    _check_pyqvd()
    table = QvdTable.from_qvd(path)
    return table.to_pandas()


def load_nessus_findings(
    path: str,
    *,
    include_closed: bool = False,
    include_info: bool = False,
) -> pd.DataFrame:
    """Load a Nessus QVD and return only POA&M-eligible findings.

    Applies the following filters in order:

    1. **STATUS** — keeps only ``'Open'`` rows unless *include_closed* is True.
    2. **SeverityID** — drops ``'Info'`` / ``'Informational'`` rows unless
       *include_info* is True.
    3. **Required fields** — drops rows where ``IP Address`` or ``VulID`` is
       blank/null (these cannot form a valid POA&M entry).

    Args:
        path: Path to the Nessus ``.qvd`` file.
        include_closed: When True, include ``STATUS='Closed'`` findings.
        include_info: When True, include ``SeverityID='Info'`` findings.

    Returns:
        Filtered DataFrame ready for :func:`~poam_generator.mapper.df_to_findings`.
    """
    df = read_qvd(path)

    # Normalise column names (trim leading/trailing whitespace)
    df.columns = [str(c).strip() for c in df.columns]

    # Warn about any expected columns that are absent
    missing = EXPECTED_COLUMNS - set(df.columns)
    if missing:
        import warnings

        warnings.warn(
            f"QVD is missing expected CLaaS columns: {sorted(missing)}. "
            "Some fields will default to empty strings.",
            stacklevel=2,
        )

    # --- STATUS filter ---
    if not include_closed and "STATUS" in df.columns:
        mask = df["STATUS"].astype(str).str.strip().str.upper() == "OPEN"
        df = df[mask].copy()

    # --- Severity filter ---
    if not include_info and "SeverityID" in df.columns:
        mask = df["SeverityID"].astype(str).str.strip().str.lower().isin(POAM_SEVERITIES)
        df = df[mask].copy()

    # --- Required-field filter ---
    for col in ("IP Address", "VulID"):
        if col in df.columns:
            mask = df[col].notna() & (df[col].astype(str).str.strip() != "")
            df = df[mask].copy()

    return df.reset_index(drop=True)


def report_columns(path: str) -> list[str]:
    """Return the column names present in a QVD file (useful for diagnostics).

    Args:
        path: Path to any ``.qvd`` file.

    Returns:
        Sorted list of column name strings.
    """
    df = read_qvd(path)
    return sorted(df.columns.tolist())
