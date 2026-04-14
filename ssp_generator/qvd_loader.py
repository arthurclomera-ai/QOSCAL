"""
QVD loaders for the CLaaS SSP Generator.

Reads the four QVD types produced by the CLaaS QVD Generator App and
assembles a :class:`~ssp_generator.system_model.SystemData` object.

QVD types and their field mappings
------------------------------------
Nessus main   IP Address, ProgramHostID, HostKeyID, VulID, SeverityID,
              Control_Temp, STATUS, Scan Date, Credentialed_Scan
PPSM          port, protocol, svc_name, HostKeyID, tagKey/tagValue
              (where tagKey ∈ {host-ip, os, mac-address, netbios-name})
Software      IP Address, ProgramHostID, HostKeyID, Software, SoftwareKey,
              Scan Date
Compliance    HostKey, pluginID, pluginName, Compliance Test,
              ComplianceResult, ResultInfo, Solution, Reference,
              PolicyValue, ActualValue

Install dependency:
    pip install pyqvd
"""

from __future__ import annotations

import warnings
from datetime import date, timedelta
from typing import Optional

import pandas as pd

from .system_model import (
    ComplianceResult,
    HostRecord,
    PortEntry,
    SoftwareEntry,
    SystemData,
    is_nist_control,
    normalise_control_id,
)

try:
    from pyqvd import QvdTable  # type: ignore
    _PYQVD_AVAILABLE = True
except ImportError:
    _PYQVD_AVAILABLE = False

# Qlik date serial epoch: days since 1899-12-30 (identical to Excel)
_QLIK_EPOCH = date(1899, 12, 30)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_pyqvd() -> None:
    if not _PYQVD_AVAILABLE:
        raise ImportError(
            "pyqvd is required to read QVD files.\n"
            "Install it with:  pip install pyqvd"
        )


def _read_qvd(path: str) -> pd.DataFrame:
    _check_pyqvd()
    table = QvdTable.from_qvd(path)
    df = table.to_pandas()
    df.columns = [str(c).strip() for c in df.columns]
    return df


def _str(row: pd.Series, col: str, default: str = "") -> str:
    val = row.get(col, default)
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return default
    return str(val).strip()


def _parse_date(val) -> Optional[str]:
    """
    Convert a QVD date value to an ISO 'YYYY-MM-DD' string.

    pyqvd may return: pandas Timestamp, Qlik numeric serial, or ISO string.
    Returns None if the value cannot be parsed.
    """
    if val is None:
        return None
    # pandas Timestamp
    try:
        ts = pd.Timestamp(val)
        if not pd.isna(ts):
            return ts.date().isoformat()
    except Exception:
        pass
    # Qlik serial number
    try:
        d = _QLIK_EPOCH + timedelta(days=int(float(val)))
        return d.isoformat()
    except (TypeError, ValueError):
        pass
    return None


def _warn_missing(path: str, missing: set[str]) -> None:
    if missing:
        warnings.warn(
            f"{path}: missing expected columns: {sorted(missing)}. "
            "Affected fields will default to empty strings.",
            stacklevel=3,
        )


# ---------------------------------------------------------------------------
# Nessus main QVD
# ---------------------------------------------------------------------------

_NESSUS_EXPECTED = {
    "IP Address", "ProgramHostID", "HostKeyID",
    "VulID", "SeverityID", "Control_Temp",
    "STATUS", "Scan Date", "Credentialed_Scan",
}


def load_nessus_main(path: str) -> list[HostRecord]:
    """
    Read the Nessus main QVD and return one :class:`HostRecord` per unique IP.

    Open and closed findings are tallied per host per control so the SSP
    builder can compute control-implementation status.

    Args:
        path: Path to the Nessus main ``.qvd`` file.

    Returns:
        List of HostRecord objects, one per unique IP Address.
    """
    df = _read_qvd(path)
    _warn_missing(path, _NESSUS_EXPECTED - set(df.columns))

    hosts: dict[str, HostRecord] = {}

    for _, row in df.iterrows():
        ip = _str(row, "IP Address")
        if not ip:
            continue

        if ip not in hosts:
            hosts[ip] = HostRecord(
                ip_address=ip,
                program_host_id=_str(row, "ProgramHostID"),
                host_key_id=_str(row, "HostKeyID"),
                scan_date=_parse_date(row.get("Scan Date")),
                credentialed_scan=_str(row, "Credentialed_Scan", "FALSE"),
            )

        control_raw = _str(row, "Control_Temp")
        if not control_raw or not is_nist_control(control_raw):
            continue

        control_id = normalise_control_id(control_raw)
        severity = _str(row, "SeverityID", "Low")
        status = _str(row, "STATUS", "Open").upper()

        if status == "OPEN":
            hosts[ip].open_controls.setdefault(control_id, []).append(severity)
        else:
            hosts[ip].closed_controls.setdefault(control_id, []).append(severity)

    return list(hosts.values())


# ---------------------------------------------------------------------------
# PPSM QVD
# ---------------------------------------------------------------------------

_PPSM_EXPECTED = {"port", "protocol", "svc_name", "HostKeyID"}


def load_ppsm(path: str) -> list[PortEntry]:
    """
    Read the Nessus PPSM QVD and return one :class:`PortEntry` per row.

    The PPSM QVD uses a tagKey/tagValue join for host attributes (host-ip,
    os, mac-address, netbios-name).  This function extracts the IP address
    from rows where tagKey == 'host-ip' and builds the port inventory.

    Args:
        path: Path to the PPSM ``.qvd`` file.

    Returns:
        List of PortEntry objects.
    """
    df = _read_qvd(path)
    _warn_missing(path, _PPSM_EXPECTED - set(df.columns))

    # Build HostKeyID → IP address map from tag rows
    host_ip_map: dict[str, str] = {}
    os_map: dict[str, str] = {}
    if "tagKey" in df.columns and "tagValue" in df.columns:
        tag_df = df[["HostKeyID", "tagKey", "tagValue"]].dropna(subset=["HostKeyID"])
        for _, row in tag_df.iterrows():
            hk = _str(row, "HostKeyID")
            key = _str(row, "tagKey").lower()
            val = _str(row, "tagValue")
            if not hk or not val:
                continue
            if key == "host-ip":
                host_ip_map[hk] = val
            elif key == "os":
                os_map[hk] = val

    # Build PortEntry list — skip rows with no meaningful port data
    entries: list[PortEntry] = []
    seen: set[tuple] = set()

    for _, row in df.iterrows():
        hk = _str(row, "HostKeyID")
        port = _str(row, "port")
        proto = _str(row, "protocol")
        svc = _str(row, "svc_name")

        if not port or port == "0":
            continue

        ip = host_ip_map.get(hk, "")
        dedup = (hk, port, proto)
        if dedup in seen:
            continue
        seen.add(dedup)

        entries.append(
            PortEntry(
                host_key_id=hk,
                ip_address=ip,
                port=port,
                protocol=proto,
                svc_name=svc,
                scan_date=_parse_date(row.get("Scan Date")),
            )
        )

    return entries


# ---------------------------------------------------------------------------
# Software QVD
# ---------------------------------------------------------------------------

_SOFTWARE_EXPECTED = {"IP Address", "ProgramHostID", "HostKeyID", "Software", "SoftwareKey"}


def load_software(path: str) -> list[SoftwareEntry]:
    """
    Read the Nessus Software QVD and return one :class:`SoftwareEntry` per row.

    Rows with blank Software values are skipped (they represent header lines
    that were not fully filtered by the QVD Generator).

    Args:
        path: Path to the Software ``.qvd`` file.

    Returns:
        List of SoftwareEntry objects.
    """
    df = _read_qvd(path)
    _warn_missing(path, _SOFTWARE_EXPECTED - set(df.columns))

    entries: list[SoftwareEntry] = []
    for _, row in df.iterrows():
        sw = _str(row, "Software")
        ip = _str(row, "IP Address")
        if not sw or not ip:
            continue
        entries.append(
            SoftwareEntry(
                ip_address=ip,
                program_host_id=_str(row, "ProgramHostID"),
                host_key_id=_str(row, "HostKeyID"),
                software=sw,
                software_key=_str(row, "SoftwareKey"),
                scan_date=_parse_date(row.get("Scan Date")),
            )
        )
    return entries


# ---------------------------------------------------------------------------
# Compliance QVD
# ---------------------------------------------------------------------------

_COMPLIANCE_EXPECTED = {
    "HostKey", "pluginID", "pluginName",
    "Compliance Test", "ComplianceResult",
    "ResultInfo", "Solution", "Reference",
    "PolicyValue", "ActualValue",
}


def load_compliance(path: str) -> list[ComplianceResult]:
    """
    Read the Nessus Compliance QVD and return one :class:`ComplianceResult` per row.

    Args:
        path: Path to the Compliance ``.qvd`` file.

    Returns:
        List of ComplianceResult objects.
    """
    df = _read_qvd(path)
    _warn_missing(path, _COMPLIANCE_EXPECTED - set(df.columns))

    entries: list[ComplianceResult] = []
    for _, row in df.iterrows():
        hk = _str(row, "HostKey")
        if not hk:
            continue
        entries.append(
            ComplianceResult(
                host_key=hk,
                plugin_id=_str(row, "pluginID"),
                plugin_name=_str(row, "pluginName"),
                compliance_test=_str(row, "Compliance Test"),
                result=_str(row, "ComplianceResult"),
                result_info=_str(row, "ResultInfo"),
                solution=_str(row, "Solution"),
                reference=_str(row, "Reference"),
                policy_value=_str(row, "PolicyValue"),
                actual_value=_str(row, "ActualValue"),
            )
        )
    return entries


# ---------------------------------------------------------------------------
# Convenience loader
# ---------------------------------------------------------------------------

def load_all_qvds(
    nessus_path: str,
    *,
    ppsm_path: Optional[str] = None,
    software_path: Optional[str] = None,
    compliance_path: Optional[str] = None,
) -> SystemData:
    """
    Load all available QVD files and return a :class:`SystemData` object.

    Only *nessus_path* is required; the other paths are optional.  When a
    PPSM QVD is provided, host OS names are back-filled onto the HostRecord
    objects derived from the Nessus main QVD.

    Args:
        nessus_path:    Path to the Nessus main ``.qvd``.
        ppsm_path:      Path to the PPSM ``.qvd`` (optional).
        software_path:  Path to the Software ``.qvd`` (optional).
        compliance_path: Path to the Compliance ``.qvd`` (optional).

    Returns:
        Populated :class:`SystemData` instance.
    """
    hosts = load_nessus_main(nessus_path)

    ports: list[PortEntry] = []
    if ppsm_path:
        ports = load_ppsm(ppsm_path)
        # Back-fill OS name and netbios-name onto HostRecords from PPSM tag data
        _backfill_ppsm_tags(hosts, ppsm_path)

    software: list[SoftwareEntry] = []
    if software_path:
        software = load_software(software_path)

    compliance: list[ComplianceResult] = []
    if compliance_path:
        compliance = load_compliance(compliance_path)

    return SystemData(
        hosts=hosts,
        ports=ports,
        software=software,
        compliance=compliance,
    )


def _backfill_ppsm_tags(hosts: list[HostRecord], ppsm_path: str) -> None:
    """Back-fill OS and NetBIOS name onto HostRecords from the PPSM QVD."""
    try:
        df = _read_qvd(ppsm_path)
    except Exception:
        return

    if "tagKey" not in df.columns or "tagValue" not in df.columns:
        return

    # Build mac → os / netbios maps
    os_map: dict[str, str] = {}
    nb_map: dict[str, str] = {}
    ip_mac_map: dict[str, str] = {}

    tag_df = df[["HostKeyID", "tagKey", "tagValue"]].dropna(subset=["HostKeyID"])
    for _, row in tag_df.iterrows():
        hk = _str(row, "HostKeyID")
        key = _str(row, "tagKey").lower()
        val = _str(row, "tagValue")
        if not hk or not val:
            continue
        if key == "os":
            os_map[hk] = val
        elif key == "netbios-name":
            nb_map[hk] = val
        elif key == "host-ip":
            ip_mac_map[val] = hk   # ip → mac

    for h in hosts:
        mac = h.host_key_id or ip_mac_map.get(h.ip_address, "")
        if not mac:
            continue
        if mac in os_map and not h.os_name:
            h.os_name = os_map[mac]
        if mac in nb_map and not h.netbios_name:
            h.netbios_name = nb_map[mac]
