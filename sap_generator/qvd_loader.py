"""
QVD loader for the CLaaS SAP Generator.

Delegates all QVD reading to :mod:`ssp_generator.qvd_loader` (the same
four QVD types are used for both the SSP and the SAP) and wraps the
result in an :class:`~sap_generator.assessment_model.AssessmentData`.

Install dependency:
    pip install pyqvd
"""

from __future__ import annotations

from typing import Optional

from ssp_generator.qvd_loader import load_all_qvds as _load_all_qvds
from .assessment_model import AssessmentData


def load_all_qvds(
    nessus_path: str,
    *,
    ppsm_path: Optional[str] = None,
    software_path: Optional[str] = None,
    compliance_path: Optional[str] = None,
) -> AssessmentData:
    """
    Load all available QVD files and return an :class:`AssessmentData`.

    Delegates to :func:`ssp_generator.qvd_loader.load_all_qvds` for
    the actual QVD parsing, then pre-computes SAP aggregations
    (unique scan dates, controls, IP addresses).

    Args:
        nessus_path:     Path to the Nessus main ``.qvd`` (required).
        ppsm_path:       Path to the PPSM ``.qvd`` (optional).
        software_path:   Path to the Software ``.qvd`` (optional).
        compliance_path: Path to the Compliance ``.qvd`` (optional).

    Returns:
        Populated :class:`AssessmentData` instance.
    """
    system_data = _load_all_qvds(
        nessus_path,
        ppsm_path=ppsm_path,
        software_path=software_path,
        compliance_path=compliance_path,
    )
    return AssessmentData.from_system_data(system_data)
