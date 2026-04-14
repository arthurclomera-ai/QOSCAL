"""
QVD loader for the CLaaS SAR Generator.

Delegates QVD reading to :mod:`sap_generator.qvd_loader` (which itself
delegates to :mod:`ssp_generator.qvd_loader`) and wraps the result in a
:class:`~sar_generator.results_model.SARData`.

Install dependency:
    pip install pyqvd
"""

from __future__ import annotations

from typing import Optional

from sap_generator.qvd_loader import load_all_qvds as _load_assessment_data
from .results_model import SARConfig, SARData


def load_all_qvds(
    nessus_path: str,
    *,
    ppsm_path: Optional[str] = None,
    software_path: Optional[str] = None,
    compliance_path: Optional[str] = None,
    config: Optional[SARConfig] = None,
) -> SARData:
    """
    Load all available QVD files and return a :class:`SARData`.

    Delegates QVD parsing to ``sap_generator.qvd_loader.load_all_qvds``,
    then pre-computes per-control evidence for the SAR findings section.

    Args:
        nessus_path:     Path to the Nessus main ``.qvd`` (required).
        ppsm_path:       Path to the PPSM ``.qvd`` (optional).
        software_path:   Path to the Software ``.qvd`` (optional).
        compliance_path: Path to the Compliance ``.qvd`` (optional).
        config:          :class:`SARConfig` used for date-range overrides.
                         A default config is used when None.

    Returns:
        Populated :class:`SARData` instance.
    """
    if config is None:
        config = SARConfig()

    assessment_data = _load_assessment_data(
        nessus_path,
        ppsm_path=ppsm_path,
        software_path=software_path,
        compliance_path=compliance_path,
    )
    return SARData.from_assessment_data(assessment_data, config)
