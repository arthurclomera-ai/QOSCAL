"""
CLaaS OSCAL SSP Generator

Reads CLaaS QVD files produced by the QVD Generator App and generates a
conformant OSCAL v1.2.1 system-security-plan (SSP) JSON document.

What is derived from QVD data
------------------------------
- system-implementation/inventory-items  — one per unique host IP (Nessus main QVD)
- system-implementation/components       — one per unique host + optional software
                                           components (Software QVD)
- system-implementation port/protocol    — enriched from PPSM QVD when supplied
- control-implementation                 — one implemented-requirement per unique
                                           NIST 800-53 control found in Control_Temp;
                                           status derived from open-finding severity;
                                           evidence from Compliance QVD when supplied

What must be supplied via CLI / config file
--------------------------------------------
- System name, short name, description
- Organisation name and roles
- FIPS 199 security categorisation (C / I / A impact levels)
- Authorization boundary narrative
- Information types (SP 800-60 references)
- Baseline profile URL (defaults to NIST 800-53 Rev 5 HIGH)

Usage (CLI):
    python -m ssp_generator Nessus.qvd --system-name "FSA Cloud"

Usage (library):
    from ssp_generator.qvd_loader import load_all_qvds
    from ssp_generator.system_model import SystemConfig
    from ssp_generator.oscal_ssp import build_ssp, write_ssp

    data   = load_all_qvds(nessus_path="Nessus.qvd")
    config = SystemConfig(system_name="FSA Cloud", org_name="IPKeys Technologies")
    ssp    = build_ssp(data, config)
    write_ssp(ssp, "output_ssp.json")
"""

__version__ = "1.0.0"
__oscal_version__ = "1.2.1"
