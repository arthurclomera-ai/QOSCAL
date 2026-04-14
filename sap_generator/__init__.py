"""
CLaaS OSCAL SAP Generator

Reads CLaaS QVD files produced by the QVD Generator App and generates a
conformant OSCAL v1.2.1 assessment-plan (SAP) JSON document.

What is derived from QVD data
------------------------------
reviewed-controls
    One control-selection entry per unique NIST 800-53 control found in
    the Control_Temp field of the Nessus main QVD.

assessment-subjects
    One subject entry per unique host IP from the Nessus main QVD.  When
    a PPSM QVD is supplied, subjects are enriched with OS and NetBIOS
    name properties.

assessment-assets / local-definitions
    Nessus scanner defined as a 'tool' component.  Separate 'TEST'
    activities are created for vulnerability scanning and (when the
    Compliance QVD is provided) policy compliance scanning.

tasks
    One task per unique scan date found in the QVD.  If no scan date is
    available, a single placeholder task is created.

What must be supplied via CLI / config file
--------------------------------------------
- System name and SSP document reference (--ssp-href)
- Assessor organisation name and roles
- Assessment start / end dates
- Rules of Engagement, methodology narrative
- NIST 800-53 baseline profile URL

Usage (CLI):
    python -m sap_generator Nessus.qvd \\
        --system-name "FSA Cloud FY25 Q3" \\
        --ssp-href    output/ssp_fy25q3.json \\
        --assessor    "Third-Party Assessment Organization"

Usage (library):
    from sap_generator.qvd_loader import load_all_qvds
    from sap_generator.assessment_model import AssessmentConfig
    from sap_generator.oscal_sap import build_sap, write_sap

    data   = load_all_qvds(nessus_path="Nessus.qvd")
    config = AssessmentConfig(
        system_name="FSA Cloud",
        ssp_href="output/ssp.json",
        assessor_name="TPAO Inc.",
    )
    sap = build_sap(data, config)
    write_sap(sap, "output/sap.json")
"""

__version__ = "1.0.0"
__oscal_version__ = "1.2.1"
