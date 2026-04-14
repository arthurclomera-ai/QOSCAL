"""
CLaaS OSCAL SAR Generator

Reads CLaaS QVD files produced by the QVD Generator App and generates a
conformant OSCAL v1.2.1 assessment-results (SAR) JSON document.

What is derived from QVD data
------------------------------
results[0].observations
    One observation per (VulID × IP Address) finding from the Nessus main
    QVD.  Each observation captures what the scanner found on a specific
    host (type='discovery').  When a Compliance QVD is supplied, additional
    observations of type='control-objective' are generated from the PASSED /
    FAILED policy compliance results.

results[0].risks
    One risk per unique VulID (plugin ID), shared across all hosts where
    that plugin fired.  Risk status is 'open' when any host has an open
    finding for that plugin; 'closed' when all findings are closed.

results[0].findings
    One finding per unique NIST 800-53 control ID found in Control_Temp.
    Each finding targets the control's primary objective ({control-id}_obj)
    and carries the assessor's pass/fail conclusion derived from the
    aggregated observation and risk evidence:

        not-satisfied / fail  — any open High or Very High finding, OR
                                any FAILED compliance check for the control
        not-satisfied / other — open Medium / Low findings only
        satisfied / pass      — no open findings and all compliance checks
                                PASSED (or no compliance data for control)

    Related-observations and related-risks are cross-referenced by UUID,
    enabling full traceability from finding → observation → host evidence.

results[0].assessment-log
    One log entry per unique scan date, providing an audit trail of when
    assessment data was collected.

What must be supplied via CLI / config file
--------------------------------------------
- System name and SAP document reference (--sap-href)
- Assessor organisation name
- Assessment start / end dates (derived from QVD scan dates when omitted)

Usage (CLI):
    python -m sar_generator Nessus.qvd \\
        --system-name "FSA Cloud FY25 Q3" \\
        --sap-href    output/sap_fy25q3.json \\
        --assessor    "IPKeys 3PAO"

Usage (library):
    from sar_generator.qvd_loader import load_all_qvds
    from sar_generator.results_model import SARConfig
    from sar_generator.oscal_sar import build_sar, write_sar

    data   = load_all_qvds(nessus_path="Nessus.qvd",
                            compliance_path="Compliance.qvd")
    config = SARConfig(system_name="FSA Cloud", sap_href="output/sap.json",
                       assessor_name="IPKeys 3PAO")
    sar    = build_sar(data, config)
    write_sar(sar, "output/sar.json")
"""

__version__ = "1.0.0"
__oscal_version__ = "1.2.1"
