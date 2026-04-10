"""
CLaaS OSCAL POA&M Generator

Reads Nessus QVD files produced by the CLaaS QVD Generator App and
outputs a conformant OSCAL plan-of-action-and-milestones JSON document.

Usage (CLI):
    python -m poam_generator Nessus.qvd --system-name "My System"

Usage (library):
    from poam_generator.qvd_reader import load_nessus_findings
    from poam_generator.mapper import df_to_findings
    from poam_generator.oscal_poam import build_poam, write_poam

    df       = load_nessus_findings("Nessus.qvd")
    findings = df_to_findings(df)
    poam     = build_poam(findings, system_name="My System")
    write_poam(poam, "output_poam.json")
"""

__version__ = "1.0.0"
__oscal_version__ = "1.2.1"
