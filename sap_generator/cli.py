"""
Command-line interface for the CLaaS OSCAL SAP Generator.

Examples
--------
Minimal — Nessus QVD only:

    python -m sap_generator Nessus.qvd \\
        --system-name "FSA Cloud FY25 Q3" \\
        --ssp-href    output/ssp_fy25q3.json \\
        --assessor    "IPKeys 3PAO"

All QVD inputs:

    python -m sap_generator Nessus.qvd \\
        --ppsm-qvd        PPSM.qvd \\
        --software-qvd    Software.qvd \\
        --compliance-qvd  Compliance.qvd \\
        --system-name     "FSA Cloud FY25 Q3" \\
        --ssp-href        output/ssp_fy25q3.json \\
        --assessor        "IPKeys 3PAO" \\
        --start-date      2025-07-01 \\
        --end-date        2025-07-31 \\
        --output          output/sap_fy25q3.json

Load assessment metadata from a JSON config file:

    python -m sap_generator Nessus.qvd --config assessment_config.json

The JSON config file mirrors the AssessmentConfig field names:

    {
      "system_name":       "FSA Cloud",
      "org_name":          "Agency Name",
      "assessor_name":     "Third-Party Assessment Organization",
      "ssp_href":          "../ssp/ssp.json",
      "start_date":        "2025-07-01",
      "end_date":          "2025-07-31",
      "rules_of_engagement": "Full ROE narrative...",
      "methodology":       "Assessment methodology narrative...",
      "assumptions":       "1. Scans were credentialed.\\n2. ...",
      "baseline_profile_href": "https://..."
    }

Inspect QVD columns without generating output:

    python -m sap_generator --inspect Nessus.qvd
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .qvd_loader import load_all_qvds
from .assessment_model import AssessmentConfig
from .oscal_sap import build_sap, write_sap, sap_summary


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m sap_generator",
        description=(
            "Generate an OSCAL v1.2.1 Security Assessment Plan (SAP) "
            "JSON document from CLaaS Nessus QVD files."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # --- Input QVDs ---
    p.add_argument(
        "nessus_qvd",
        metavar="NESSUS_QVD",
        help="Path to the Nessus main .qvd file (required).",
    )
    p.add_argument(
        "--ppsm-qvd", metavar="QVD", default=None,
        help="Path to the Nessus PPSM .qvd file (port/protocol/service inventory).",
    )
    p.add_argument(
        "--software-qvd", metavar="QVD", default=None,
        help="Path to the Nessus Software .qvd file (installed software inventory).",
    )
    p.add_argument(
        "--compliance-qvd", metavar="QVD", default=None,
        help="Path to the Nessus Compliance .qvd file (Policy Compliance results).",
    )

    # --- Config file ---
    p.add_argument(
        "--config", metavar="JSON_FILE", default=None,
        help=(
            "JSON file with AssessmentConfig fields. "
            "CLI flags override values in the config file."
        ),
    )

    # --- Assessment metadata ---
    p.add_argument(
        "--system-name", metavar="NAME", default=None,
        help='Full name of the system under assessment.',
    )
    p.add_argument(
        "--system-name-short", metavar="ACRONYM", default=None,
        help="Short name / acronym for the system.",
    )
    p.add_argument(
        "--org-name", metavar="NAME", default=None,
        help="System owner organisation name.",
    )
    p.add_argument(
        "--assessor", metavar="NAME", default=None,
        help="Name of the assessing organisation (3PAO or government assessor).",
    )
    p.add_argument(
        "--ssp-href", metavar="HREF", default=None,
        help=(
            "Relative or absolute path / URI to the SSP document being assessed. "
            "Example: ../ssp/ssp_fy25q3.json"
        ),
    )
    p.add_argument(
        "--assessment-id", metavar="UUID", default=None,
        help=(
            "Explicit UUID for the assessment-plan element. "
            "Generated randomly when omitted."
        ),
    )
    p.add_argument(
        "--version", metavar="VER", default=None,
        help='Document version string (default: "1.0").',
    )

    # --- Schedule ---
    p.add_argument(
        "--start-date", metavar="YYYY-MM-DD", default=None,
        help="Assessment start date.",
    )
    p.add_argument(
        "--end-date", metavar="YYYY-MM-DD", default=None,
        help="Assessment end date.",
    )

    # --- Baseline ---
    p.add_argument(
        "--baseline", metavar="URL", default=None,
        help=(
            "URL of the NIST 800-53 Rev 5 baseline profile (must match SSP). "
            "Defaults to the NIST HIGH baseline."
        ),
    )

    # --- Output ---
    p.add_argument(
        "-o", "--output", metavar="OUTPUT_JSON", default=None,
        help=(
            "Destination JSON file path. "
            "Defaults to <nessus_stem>_sap.json in the current directory."
        ),
    )

    # --- Utility ---
    p.add_argument(
        "--inspect", action="store_true", default=False,
        help=(
            "Print column names for each QVD provided and exit. "
            "Useful for diagnosing field-name issues."
        ),
    )

    return p


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _load_config_file(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _build_config(args: argparse.Namespace, cfg_file: dict) -> AssessmentConfig:
    """Merge JSON config file with CLI flag overrides."""
    def _pick(attr: str, default):
        val = getattr(args, attr, None)
        if val is not None:
            return val
        return cfg_file.get(attr, default)

    cfg = AssessmentConfig()
    cfg.system_name    = _pick("system_name",    cfg.system_name)
    cfg.system_name_short = _pick("system_name_short", cfg.system_name_short)
    cfg.org_name       = _pick("org_name",       cfg.org_name)
    cfg.assessor_name  = _pick("assessor",       cfg.assessor_name)
    cfg.ssp_href       = _pick("ssp_href",       cfg.ssp_href)
    cfg.assessment_id  = _pick("assessment_id",  cfg.assessment_id)
    cfg.version        = _pick("version",        cfg.version)
    cfg.start_date     = _pick("start_date",     cfg.start_date)
    cfg.end_date       = _pick("end_date",       cfg.end_date)

    if args.baseline:
        cfg.baseline_profile_href = args.baseline
    elif "baseline_profile_href" in cfg_file:
        cfg.baseline_profile_href = cfg_file["baseline_profile_href"]

    for field in ("rules_of_engagement", "methodology", "assumptions"):
        if field in cfg_file:
            setattr(cfg, field, cfg_file[field])

    return cfg


# ---------------------------------------------------------------------------
# Inspect mode
# ---------------------------------------------------------------------------

def _inspect_qvds(args: argparse.Namespace) -> int:
    from pyqvd import QvdTable  # type: ignore

    paths = [
        ("Nessus main", args.nessus_qvd),
        ("PPSM",        args.ppsm_qvd),
        ("Software",    args.software_qvd),
        ("Compliance",  args.compliance_qvd),
    ]
    any_error = False
    for label, path in paths:
        if not path:
            continue
        p = Path(path)
        if not p.exists():
            print(f"ERROR: {label} QVD not found: {p}", file=sys.stderr)
            any_error = True
            continue
        try:
            df = QvdTable.from_qvd(str(p)).to_pandas()
            cols = sorted(str(c).strip() for c in df.columns)
            print(f"\n{label} QVD — {p.name} ({len(cols)} columns):")
            for c in cols:
                print(f"  {c}")
        except Exception as exc:
            print(f"ERROR reading {label} QVD {p}: {exc}", file=sys.stderr)
            any_error = True

    return 1 if any_error else 0


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """
    Parse arguments, load QVDs, build SAP, write JSON.

    Returns:
        0 = success, 1 = bad argument / file not found,
        2 = import error, 3 = QVD read error, 4 = no hosts found.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    nessus_path = Path(args.nessus_qvd)
    if not nessus_path.exists():
        print(f"ERROR: Nessus QVD not found: {nessus_path}", file=sys.stderr)
        return 1

    if args.inspect:
        try:
            return _inspect_qvds(args)
        except ImportError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

    output_path = (
        Path(args.output) if args.output else Path(f"{nessus_path.stem}_sap.json")
    )

    # --- Config ---
    cfg_file: dict = {}
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"ERROR: Config file not found: {config_path}", file=sys.stderr)
            return 1
        try:
            cfg_file = _load_config_file(str(config_path))
        except json.JSONDecodeError as exc:
            print(f"ERROR: Invalid JSON in config file: {exc}", file=sys.stderr)
            return 1

    config = _build_config(args, cfg_file)

    # --- Load QVDs ---
    print(f"Reading Nessus main QVD : {nessus_path}")
    try:
        data = load_all_qvds(
            str(nessus_path),
            ppsm_path=args.ppsm_qvd,
            software_path=args.software_qvd,
            compliance_path=args.compliance_qvd,
        )
    except ImportError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"ERROR reading QVD: {exc}", file=sys.stderr)
        return 3

    print(f"  Hosts found         : {len(data.system_data.hosts)}")
    print(f"  Unique scan dates   : {len(data.unique_scan_dates)}")
    print(f"  Unique controls     : {len(data.unique_controls)}")
    print(f"  Compliance results  : {len(data.system_data.compliance)}")

    if not data.system_data.hosts:
        print("No hosts found in QVD. Nothing written.", file=sys.stderr)
        return 4

    # --- Build SAP ---
    print("Building OSCAL SAP document ...")
    sap = build_sap(
        data,
        config,
        nessus_path=str(nessus_path),
        ppsm_path=args.ppsm_qvd,
        software_path=args.software_qvd,
        compliance_path=args.compliance_qvd,
    )

    summary = sap_summary(sap)

    # --- Write output ---
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_sap(sap, str(output_path))

    print(f"Output written : {output_path}")
    print(f"  Document UUID       : {summary['document_uuid']}")
    print(f"  OSCAL version       : {summary['oscal_version']}")
    print(f"  Reviewed controls   : {summary['reviewed_controls']}")
    print(f"  Assessment subjects : {summary['assessment_subjects']}")
    print(f"  Tasks               : {summary['tasks']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
