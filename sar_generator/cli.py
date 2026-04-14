"""
Command-line interface for the CLaaS OSCAL SAR Generator.

Examples
--------
Minimal — Nessus QVD only:

    python -m sar_generator Nessus.qvd \\
        --system-name "FSA Cloud FY25 Q3" \\
        --sap-href    output/sap_fy25q3.json \\
        --assessor    "IPKeys 3PAO"

Full inputs with compliance evidence:

    python -m sar_generator Nessus.qvd \\
        --ppsm-qvd        PPSM.qvd \\
        --compliance-qvd  Compliance.qvd \\
        --system-name     "FSA Cloud FY25 Q3" \\
        --sap-href        output/sap_fy25q3.json \\
        --assessor        "IPKeys 3PAO" \\
        --start-date      2025-07-01 \\
        --end-date        2025-07-31 \\
        --output          output/sar_fy25q3.json

Load assessment metadata from a JSON config file:

    python -m sar_generator Nessus.qvd --config assessment_config.json

The JSON config file mirrors the SARConfig field names:

    {
      "system_name":        "FSA Cloud",
      "org_name":           "Agency Name",
      "assessor_name":      "Third-Party Assessment Organization",
      "sap_href":           "../sap/sap.json",
      "start_date":         "2025-07-01",
      "end_date":           "2025-07-31",
      "result_title":       "FY25 Q3 Assessment Results",
      "result_description": "Full assessment description...",
      "baseline_profile_href": "https://..."
    }

Inspect QVD columns without generating output:

    python -m sar_generator --inspect Nessus.qvd --compliance-qvd Compliance.qvd

Four-document generation workflow
----------------------------------
    python -m ssp_generator Nessus.qvd --system-name "FSA Cloud" -o output/ssp.json
    python -m sap_generator Nessus.qvd --ssp-href output/ssp.json -o output/sap.json
    python -m sar_generator Nessus.qvd --sap-href output/sap.json -o output/sar.json
    python -m poam_generator Nessus.qvd -o output/poam.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .qvd_loader import load_all_qvds
from .results_model import SARConfig
from .oscal_sar import build_sar, write_sar, sar_summary


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m sar_generator",
        description=(
            "Generate an OSCAL v1.2.1 Security Assessment Results (SAR) "
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
        help=(
            "Path to the Nessus Compliance .qvd file (Policy Compliance results). "
            "When provided, compliance observations and control-level evidence are "
            "included in the SAR findings."
        ),
    )

    # --- Config file ---
    p.add_argument(
        "--config", metavar="JSON_FILE", default=None,
        help=(
            "JSON file with SARConfig fields. "
            "CLI flags override values in the config file."
        ),
    )

    # --- Assessment metadata ---
    p.add_argument(
        "--system-name", metavar="NAME", default=None,
        help="Full name of the assessed system.",
    )
    p.add_argument(
        "--org-name", metavar="NAME", default=None,
        help="System owner organisation name.",
    )
    p.add_argument(
        "--assessor", metavar="NAME", default=None,
        help="Name of the assessing organisation.",
    )
    p.add_argument(
        "--sap-href", metavar="HREF", default=None,
        help=(
            "Relative or absolute path / URI to the SAP document. "
            "Example: ../sap/sap_fy25q3.json"
        ),
    )
    p.add_argument(
        "--version", metavar="VER", default=None,
        help='Document version string (default: "1.0").',
    )

    # --- Result metadata ---
    p.add_argument(
        "--result-title", metavar="TITLE", default=None,
        help="Title of the result block (default: CLaaS Automated Assessment Results).",
    )
    p.add_argument(
        "--result-description", metavar="TEXT", default=None,
        help="Description of the result block.",
    )

    # --- Date range ---
    p.add_argument(
        "--start-date", metavar="YYYY-MM-DD", default=None,
        help=(
            "Assessment start date. "
            "Defaults to the earliest scan date found in the QVD."
        ),
    )
    p.add_argument(
        "--end-date", metavar="YYYY-MM-DD", default=None,
        help=(
            "Assessment end date. "
            "Defaults to the latest scan date found in the QVD."
        ),
    )

    # --- Baseline ---
    p.add_argument(
        "--baseline", metavar="URL", default=None,
        help="NIST 800-53 Rev 5 baseline profile URL (must match SSP and SAP).",
    )

    # --- Output ---
    p.add_argument(
        "-o", "--output", metavar="OUTPUT_JSON", default=None,
        help=(
            "Destination JSON file path. "
            "Defaults to <nessus_stem>_sar.json in the current directory."
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


def _build_config(args: argparse.Namespace, cfg_file: dict) -> SARConfig:
    """Merge JSON config file with CLI flag overrides."""
    def _pick(attr: str, default):
        val = getattr(args, attr, None)
        if val is not None:
            return val
        return cfg_file.get(attr, default)

    cfg = SARConfig()
    cfg.system_name      = _pick("system_name",      cfg.system_name)
    cfg.org_name         = _pick("org_name",          cfg.org_name)
    cfg.assessor_name    = _pick("assessor",          cfg.assessor_name)
    cfg.sap_href         = _pick("sap_href",          cfg.sap_href)
    cfg.version          = _pick("version",           cfg.version)
    cfg.start_date       = _pick("start_date",        cfg.start_date)
    cfg.end_date         = _pick("end_date",          cfg.end_date)
    cfg.result_title     = _pick("result_title",      cfg.result_title)
    cfg.result_description = _pick("result_description", cfg.result_description)

    if args.baseline:
        cfg.baseline_profile_href = args.baseline
    elif "baseline_profile_href" in cfg_file:
        cfg.baseline_profile_href = cfg_file["baseline_profile_href"]

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
    Parse arguments, load QVDs, build SAR, write JSON.

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
        Path(args.output) if args.output else Path(f"{nessus_path.stem}_sar.json")
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
            config=config,
        )
    except ImportError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"ERROR reading QVD: {exc}", file=sys.stderr)
        return 3

    ad = data.assessment_data
    print(f"  Hosts found         : {len(ad.system_data.hosts)}")
    print(f"  Unique scan dates   : {len(ad.unique_scan_dates)}")
    print(f"  Unique controls     : {len(ad.unique_controls)}")
    print(f"  Compliance results  : {len(ad.system_data.compliance)}")
    print(f"  Assessment start    : {data.result_start or '(unknown)'}")
    print(f"  Assessment end      : {data.result_end or '(unknown)'}")

    if not ad.system_data.hosts:
        print("No hosts found in QVD. Nothing written.", file=sys.stderr)
        return 4

    # --- Build SAR ---
    print("Building OSCAL SAR document ...")
    sar = build_sar(
        data,
        config,
        nessus_path=str(nessus_path),
        ppsm_path=args.ppsm_qvd,
        software_path=args.software_qvd,
        compliance_path=args.compliance_qvd,
    )

    summary = sar_summary(sar)

    # --- Write output ---
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_sar(sar, str(output_path))

    print(f"Output written : {output_path}")
    print(f"  Document UUID    : {summary['document_uuid']}")
    print(f"  OSCAL version    : {summary['oscal_version']}")
    print(f"  Observations     : {summary['observations']}")
    print(f"  Risks            : {summary['risks']}")
    print(f"  Findings         : {summary['findings']}")
    print(f"    Satisfied      : {summary['satisfied']}")
    print(f"    Not satisfied  : {summary['not_satisfied']}")
    print(f"  Log entries      : {summary['log_entries']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
