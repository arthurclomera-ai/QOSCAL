"""
Command-line interface for the CLaaS OSCAL SSP Generator.

Examples
--------
Minimal — Nessus QVD only:

    python -m ssp_generator Nessus.qvd \\
        --system-name "FSA Cloud (FY25 Q3)" \\
        --org-name    "IPKeys Technologies"

All QVD inputs + full metadata:

    python -m ssp_generator Nessus.qvd \\
        --ppsm-qvd        PPSM.qvd \\
        --software-qvd    Software.qvd \\
        --compliance-qvd  Compliance.qvd \\
        --system-name     "FSA Cloud (FY25 Q3)" \\
        --org-name        "IPKeys Technologies" \\
        --security-level  moderate \\
        --cia             moderate moderate moderate \\
        --output          output/ssp_fy25q3.json

Load system metadata from a JSON config file:

    python -m ssp_generator Nessus.qvd --config system_config.json

The JSON config file mirrors the SystemConfig field names:

    {
      "system_name": "FSA Cloud",
      "org_name":    "IPKeys Technologies",
      "system_description": "Full narrative here...",
      "boundary_description": "Boundary narrative...",
      "confidentiality_impact": "moderate",
      "integrity_impact": "moderate",
      "availability_impact": "moderate",
      "authorization_status": "operational",
      "date_authorized": "2024-09-30",
      "baseline_profile_href": "https://...",
      "information_types": [
        {
          "title": "General Support",
          "description": "...",
          "sp800_60_id": "D.20",
          "confidentiality_impact": "moderate",
          "integrity_impact": "moderate",
          "availability_impact": "moderate"
        }
      ]
    }

Inspect QVD columns without generating output:

    python -m ssp_generator --inspect Nessus.qvd
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .qvd_loader import load_all_qvds
from .system_model import InformationType, SystemConfig
from .oscal_ssp import build_ssp, write_ssp, ssp_summary


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m ssp_generator",
        description=(
            "Generate an OSCAL v1.2.1 System Security Plan (SSP) JSON document "
            "from CLaaS Nessus QVD files."
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
        "--ppsm-qvd",
        metavar="QVD",
        default=None,
        help="Path to the Nessus PPSM .qvd file (port/protocol/service inventory).",
    )
    p.add_argument(
        "--software-qvd",
        metavar="QVD",
        default=None,
        help="Path to the Nessus Software .qvd file (installed software inventory).",
    )
    p.add_argument(
        "--compliance-qvd",
        metavar="QVD",
        default=None,
        help="Path to the Nessus Compliance .qvd file (Policy Compliance results).",
    )

    # --- System config file ---
    p.add_argument(
        "--config",
        metavar="JSON_FILE",
        default=None,
        help=(
            "JSON file containing SystemConfig fields. "
            "CLI flags override values from the config file."
        ),
    )

    # --- System metadata (override or supplement config file) ---
    p.add_argument(
        "--system-name",
        metavar="NAME",
        default=None,
        help='Full system name (e.g. "FSA Cloud FY25 Q3").',
    )
    p.add_argument(
        "--system-name-short",
        metavar="ACRONYM",
        default=None,
        help="Short name / acronym for the system.",
    )
    p.add_argument(
        "--system-description",
        metavar="TEXT",
        default=None,
        help="System description narrative (NIST SP 800-18 §2.1).",
    )
    p.add_argument(
        "--system-id",
        metavar="UUID",
        default=None,
        help=(
            "Explicit UUID for the system-id element. "
            "Generated deterministically from --system-name when omitted."
        ),
    )
    p.add_argument(
        "--org-name",
        metavar="NAME",
        default=None,
        help='Name of the responsible organisation.',
    )
    p.add_argument(
        "--version",
        metavar="VER",
        default=None,
        help='Document version string (default: "1.0").',
    )

    # --- Security categorisation ---
    p.add_argument(
        "--cia",
        nargs=3,
        metavar=("C", "I", "A"),
        default=None,
        help=(
            "FIPS 199 C/I/A impact levels. "
            "Each must be one of: low moderate high. "
            "Example: --cia moderate moderate high"
        ),
    )

    # --- Authorization status ---
    p.add_argument(
        "--auth-status",
        metavar="STATUS",
        default=None,
        choices=[
            "operational", "under-development",
            "under-major-modification", "disposition", "other",
        ],
        help="OSCAL authorization status (default: operational).",
    )
    p.add_argument(
        "--date-authorized",
        metavar="YYYY-MM-DD",
        default=None,
        help="Date system received ATO (YYYY-MM-DD).",
    )

    # --- Baseline profile ---
    p.add_argument(
        "--baseline",
        metavar="URL",
        default=None,
        help=(
            "URL of the NIST 800-53 Rev 5 baseline profile to import. "
            "Defaults to the NIST HIGH baseline profile."
        ),
    )

    # --- Output ---
    p.add_argument(
        "-o", "--output",
        metavar="OUTPUT_JSON",
        default=None,
        help=(
            "Destination JSON file path. "
            "Defaults to <nessus_stem>_ssp.json in the current directory."
        ),
    )

    # --- Utility ---
    p.add_argument(
        "--inspect",
        action="store_true",
        default=False,
        help=(
            "Print column names for each QVD provided and exit without "
            "generating output.  Useful for diagnosing field-name issues."
        ),
    )

    return p


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _load_config_file(path: str) -> dict:
    """Load and return a JSON config file as a dict."""
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _build_system_config(args: argparse.Namespace, config_file: dict) -> SystemConfig:
    """
    Merge config file values with CLI flag overrides into a SystemConfig.

    CLI flags take precedence over the config file.
    """
    def _pick(attr: str, default):
        """Return CLI value if set, else config file value, else default."""
        cli_val = getattr(args, attr.replace("-", "_"), None)
        if cli_val is not None:
            return cli_val
        return config_file.get(attr, default)

    cfg = SystemConfig()

    cfg.system_name       = _pick("system_name",       cfg.system_name)
    cfg.system_name_short = _pick("system_name_short",  cfg.system_name_short)
    cfg.system_id         = _pick("system_id",          cfg.system_id)
    cfg.org_name          = _pick("org_name",            cfg.org_name)
    cfg.version           = _pick("version",             cfg.version)
    cfg.system_description  = _pick("system_description",  cfg.system_description)
    cfg.boundary_description = config_file.get(
        "boundary_description", cfg.boundary_description
    )
    cfg.authorization_status = _pick("auth_status",     cfg.authorization_status)
    cfg.date_authorized   = _pick("date_authorized",    cfg.date_authorized)

    # CIA from --cia flag or config file
    if args.cia:
        c, i, a = [v.lower() for v in args.cia]
        cfg.confidentiality_impact = c
        cfg.integrity_impact       = i
        cfg.availability_impact    = a
    else:
        cfg.confidentiality_impact = config_file.get(
            "confidentiality_impact", cfg.confidentiality_impact
        )
        cfg.integrity_impact = config_file.get(
            "integrity_impact", cfg.integrity_impact
        )
        cfg.availability_impact = config_file.get(
            "availability_impact", cfg.availability_impact
        )

    # Baseline
    if args.baseline:
        cfg.baseline_profile_href = args.baseline
    elif "baseline_profile_href" in config_file:
        cfg.baseline_profile_href = config_file["baseline_profile_href"]

    # Information types from config file
    if "information_types" in config_file:
        cfg.information_types = [
            InformationType(
                title=it.get("title", "Federal Information"),
                description=it.get("description", ""),
                sp800_60_id=it.get("sp800_60_id", ""),
                confidentiality_impact=it.get("confidentiality_impact", "moderate"),
                integrity_impact=it.get("integrity_impact", "moderate"),
                availability_impact=it.get("availability_impact", "moderate"),
            )
            for it in config_file["information_types"]
        ]

    return cfg


# ---------------------------------------------------------------------------
# Inspect mode
# ---------------------------------------------------------------------------

def _inspect_qvds(args: argparse.Namespace) -> int:
    """Print column names for each QVD and return exit code."""
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
            table = QvdTable.from_qvd(str(p))
            df = table.to_pandas()
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
    Parse arguments, load QVDs, build SSP, write JSON.

    Returns:
        Exit code: 0 = success, 1 = bad argument / file not found,
        2 = import error, 3 = QVD read error, 4 = no hosts found.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    nessus_path = Path(args.nessus_qvd)
    if not nessus_path.exists():
        print(f"ERROR: Nessus QVD not found: {nessus_path}", file=sys.stderr)
        return 1

    # ------------------------------------------------------------------
    # --inspect mode
    # ------------------------------------------------------------------
    if args.inspect:
        try:
            return _inspect_qvds(args)
        except ImportError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

    # ------------------------------------------------------------------
    # Output path
    # ------------------------------------------------------------------
    output_path = Path(args.output) if args.output else Path(f"{nessus_path.stem}_ssp.json")

    # ------------------------------------------------------------------
    # Build SystemConfig
    # ------------------------------------------------------------------
    config_file: dict = {}
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"ERROR: Config file not found: {config_path}", file=sys.stderr)
            return 1
        try:
            config_file = _load_config_file(str(config_path))
        except json.JSONDecodeError as exc:
            print(f"ERROR: Invalid JSON in config file: {exc}", file=sys.stderr)
            return 1

    config = _build_system_config(args, config_file)

    # ------------------------------------------------------------------
    # Load QVDs
    # ------------------------------------------------------------------
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

    print(f"  Hosts found         : {len(data.hosts)}")
    print(f"  Port entries        : {len(data.ports)}")
    print(f"  Software entries    : {len(data.software)}")
    print(f"  Compliance results  : {len(data.compliance)}")
    print(f"  Unique controls     : {len(data.all_control_ids)}")

    if not data.hosts:
        print("No hosts found in QVD. Nothing written.", file=sys.stderr)
        return 4

    # ------------------------------------------------------------------
    # Build SSP
    # ------------------------------------------------------------------
    print("Building OSCAL SSP document ...")
    ssp = build_ssp(
        data,
        config,
        nessus_path=str(nessus_path),
        ppsm_path=args.ppsm_qvd,
        software_path=args.software_qvd,
        compliance_path=args.compliance_qvd,
    )

    summary = ssp_summary(ssp)

    # ------------------------------------------------------------------
    # Write output
    # ------------------------------------------------------------------
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_ssp(ssp, str(output_path))

    print(f"Output written : {output_path}")
    print(f"  Document UUID    : {summary['document_uuid']}")
    print(f"  OSCAL version    : {summary['oscal_version']}")
    print(f"  Components       : {summary['components']}")
    print(f"  Inventory items  : {summary['inventory_items']}")
    print(f"  Controls covered : {summary['controls']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
