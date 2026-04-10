"""
Command-line interface for the CLaaS OSCAL POA&M Generator.

Examples
--------
Generate a POA&M from a Nessus QVD (open findings only):

    python -m poam_generator Nessus.qvd

Specify system metadata and output path:

    python -m poam_generator Nessus.qvd \\
        --system-name "FSA Cloud (FY25 Q3)" \\
        --party-name  "IPKeys Technologies" \\
        --output       output/poam_fy25q3.json

List the columns present in a QVD without generating output:

    python -m poam_generator --inspect Nessus.qvd
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .qvd_reader import load_nessus_findings, report_columns
from .mapper import df_to_findings
from .oscal_poam import build_poam, write_poam, poam_summary


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m poam_generator",
        description=(
            "Generate an OSCAL v1.2.1 Plan of Action & Milestones (POA&M) "
            "JSON document from a CLaaS Nessus QVD file."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    p.add_argument(
        "qvd",
        metavar="QVD_FILE",
        help="Path to the Nessus .qvd file produced by the CLaaS QVD Generator.",
    )

    p.add_argument(
        "-o", "--output",
        metavar="OUTPUT_JSON",
        default=None,
        help=(
            "Destination JSON file path. "
            "Defaults to <qvd_stem>_poam.json in the current directory."
        ),
    )

    p.add_argument(
        "--system-name",
        metavar="NAME",
        default="CLaaS Target System",
        help='Human-readable name of the assessed system (default: "CLaaS Target System").',
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
        "--party-name",
        metavar="NAME",
        default="CLaaS Organization",
        help='Name of the responsible organisation (default: "CLaaS Organization").',
    )

    p.add_argument(
        "--version",
        metavar="VER",
        default="1.0",
        help='Document version string written into OSCAL metadata (default: "1.0").',
    )

    p.add_argument(
        "--include-closed",
        action="store_true",
        default=False,
        help="Include STATUS='Closed' findings in the POA&M (default: open only).",
    )

    p.add_argument(
        "--include-info",
        action="store_true",
        default=False,
        help="Include Info/Informational severity findings (default: excluded).",
    )

    p.add_argument(
        "--inspect",
        action="store_true",
        default=False,
        help=(
            "Print the column names present in the QVD file and exit "
            "without generating output. Useful for diagnosing field-name issues."
        ),
    )

    return p


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """Parse arguments, load QVD, build POA&M, write JSON.

    Returns:
        Exit code: 0 = success, 1 = bad argument, 2 = import error,
        3 = QVD read error, 4 = no eligible findings.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    qvd_path = Path(args.qvd)
    if not qvd_path.exists():
        print(f"ERROR: QVD file not found: {qvd_path}", file=sys.stderr)
        return 1

    # ------------------------------------------------------------------
    # --inspect mode: print columns and exit
    # ------------------------------------------------------------------
    if args.inspect:
        try:
            cols = report_columns(str(qvd_path))
        except ImportError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        except Exception as exc:
            print(f"ERROR reading QVD: {exc}", file=sys.stderr)
            return 3

        print(f"Columns in {qvd_path.name} ({len(cols)} total):")
        for c in cols:
            print(f"  {c}")
        return 0

    # ------------------------------------------------------------------
    # Determine output path
    # ------------------------------------------------------------------
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = Path(f"{qvd_path.stem}_poam.json")

    # ------------------------------------------------------------------
    # Load and filter the QVD
    # ------------------------------------------------------------------
    print(f"Reading QVD : {qvd_path}")

    try:
        df = load_nessus_findings(
            str(qvd_path),
            include_closed=args.include_closed,
            include_info=args.include_info,
        )
    except ImportError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"ERROR reading QVD: {exc}", file=sys.stderr)
        return 3

    print(f"  Eligible findings : {len(df)}")

    if df.empty:
        print("No eligible findings to include in POA&M. Nothing written.")
        return 4

    # ------------------------------------------------------------------
    # Build OSCAL POA&M
    # ------------------------------------------------------------------
    print("Building OSCAL POA&M document ...")
    findings = df_to_findings(df)

    poam = build_poam(
        findings,
        system_name=args.system_name,
        system_id=args.system_id,
        party_name=args.party_name,
        version=args.version,
    )

    summary = poam_summary(poam)

    # ------------------------------------------------------------------
    # Write output
    # ------------------------------------------------------------------
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_poam(poam, str(output_path))

    print(f"Output written : {output_path}")
    print(f"  Document UUID  : {summary['document_uuid']}")
    print(f"  OSCAL version  : {summary['oscal_version']}")
    print(f"  Observations   : {summary['observations']}")
    print(f"  Risks          : {summary['risks']}  (unique plugins)")
    print(f"  POA&M items    : {summary['poam_items']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
