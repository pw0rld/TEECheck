from __future__ import annotations

import argparse
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tee-usage-scanner",
        description="Prototype CLI for the TEE usage scanner project.",
    )
    parser.add_argument(
        "--show-outline",
        action="store_true",
        help="Print the location of the scanner outline document.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[2]
    outline_path = project_root / "docs" / "SCANNER_OUTLINE.md"

    if args.show_outline:
        print(outline_path)
        return

    print("TEE Usage Scanner prototype")
    print(f"Project root: {project_root}")
    print(f"Outline: {outline_path}")
    print("Status: planning scaffold only")


if __name__ == "__main__":
    main()
