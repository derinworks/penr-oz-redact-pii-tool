from __future__ import annotations

import argparse
from pathlib import Path

from .patterns import DEFAULT_PII_TYPES, SUPPORTED_PII_TYPES
from .redactor import redact_pdf


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pii-redact",
        description="Securely redact PII from PDFs using PyMuPDF with optional OCR fallback.",
    )
    parser.add_argument("input_pdf", help="Path to the source PDF.")
    parser.add_argument(
        "--output",
        required=True,
        help="Path for the redacted PDF.",
    )
    parser.add_argument(
        "--types",
        default=",".join(DEFAULT_PII_TYPES),
        help=f"Comma-separated PII types to redact. Supported: {', '.join(SUPPORTED_PII_TYPES)}.",
    )
    parser.add_argument(
        "--ocr-fallback",
        action="store_true",
        help="Run OCR on pages with no extractable text.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    pii_types = [item.strip() for item in args.types.split(",") if item.strip()]
    result = redact_pdf(
        input_path=Path(args.input_pdf),
        output_path=Path(args.output),
        pii_types=pii_types,
        ocr_fallback=args.ocr_fallback,
    )

    print(
        f"Redacted {result.total_redactions} item(s) across {len(result.pages)} page(s) "
        f"to {result.output_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
