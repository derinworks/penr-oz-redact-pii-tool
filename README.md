# penr-oz-redact-pii-tool

Offline CLI tool to securely redact PII from PDF tax-like documents using Python.

## Features

- Secure PDF redaction using PyMuPDF `add_redact_annot` plus `apply_redactions`
- Regex-based detection for `ssn`, `ein`, `email`, and `phone`
- Word-level extraction with line reconstruction to catch multi-token matches
- Optional OCR fallback for scanned pages using `pdf2image` and `pytesseract`
- Local-only processing with no external API calls

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

OCR fallback also requires native tools:

- `tesseract` must be installed and available on `PATH`
- `poppler` must be installed so `pdf2image` can render PDF pages

## Usage

```bash
pii-redact input.pdf --output out.pdf
pii-redact input.pdf --output out.pdf --types ssn,email,phone --ocr-fallback
pii-redact input.pdf --output out.pdf --types ein
```

Defaults:

- PII types: `ssn,email,phone`
- OCR fallback: disabled

## Development

Run tests with:

```bash
pytest
```
