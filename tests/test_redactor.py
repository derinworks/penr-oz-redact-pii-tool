from __future__ import annotations

from pathlib import Path

import fitz

from pii_redact.redactor import redact_pdf


def _make_text_pdf(path: Path, text: str) -> None:
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), text, fontsize=12)
    document.save(path)
    document.close()


def test_redact_pdf_removes_extractable_ssn_and_email(tmp_path: Path) -> None:
    source = tmp_path / "input.pdf"
    output = tmp_path / "output.pdf"
    _make_text_pdf(
        source,
        "Employee SSN 123-45-6789 Email jane.doe@example.com Phone (555) 123-4567",
    )

    result = redact_pdf(source, output, pii_types=["ssn", "email", "phone"])

    assert result.total_redactions >= 3

    with fitz.open(output) as redacted_doc:
        text = "\n".join(page.get_text() for page in redacted_doc)
        assert "123-45-6789" not in text
        assert "jane.doe@example.com" not in text
        assert "(555) 123-4567" not in text


def test_redact_pdf_can_limit_detection_types(tmp_path: Path) -> None:
    source = tmp_path / "input.pdf"
    output = tmp_path / "output.pdf"
    _make_text_pdf(
        source,
        "Employee SSN 123-45-6789 EIN 12-3456789 Email jane.doe@example.com",
    )

    result = redact_pdf(source, output, pii_types=["ein"])

    assert result.total_redactions == 1

    with fitz.open(output) as redacted_doc:
        text = "\n".join(page.get_text() for page in redacted_doc)
        assert "12-3456789" not in text
        assert "123-45-6789" in text
        assert "jane.doe@example.com" in text
