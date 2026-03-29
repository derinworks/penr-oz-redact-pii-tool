from __future__ import annotations

from pathlib import Path

import fitz

from pii_redact.redactor import redact_pdf


def _make_text_pdf(path: Path, text: str) -> None:
    document = fitz.open()
    page = document.new_page()
    page.insert_textbox(fitz.Rect(72, 72, 540, 760), text, fontsize=12)
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


def test_redact_pdf_defaults_cover_tax_document_fields(tmp_path: Path) -> None:
    source = tmp_path / "input.pdf"
    output = tmp_path / "output.pdf"
    _make_text_pdf(
        source,
        "\n".join(
            [
                "Employee name John Q Public",
                "Address 123 Main Street",
                "Springfield, NY 12345",
                "Employer's state ID number NY-12345",
                "Control number AB1234",
            ]
        ),
    )

    result = redact_pdf(source, output)

    assert result.total_redactions >= 5

    with fitz.open(output) as redacted_doc:
        text = "\n".join(page.get_text() for page in redacted_doc)
        assert "John Q Public" not in text
        assert "123 Main Street" not in text
        assert "12345" not in text
        assert "NY-12345" not in text
        assert "AB1234" not in text


def test_redact_pdf_redacts_split_ssn_and_ein_fields(tmp_path: Path) -> None:
    source = tmp_path / "input.pdf"
    output = tmp_path / "output.pdf"
    _make_text_pdf(
        source,
        "\n".join(
            [
                "SSN 111 22 3333",
                "Employer identification number 1 2 2 3 4 2 3 4 5",
                "TIN 11-2223334",
            ]
        ),
    )

    result = redact_pdf(source, output, pii_types=["ssn", "ein"])

    assert result.total_redactions >= 3

    with fitz.open(output) as redacted_doc:
        text = "\n".join(page.get_text() for page in redacted_doc)
        assert "111 22 3333" not in text
        assert "1 2 2 3 4 2 3 4 5" not in text
        assert "11-2223334" not in text


def test_redact_pdf_preserves_form_titles_and_instruction_lines(tmp_path: Path) -> None:
    source = tmp_path / "input.pdf"
    output = tmp_path / "output.pdf"
    _make_text_pdf(
        source,
        "\n".join(
            [
                "Form 1040 U.S. Individual Income Tax Return",
                "Schedule 1 Additional Income and Adjustments to Income",
                "Control number AB1234",
                "Employer's state ID number NY-12345",
            ]
        ),
    )

    redact_pdf(source, output)

    with fitz.open(output) as redacted_doc:
        text = "\n".join(page.get_text() for page in redacted_doc)
        assert "Form 1040" in text
        assert "Schedule 1" in text
        assert "AB1234" not in text
        assert "NY-12345" not in text
