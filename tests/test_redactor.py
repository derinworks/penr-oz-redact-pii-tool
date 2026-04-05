from __future__ import annotations

from pathlib import Path

import fitz

from pii_redact.detector import (
    _build_lines,
    _classify_widget_value,
    _looks_like_widget_value,
    detect_pii,
    extract_page_words,
)
from pii_redact.redactor import redact_pdf


def _make_text_pdf(path: Path, text: str) -> None:
    document = fitz.open()
    page = document.new_page()
    page.insert_textbox(fitz.Rect(72, 72, 540, 760), text, fontsize=12)
    document.save(path)
    document.close()


def _add_text_widget(
    page: fitz.Page,
    rect: fitz.Rect,
    field_name: str,
    value: str,
) -> None:
    widget = fitz.Widget()
    widget.field_name = field_name
    widget.field_type = fitz.PDF_WIDGET_TYPE_TEXT
    widget.rect = rect
    widget.field_value = value
    page.add_widget(widget)


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


def test_detect_pii_separates_first_and_last_name_fields() -> None:
    document = fitz.open()
    page = document.new_page()
    page.insert_textbox(
        fitz.Rect(72, 72, 540, 200),
        "First name John Last name Doe",
        fontsize=12,
    )

    detections = detect_pii(extract_page_words(page), ["name"], "text")
    document.close()

    values = {detection.value for detection in detections}
    assert "John" in values
    assert "Doe" in values
    assert all("Last name" not in detection.value for detection in detections)
    assert all("First name" not in detection.value for detection in detections)


def test_redact_pdf_redacts_company_name_address_columns_and_payer_state(tmp_path: Path) -> None:
    source = tmp_path / "input.pdf"
    output = tmp_path / "output.pdf"
    _make_text_pdf(
        source,
        "\n".join(
            [
                "Company name / Trade / Business / Aggregation name",
                "Acme Holdings LLC",
                "Physical address",
                "123 Main Street",
                "Suite 9",
                "Payer's state no.",
                "CA-98765",
                "Control number",
                "CN7788",
                "EIN",
                "1 2 2 3 4 2 3 4 5",
            ]
        ),
    )

    redact_pdf(source, output)

    with fitz.open(output) as redacted_doc:
        text = "\n".join(page.get_text() for page in redacted_doc)
        assert "Acme Holdings LLC" not in text
        assert "123 Main Street" not in text
        assert "Suite 9" not in text
        assert "CA-98765" not in text
        assert "CN7788" not in text
        assert "1 2 2 3 4 2 3 4 5" not in text


def test_redact_pdf_redacts_values_under_pii_table_headers(tmp_path: Path) -> None:
    source = tmp_path / "input.pdf"
    output = tmp_path / "output.pdf"
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), "Name", fontsize=12)
    page.insert_text((230, 72), "Control number", fontsize=12)
    page.insert_text((72, 96), "Jane Public", fontsize=12)
    page.insert_text((230, 96), "W2-4455", fontsize=12)
    page.insert_text((72, 120), "Form 1040 Title", fontsize=12)
    document.save(source)
    document.close()

    redact_pdf(source, output)

    with fitz.open(output) as redacted_doc:
        text = "\n".join(page.get_text() for page in redacted_doc)
        assert "Jane Public" not in text
        assert "W2-4455" not in text
        assert "Form 1040 Title" in text


def test_widget_value_allows_joint_names_and_numeric_control_numbers() -> None:
    assert _looks_like_widget_value("John Doe & Betty Doe", "name")
    assert _looks_like_widget_value("778899001", "control_number")


def test_widget_classification_prefers_name_over_nearby_control_label() -> None:
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), "d Control number", fontsize=12)
    page.insert_text((72, 96), "e Employee's first name and initial", fontsize=12)

    lines = _build_lines(extract_page_words(page))
    pii_type = _classify_widget_value(
        "John Doe & Betty Doe",
        fitz.Rect(72, 110, 210, 122),
        lines,
        "FirstName_ReadOrder",
        ["name", "address", "zip", "state_id", "control_number"],
    )
    document.close()

    assert pii_type == "name"


def test_widget_classification_prefers_address_over_nearby_zip_label() -> None:
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), "Physical address of each property (street, city, state, ZIP code)", fontsize=12)

    lines = _build_lines(extract_page_words(page))
    pii_type = _classify_widget_value(
        "123 Main Street, Sometown, CA 01234",
        fitz.Rect(72, 86, 360, 98),
        lines,
        "Table_Line1a.RowA",
        ["name", "address", "zip", "state_id", "control_number"],
    )
    document.close()

    assert pii_type == "address"


def test_redact_pdf_redacts_printed_names_shown_and_ssn(tmp_path: Path) -> None:
    source = tmp_path / "printed-names.pdf"
    output = tmp_path / "printed-names-redacted.pdf"
    _make_text_pdf(
        source,
        "\n".join(
            [
                "Name(s) shown on Form 1040, 1040-SR, or 1040-NR",
                "J OHN H DOE & BETTY DOE",
                "Your social security number",
                "111-22-3333",
            ]
        ),
    )

    redact_pdf(source, output)

    with fitz.open(output) as redacted_doc:
        text = "\n".join(page.get_text() for page in redacted_doc)
        assert "J OHN H DOE & BETTY DOE" not in text
        assert "111-22-3333" not in text


def test_redact_pdf_redacts_printed_dependent_name_and_ssn_columns(tmp_path: Path) -> None:
    source = tmp_path / "printed-dependent.pdf"
    output = tmp_path / "printed-dependent-redacted.pdf"
    _make_text_pdf(
        source,
        "\n".join(
            [
                "Dependents",
                "(1) First name",
                "SMALL",
                "(2) Last name",
                "DOE",
                "(3) SSN",
                "3 3 3 4 4 5 5 5 5",
            ]
        ),
    )

    redact_pdf(source, output)

    with fitz.open(output) as redacted_doc:
        text = "\n".join(page.get_text() for page in redacted_doc)
        assert "SMALL" not in text
        assert "DOE" not in text
        assert "3 3 3 4 4 5 5 5 5" not in text


def test_redact_pdf_redacts_printed_recipient_name(tmp_path: Path) -> None:
    source = tmp_path / "printed-1099r.pdf"
    output = tmp_path / "printed-1099r-redacted.pdf"
    _make_text_pdf(
        source,
        "\n".join(
            [
                "RECIPIENT'S name",
                "J OHN H DOE",
            ]
        ),
    )

    redact_pdf(source, output)

    with fitz.open(output) as redacted_doc:
        text = "\n".join(page.get_text() for page in redacted_doc)
        assert "J OHN H DOE" not in text


def test_widget_classification_redacts_identifying_number_as_ssn() -> None:
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), "Identifying number", fontsize=12)

    lines = _build_lines(extract_page_words(page))
    pii_type = _classify_widget_value(
        "111223333",
        fitz.Rect(72, 86, 180, 98),
        lines,
        "f1_3",
        ["name", "address", "zip", "ssn", "ein", "state_id", "control_number"],
    )
    document.close()

    assert pii_type == "ssn"


def test_widget_classification_redacts_taxpayer_identification_number_as_ssn() -> None:
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), "Your taxpayer identification number", fontsize=12)

    lines = _build_lines(extract_page_words(page))
    pii_type = _classify_widget_value(
        "111223333",
        fitz.Rect(72, 86, 180, 98),
        lines,
        "f1_2",
        ["name", "address", "zip", "ssn", "ein", "state_id", "control_number"],
    )
    document.close()

    assert pii_type == "ssn"


def test_redact_pdf_on_widget_pages_still_redacts_printed_issue_fields(tmp_path: Path) -> None:
    source = tmp_path / "widget-page-printed-pii.pdf"
    output = tmp_path / "widget-page-printed-pii-redacted.pdf"
    document = fitz.open()
    page = document.new_page()
    page.insert_textbox(
        fitz.Rect(72, 72, 540, 760),
        "\n".join(
            [
                "(3) SSN",
                "111 22 3333",
                "Physical address of each property",
                "123 Main Street",
                "PAYER'S address",
                "456 Oak Road",
                "SCHEDULE C: Acme Holdings LLC",
                "Control number",
                "AB1234",
            ]
        ),
        fontsize=12,
    )
    _add_text_widget(page, fitz.Rect(360, 72, 500, 90), "non_pii_note", "")
    document.save(source)
    document.close()

    result = redact_pdf(source, output)

    assert result.total_redactions >= 5

    with fitz.open(output) as redacted_doc:
        text = "\n".join(page.get_text() for page in redacted_doc)
        assert "111 22 3333" not in text
        assert "123 Main Street" not in text
        assert "456 Oak Road" not in text
        assert "Acme Holdings LLC" not in text
        assert "AB1234" not in text


def test_redact_pdf_redacts_split_dependent_ssn_widgets(tmp_path: Path) -> None:
    source = tmp_path / "split-dependent-ssn.pdf"
    output = tmp_path / "split-dependent-ssn-redacted.pdf"
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), "(3) SSN", fontsize=12)
    _add_text_widget(page, fitz.Rect(72, 86, 110, 104), "table_dependents.row1.ssn_1", "111")
    _add_text_widget(page, fitz.Rect(116, 86, 145, 104), "table_dependents.row1.ssn_2", "22")
    _add_text_widget(page, fitz.Rect(151, 86, 205, 104), "table_dependents.row1.ssn_3", "3333")
    document.save(source)
    document.close()

    result = redact_pdf(source, output, pii_types=["ssn"])

    assert result.total_redactions >= 3

    with fitz.open(output) as redacted_doc:
        assert list(redacted_doc[0].widgets() or []) == []


def test_detect_pii_redacts_labeled_same_row_split_dependent_ssn() -> None:
    document = fitz.open()
    page = document.new_page()
    page.insert_text((93, 336), "SSN (3)        297  51  4004", fontsize=12)

    detections = detect_pii(extract_page_words(page), ["ssn"], "text")
    document.close()

    values = {detection.value for detection in detections}
    assert any("297" in value and "4004" in value for value in values)


def test_detect_pii_redacts_schedule_e_mac_style_address_line() -> None:
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), "Physical address of each property (street, city, state, ZIP code)", fontsize=12)
    page.insert_text((72, 108), "561 BROADWAY B2, SOMERVILLE, MA, 02145", fontsize=12)

    detections = detect_pii(extract_page_words(page), ["address"], "text")
    document.close()

    values = {detection.value for detection in detections}
    assert any("561 BROADWAY B2" in value and "02145" in value for value in values)


def test_detect_pii_redacts_1099r_payer_po_box_address() -> None:
    document = fitz.open()
    page = document.new_page()
    page.insert_text(
        (54, 48),
        "PAYER'S name, street address, city or town, state or province, country, ZIP or foreign postal code, and telephone no.",
        fontsize=10,
    )
    page.insert_text((55, 84), "PO BOX 173764 D999", fontsize=12)

    detections = detect_pii(extract_page_words(page), ["address"], "text")
    document.close()

    values = {detection.value for detection in detections}
    assert "PO BOX 173764 D999" in values


def test_detect_pii_redacts_w2_numeric_control_number_and_city_zip_above_label() -> None:
    document = fitz.open()
    page = document.new_page()
    page.insert_text((50, 158), "Control number", fontsize=12)
    page.insert_text((41, 168), "1178270", fontsize=12)
    page.insert_text((41, 228), "BELMONT, MA - 02478", fontsize=12)
    page.insert_text((48, 278), "Employee's address and ZIP code", fontsize=12)

    detections = detect_pii(extract_page_words(page), ["address", "control_number"], "text")
    document.close()

    by_type = {(detection.pii_type, detection.value) for detection in detections}
    assert ("control_number", "1178270") in by_type
    assert any(
        pii_type == "address" and "BELMONT, MA - 02478" in value
        for pii_type, value in by_type
    )
