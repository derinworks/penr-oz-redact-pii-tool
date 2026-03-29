from __future__ import annotations

from pathlib import Path

import fitz
import pytesseract
from pdf2image import convert_from_path

from .detector import WordBox


def extract_ocr_words(pdf_path: str | Path, page_number: int, page_rect: fitz.Rect) -> list[WordBox]:
    images = convert_from_path(
        str(pdf_path),
        dpi=200,
        first_page=page_number + 1,
        last_page=page_number + 1,
        single_file=True,
    )
    if not images:
        return []

    image = images[0]
    data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
    width, height = image.size
    x_scale = page_rect.width / width
    y_scale = page_rect.height / height

    results: list[WordBox] = []
    for idx, text in enumerate(data["text"]):
        value = text.strip()
        if not value:
            continue

        x = data["left"][idx] * x_scale
        y = data["top"][idx] * y_scale
        w = data["width"][idx] * x_scale
        h = data["height"][idx] * y_scale
        rect = fitz.Rect(
            page_rect.x0 + x,
            page_rect.y0 + y,
            page_rect.x0 + x + w,
            page_rect.y0 + y + h,
        )
        results.append(
            WordBox(
                text=value,
                rect=rect,
                line_key=(int(data["block_num"][idx]), int(data["line_num"][idx])),
            )
        )
    return results
