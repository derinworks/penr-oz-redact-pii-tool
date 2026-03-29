from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import fitz

from .patterns import PII_PATTERNS


@dataclass(frozen=True)
class WordBox:
    text: str
    rect: fitz.Rect
    line_key: tuple[int, int]


@dataclass(frozen=True)
class Detection:
    pii_type: str
    value: str
    rect: fitz.Rect
    source: str


def extract_page_words(page: fitz.Page) -> list[WordBox]:
    words = page.get_text("words")
    results: list[WordBox] = []
    for x0, y0, x1, y1, text, block_no, line_no, _word_no in words:
        if not text.strip():
            continue
        results.append(
            WordBox(
                text=text,
                rect=fitz.Rect(x0, y0, x1, y1),
                line_key=(int(block_no), int(line_no)),
            )
        )
    return results


def detect_pii(
    word_boxes: Iterable[WordBox],
    pii_types: list[str],
    source: str,
) -> list[Detection]:
    words = list(word_boxes)
    detections: list[Detection] = []
    detections.extend(_detect_word_level(words, pii_types, source))
    detections.extend(_detect_line_level(words, pii_types, source))
    return _dedupe_detections(detections)


def _detect_word_level(
    words: list[WordBox],
    pii_types: list[str],
    source: str,
) -> list[Detection]:
    detections: list[Detection] = []
    for word in words:
        for pii_type in pii_types:
            if PII_PATTERNS[pii_type].fullmatch(word.text):
                detections.append(
                    Detection(
                        pii_type=pii_type,
                        value=word.text,
                        rect=word.rect,
                        source=source,
                    )
                )
    return detections


def _detect_line_level(
    words: list[WordBox],
    pii_types: list[str],
    source: str,
) -> list[Detection]:
    lines: dict[tuple[int, int], list[WordBox]] = {}
    for word in words:
        lines.setdefault(word.line_key, []).append(word)

    detections: list[Detection] = []
    for line_words in lines.values():
        sorted_words = sorted(line_words, key=lambda item: (item.rect.y0, item.rect.x0))
        line_text = " ".join(word.text for word in sorted_words)
        for pii_type in pii_types:
            for match in PII_PATTERNS[pii_type].finditer(line_text):
                target = match.group(0)
                matched_words = _words_covering_span(sorted_words, line_text, match.start(), match.end())
                if not matched_words:
                    continue
                detections.append(
                    Detection(
                        pii_type=pii_type,
                        value=target,
                        rect=_union_rect(word.rect for word in matched_words),
                        source=source,
                    )
                )
    return detections


def _words_covering_span(
    words: list[WordBox],
    line_text: str,
    start: int,
    end: int,
) -> list[WordBox]:
    matched_words: list[WordBox] = []
    cursor = 0
    for index, word in enumerate(words):
        word_start = cursor
        word_end = cursor + len(word.text)
        if word_end > start and word_start < end:
            matched_words.append(word)
        cursor = word_end
        if index < len(words) - 1:
            cursor += 1
    return matched_words


def _union_rect(rects: Iterable[fitz.Rect]) -> fitz.Rect:
    rect_list = list(rects)
    if not rect_list:
        raise ValueError("Cannot union an empty collection of rectangles.")
    result = fitz.Rect(rect_list[0])
    for rect in rect_list[1:]:
        result.include_rect(rect)
    return result


def _dedupe_detections(detections: list[Detection]) -> list[Detection]:
    seen: set[tuple[str, str, int, int, int, int]] = set()
    deduped: list[Detection] = []
    for detection in detections:
        key = (
            detection.pii_type,
            detection.value,
            round(detection.rect.x0),
            round(detection.rect.y0),
            round(detection.rect.x1),
            round(detection.rect.y1),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(detection)
    return deduped
