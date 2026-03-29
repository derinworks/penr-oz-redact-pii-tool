from __future__ import annotations

from dataclasses import dataclass
import re
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


@dataclass(frozen=True)
class LineData:
    words: list[WordBox]
    text: str
    spans: list[tuple[int, int]]


LABEL_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "name": (
        re.compile(r"\bemployee name\b", re.IGNORECASE),
        re.compile(r"\bemployee'?s first name and (?:middle )?initial\b", re.IGNORECASE),
        re.compile(r"\bfirst name(?: and (?:middle )?initial)?\b", re.IGNORECASE),
        re.compile(r"\blast name\b", re.IGNORECASE),
        re.compile(r"\bfull name\b", re.IGNORECASE),
        re.compile(r"\bname\b", re.IGNORECASE),
    ),
    "address": (
        re.compile(r"\bemployee address\b", re.IGNORECASE),
        re.compile(r"\bstreet address\b", re.IGNORECASE),
        re.compile(r"\baddress\b", re.IGNORECASE),
    ),
    "zip": (
        re.compile(r"\bzip code\b", re.IGNORECASE),
        re.compile(r"\bpostal code\b", re.IGNORECASE),
        re.compile(r"\bzip\b", re.IGNORECASE),
    ),
    "state_id": (
        re.compile(r"\bemployer'?s state id number\b", re.IGNORECASE),
        re.compile(r"\bstate id number\b", re.IGNORECASE),
        re.compile(r"\bstate id\b", re.IGNORECASE),
    ),
    "control_number": (
        re.compile(r"\bcontrol number\b", re.IGNORECASE),
    ),
}

EIN_HINT_PATTERN = re.compile(
    r"\b(?:ein|tin|employer(?:'s)? (?:id|identification) number|federal id)\b",
    re.IGNORECASE,
)
STREET_ADDRESS_PATTERN = re.compile(
    r"\b\d+[A-Za-z0-9./#-]*\s+(?:[A-Za-z0-9.'#-]+\s+){0,6}"
    r"(?:street|st|road|rd|avenue|ave|boulevard|blvd|lane|ln|drive|dr|court|ct|"
    r"circle|cir|place|pl|way|terrace|ter|parkway|pkwy)\b",
    re.IGNORECASE,
)
CITY_STATE_ZIP_PATTERN = re.compile(
    r"\b[A-Za-z][A-Za-z .'-]+,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?\b"
)
DIRECT_PATTERN_TYPES = {"ssn", "ein", "email", "phone"}


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
    lines = _build_lines(words)

    detections: list[Detection] = []
    detections.extend(_detect_word_level(words, pii_types, source))
    detections.extend(_detect_line_patterns(lines, pii_types, source))
    detections.extend(_detect_labeled_fields(lines, pii_types, source))
    detections.extend(_detect_address_lines(lines, pii_types, source))
    detections.extend(_detect_split_numeric_fields(lines, pii_types, source))
    return _dedupe_detections(detections)


def _detect_word_level(
    words: list[WordBox],
    pii_types: list[str],
    source: str,
) -> list[Detection]:
    detections: list[Detection] = []
    for word in words:
        for pii_type in pii_types:
            if pii_type not in DIRECT_PATTERN_TYPES:
                continue
            pattern = PII_PATTERNS.get(pii_type)
            if pattern and pattern.fullmatch(word.text):
                detections.append(
                    Detection(
                        pii_type=pii_type,
                        value=word.text,
                        rect=word.rect,
                        source=source,
                    )
                )
    return detections


def _detect_line_patterns(
    lines: list[LineData],
    pii_types: list[str],
    source: str,
) -> list[Detection]:
    detections: list[Detection] = []
    for line in lines:
        for pii_type in pii_types:
            if pii_type not in DIRECT_PATTERN_TYPES:
                continue
            pattern = PII_PATTERNS.get(pii_type)
            if not pattern:
                continue
            for match in pattern.finditer(line.text):
                matched_words = _words_covering_span(line, match.start(), match.end())
                if not matched_words:
                    continue
                detections.append(
                    Detection(
                        pii_type=pii_type,
                        value=match.group(0),
                        rect=_union_rect(word.rect for word in matched_words),
                        source=source,
                    )
                )
    return detections


def _detect_labeled_fields(
    lines: list[LineData],
    pii_types: list[str],
    source: str,
) -> list[Detection]:
    detections: list[Detection] = []
    for line in lines:
        for pii_type in pii_types:
            for label_pattern in LABEL_PATTERNS.get(pii_type, ()):
                for match in label_pattern.finditer(line.text):
                    value_start = _skip_separators(line.text, match.end())
                    value_end = _trim_trailing_separators(line.text, value_start, len(line.text))
                    if value_start >= value_end:
                        continue
                    matched_words = _words_covering_span(line, value_start, value_end)
                    matched_words = _trim_labeled_value_words(matched_words, pii_type)
                    if not matched_words:
                        continue
                    detections.append(
                        Detection(
                            pii_type=pii_type,
                            value=" ".join(word.text for word in matched_words),
                            rect=_union_rect(word.rect for word in matched_words),
                            source=source,
                        )
                    )
    return detections


def _detect_address_lines(
    lines: list[LineData],
    pii_types: list[str],
    source: str,
) -> list[Detection]:
    if "address" not in pii_types:
        return []

    detections: list[Detection] = []
    for line in lines:
        if STREET_ADDRESS_PATTERN.search(line.text) or CITY_STATE_ZIP_PATTERN.search(line.text):
            detections.append(
                Detection(
                    pii_type="address",
                    value=line.text,
                    rect=_union_rect(word.rect for word in line.words),
                    source=source,
                )
            )
    return detections


def _trim_labeled_value_words(words: list[WordBox], pii_type: str) -> list[WordBox]:
    trimmed = list(words)
    if pii_type == "zip":
        trimmed = [word for word in trimmed if PII_PATTERNS["zip"].fullmatch(word.text)]
    elif pii_type in {"state_id", "control_number"}:
        while trimmed and not re.search(r"\d", trimmed[0].text):
            trimmed.pop(0)
        while trimmed and not re.search(r"\d", trimmed[-1].text):
            trimmed.pop()
    return trimmed


def _detect_split_numeric_fields(
    lines: list[LineData],
    pii_types: list[str],
    source: str,
) -> list[Detection]:
    detections: list[Detection] = []
    for line in lines:
        if "ssn" in pii_types:
            detections.extend(
                _scan_digit_sequences(
                    line,
                    source=source,
                    pii_type="ssn",
                    target_length=9,
                    valid_partitions={(3, 2, 4)},
                    require_hint=False,
                )
            )
        if "ein" in pii_types:
            detections.extend(
                _scan_digit_sequences(
                    line,
                    source=source,
                    pii_type="ein",
                    target_length=9,
                    valid_partitions={(2, 7)},
                    require_hint=not EIN_HINT_PATTERN.search(line.text),
                )
            )
    return detections


def _scan_digit_sequences(
    line: LineData,
    source: str,
    pii_type: str,
    target_length: int,
    valid_partitions: set[tuple[int, ...]],
    require_hint: bool,
) -> list[Detection]:
    if require_hint:
        return []

    detections: list[Detection] = []
    digit_indices = [index for index, word in enumerate(line.words) if word.text.isdigit()]
    for start_pos, start_index in enumerate(digit_indices):
        selected: list[WordBox] = []
        lengths: list[int] = []
        expected = start_index
        total = 0
        for index in digit_indices[start_pos:]:
            if index != expected:
                break
            word = line.words[index]
            selected.append(word)
            lengths.append(len(word.text))
            total += len(word.text)
            expected += 1
            if total == target_length:
                if tuple(lengths) in valid_partitions or (
                    pii_type == "ein" and len(selected) > 1 and all(len(word.text) == 1 for word in selected)
                ):
                    detections.append(
                        Detection(
                            pii_type=pii_type,
                            value="".join(word.text for word in selected),
                            rect=_union_rect(word.rect for word in selected),
                            source=source,
                        )
                    )
                break
            if total > target_length:
                break
    return detections


def _build_lines(words: list[WordBox]) -> list[LineData]:
    grouped: dict[tuple[int, int], list[WordBox]] = {}
    for word in words:
        grouped.setdefault(word.line_key, []).append(word)

    lines: list[LineData] = []
    for line_words in grouped.values():
        sorted_words = sorted(line_words, key=lambda item: (item.rect.y0, item.rect.x0))
        parts: list[str] = []
        spans: list[tuple[int, int]] = []
        cursor = 0
        for index, word in enumerate(sorted_words):
            if index:
                parts.append(" ")
                cursor += 1
            start = cursor
            parts.append(word.text)
            cursor += len(word.text)
            spans.append((start, cursor))
        lines.append(LineData(words=sorted_words, text="".join(parts), spans=spans))
    return lines


def _words_covering_span(line: LineData, start: int, end: int) -> list[WordBox]:
    matched_words: list[WordBox] = []
    for word, (word_start, word_end) in zip(line.words, line.spans):
        if word_end > start and word_start < end:
            matched_words.append(word)
    return matched_words


def _skip_separators(text: str, offset: int) -> int:
    while offset < len(text) and text[offset] in " :-":
        offset += 1
    return offset


def _trim_trailing_separators(text: str, start: int, end: int) -> int:
    while end > start and text[end - 1] in " :-":
        end -= 1
    return end


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
