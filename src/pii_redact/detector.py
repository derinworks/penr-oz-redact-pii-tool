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
class WidgetDetection:
    detection: Detection
    xref: int


@dataclass(frozen=True)
class LineData:
    key: tuple[int, int]
    words: list[WordBox]
    text: str
    spans: list[tuple[int, int]]
    rect: fitz.Rect


LABEL_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "name": (
        re.compile(r"\bname\(s\) shown on (?:form|your tax return|return)\b", re.IGNORECASE),
        re.compile(r"\bname of person with self-employment income\b", re.IGNORECASE),
        re.compile(r"\brecipient(?:'|’)?s name\b", re.IGNORECASE),
        re.compile(r"\bpayer(?:'|’)?s name\b", re.IGNORECASE),
        re.compile(r"\bemployer(?:'|’)?s name\b", re.IGNORECASE),
        re.compile(r"\bname of employer\b", re.IGNORECASE),
        re.compile(r"\bemployee(?:'|’)?s first name and initial\b", re.IGNORECASE),
        re.compile(r"\bname of proprietor\b", re.IGNORECASE),
        re.compile(r"\bemployer(?:'|’)?s name, address, and ZIP code\b", re.IGNORECASE),
        re.compile(r"\bemployee name\b", re.IGNORECASE),
        re.compile(r"\bemployee(?:'|’)?s first name and (?:middle )?initial\b", re.IGNORECASE),
        re.compile(r"\bfirst name(?: and (?:middle )?initial)?\b", re.IGNORECASE),
        re.compile(r"\blast name\b", re.IGNORECASE),
        re.compile(r"\bmiddle initial\b", re.IGNORECASE),
        re.compile(r"\bcompany name\b", re.IGNORECASE),
        re.compile(r"\btrade name\b", re.IGNORECASE),
        re.compile(r"\bbusiness name\b", re.IGNORECASE),
        re.compile(r"\baggregation name\b", re.IGNORECASE),
        re.compile(r"\bschedule c\s*:", re.IGNORECASE),
        re.compile(r"\bname of (?:person|business|company|trade|aggregation)\b", re.IGNORECASE),
        re.compile(r"\bfull name\b", re.IGNORECASE),
    ),
    "address": (
        re.compile(r"\bemployer(?:'|’)?s name, address, and ZIP code\b", re.IGNORECASE),
        re.compile(r"\bemployer(?:'|’)?s address\b", re.IGNORECASE),
        re.compile(r"\bemployee address\b", re.IGNORECASE),
        re.compile(r"\bemployee(?:'|’)?s address and ZIP code\b", re.IGNORECASE),
        re.compile(r"\bphysical address\b", re.IGNORECASE),
        re.compile(r"\bmailing address\b", re.IGNORECASE),
        re.compile(r"\bhome address\b", re.IGNORECASE),
        re.compile(r"\bpayer(?:'|’)?s address\b", re.IGNORECASE),
        re.compile(r"\bpayer(?:'|’)?s name, street address\b", re.IGNORECASE),
        re.compile(r"\bapt\.? no\.?\b", re.IGNORECASE),
        re.compile(r"\bcity, town(?:,? or post office)?\b", re.IGNORECASE),
        re.compile(r"\bcity, state, and ZIP code\b", re.IGNORECASE),
        re.compile(r"\bcity, town or post office, state, and ZIP code\b", re.IGNORECASE),
        re.compile(r"\bstreet address\b", re.IGNORECASE),
    ),
    "zip": (
        re.compile(r"\bemployer(?:'|’)?s name, address, and ZIP code\b", re.IGNORECASE),
        re.compile(r"\bzip code\b", re.IGNORECASE),
        re.compile(r"\bpostal code\b", re.IGNORECASE),
        re.compile(r"\bzip\b", re.IGNORECASE),
    ),
    "state_id": (
        re.compile(r"\bemployer(?:'|’)?s state id number\b", re.IGNORECASE),
        re.compile(r"\bpayer(?:'|’)?s state (?:no|number)\b", re.IGNORECASE),
        re.compile(r"\bstate id number\b", re.IGNORECASE),
        re.compile(r"\bstate id\b", re.IGNORECASE),
        re.compile(r"\bstate no\b", re.IGNORECASE),
    ),
    "control_number": (
        re.compile(r"\bcontrol number\b", re.IGNORECASE),
    ),
}
COLUMN_HEADER_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "name": (
        re.compile(r"^name$", re.IGNORECASE),
        re.compile(r"^\(\d+\)\s+first name(?: and (?:middle )?initial)?$", re.IGNORECASE),
        re.compile(r"^\(\d+\)\s+last name$", re.IGNORECASE),
        re.compile(r"^\(\d+\)\s+middle initial$", re.IGNORECASE),
    ),
    "control_number": (re.compile(r"^control number$", re.IGNORECASE),),
    "state_id": (
        re.compile(r"^employer state id number$", re.IGNORECASE),
        re.compile(r"^payer'?s state (?:no|number)\.?$", re.IGNORECASE),
    ),
    "zip": (re.compile(r"^zip(?: code)?$", re.IGNORECASE),),
    "ssn": (
        re.compile(r"^ssn$", re.IGNORECASE),
        re.compile(r"^\(\d+\)\s+ssn$", re.IGNORECASE),
        re.compile(r"^ssn\s+\(\d+\)$", re.IGNORECASE),
    ),
    "ein": (re.compile(r"^ein$", re.IGNORECASE),),
}

EIN_HINT_PATTERN = re.compile(
    r"\b(?:ein|tin|identifying number|employer(?:(?:'|’)s)? (?:id|identification) number|federal id)\b",
    re.IGNORECASE,
)
STREET_ADDRESS_PATTERN = re.compile(
    r"(?:"
    r"\b\d+[A-Za-z0-9./#-]*\s+(?:[A-Za-z0-9.'#-]+\s+){0,6}"
    r"(?:street|st|road|rd|avenue|ave|boulevard|blvd|lane|ln|drive|dr|court|ct|"
    r"circle|cir|place|pl|way|terrace|ter|parkway|pkwy)\b"
    r"|"
    r"\bP\.?\s*O\.?\s+Box\s+\d+[A-Za-z0-9-]*(?:\s+[A-Za-z0-9-]+){0,2}\b"
    r")",
    re.IGNORECASE,
)
CITY_STATE_ZIP_PATTERN = re.compile(
    r"\b[A-Za-z][A-Za-z .'-]+,?\s+[A-Z]{2}(?:\s*,\s*|\s*-\s*|\s+)\d{5}(?:-\d{4})?\b"
)
DIRECT_PATTERN_TYPES = {"ssn", "ein", "email", "phone"}
FIELD_COLUMN_TYPES = {"name", "address", "zip", "state_id", "control_number", "ein", "ssn"}
ROW_VALUE_SCAN_LIMIT = 3
COMPANY_SUFFIXES = {
    "llc",
    "inc",
    "corp",
    "co",
    "company",
    "ltd",
    "lp",
    "llp",
    "pllc",
    "pc",
}
ADDRESS_HINT_WORDS = {
    "apt",
    "apartment",
    "suite",
    "ste",
    "unit",
    "floor",
    "fl",
    "#",
}
NAME_STOPWORDS = {
    "last",
    "first",
    "middle",
    "initial",
    "suffix",
    "suff",
    "spouse",
    "spouse’s",
    "head",
    "relationship",
    "ssn",
    "name",
    "phone",
}
WIDGET_NAME_CONTEXT_PATTERN = re.compile(
    r"(name\(s\) shown|shown on return|first name|last name|middle initial|dependent|"
    r"name of proprietor|employer.?s name|employee.?s first name|employee.?s name|"
    r"name of person with self-employment income|"
    r"payer.?s name|recipient.?s name|trade, business, or aggregation name|"
    r"schedule c|"
    r"company name|trade name|business name|aggregation name|full name)",
    re.IGNORECASE,
)
WIDGET_ADDRESS_CONTEXT_PATTERN = re.compile(
    r"(address|street|city|town|zip|postal code|apt|physical address|"
    r"employee.?s address|employer.?s name, address, and zip code|"
    r"payer.?s name, street address|recipient.?s name|name, street address)",
    re.IGNORECASE,
)
WIDGET_STATE_ID_CONTEXT_PATTERN = re.compile(
    r"(state id|state no|payer.?s state|employer.?s state)",
    re.IGNORECASE,
)


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
    detections.extend(_detect_column_header_fields(lines, pii_types, source))
    detections.extend(_detect_address_lines(lines, pii_types, source))
    detections.extend(_detect_split_numeric_fields(lines, pii_types, source))
    return _dedupe_detections(detections)


def detect_direct_text_pii(
    word_boxes: Iterable[WordBox],
    pii_types: list[str],
    source: str,
) -> list[Detection]:
    words = list(word_boxes)
    lines = _build_lines(words)
    detections: list[Detection] = []
    detections.extend(_detect_word_level(words, pii_types, source))
    detections.extend(_detect_line_patterns(lines, pii_types, source))
    return _dedupe_detections(detections)


def detect_widget_pii(page: fitz.Page, pii_types: list[str]) -> list[WidgetDetection]:
    lines = _build_lines(extract_page_words(page))
    results: list[WidgetDetection] = []
    for widget in list(page.widgets() or []):
        value = str(widget.field_value or "").strip()
        if not value or value in {"Off", "Yes", "No"}:
            continue
        pii_type = _classify_widget_value(value, widget.rect, lines, widget.field_name or "", pii_types)
        if not pii_type:
            continue
        results.append(
            WidgetDetection(
                detection=Detection(
                    pii_type=pii_type,
                    value=value,
                    rect=fitz.Rect(widget.rect),
                    source="widget",
                ),
                xref=widget.xref,
            )
        )
    return results


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
            if pii_type == "phone":
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
    for line_index, line in enumerate(lines):
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
                if not _allow_direct_match(_direct_match_context(lines, line_index), pii_type):
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
    for line_index, line in enumerate(lines):
        for pii_type in pii_types:
            for label_pattern in LABEL_PATTERNS.get(pii_type, ()):
                for match in label_pattern.finditer(line.text):
                    label_words = _words_covering_span(line, match.start(), match.end())
                    if not label_words:
                        continue
                    label_rect = _union_rect(word.rect for word in label_words)
                    value_groups = _candidate_value_groups(
                        lines,
                        label_rect,
                        label_words,
                        pii_type,
                        match.end(),
                        _next_label_start(line.text, match.end()),
                    )
                    for matched_words in value_groups:
                        trimmed_words = _trim_labeled_value_words(matched_words, pii_type)
                        if not _looks_like_value(trimmed_words, pii_type):
                            continue
                        if not trimmed_words:
                            continue
                        detections.append(
                            Detection(
                                pii_type=pii_type,
                                value=" ".join(word.text for word in trimmed_words),
                                rect=_union_rect(word.rect for word in trimmed_words),
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


def _detect_column_header_fields(
    lines: list[LineData],
    pii_types: list[str],
    source: str,
) -> list[Detection]:
    detections: list[Detection] = []
    for line in lines:
        for pii_type in pii_types:
            for pattern in COLUMN_HEADER_PATTERNS.get(pii_type, ()):
                if not pattern.fullmatch(line.text.strip()):
                    continue
                groups = _candidate_value_groups(
                    lines,
                    line.rect,
                    line.words,
                    pii_type,
                    len(line.text),
                    len(line.text),
                )
                for matched_words in groups:
                    trimmed_words = _trim_labeled_value_words(matched_words, pii_type)
                    if not trimmed_words or not _looks_like_value(trimmed_words, pii_type):
                        continue
                    detections.append(
                        Detection(
                            pii_type=pii_type,
                            value=" ".join(word.text for word in trimmed_words),
                            rect=_union_rect(word.rect for word in trimmed_words),
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
    elif pii_type in {"name", "address"}:
        while trimmed and _looks_like_label_word(trimmed[0].text):
            trimmed.pop(0)
        while trimmed and _looks_like_label_word(trimmed[-1].text):
            trimmed.pop()
    return trimmed


def _detect_split_numeric_fields(
    lines: list[LineData],
    pii_types: list[str],
    source: str,
) -> list[Detection]:
    detections: list[Detection] = []
    for line_index, line in enumerate(lines):
        if "ssn" in pii_types:
            detections.extend(
                _scan_digit_sequences(
                    lines,
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
                    lines,
                    line,
                    source=source,
                    pii_type="ein",
                    target_length=9,
                    valid_partitions={(2, 7)},
                    require_hint=False,
                )
            )
    if "ssn" in pii_types:
        detections.extend(
            _scan_row_digit_sequences(
                lines,
                source=source,
                pii_type="ssn",
                target_length=9,
                valid_partitions={(3, 2, 4)},
            )
        )
    if "ein" in pii_types:
        detections.extend(
            _scan_row_digit_sequences(
                lines,
                source=source,
                pii_type="ein",
                target_length=9,
                valid_partitions={(2, 7)},
            )
        )
    return detections


def _scan_digit_sequences(
    lines: list[LineData],
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
                    pii_type in {"ssn", "ein"} and len(selected) > 1 and all(len(word.text) == 1 for word in selected)
                ):
                    if pii_type == "ein" and not _supports_ein_context(lines, line, selected):
                        break
                    if pii_type == "ssn" and not _supports_ssn_context(lines, line, selected):
                        break
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


def _scan_row_digit_sequences(
    lines: list[LineData],
    source: str,
    pii_type: str,
    target_length: int,
    valid_partitions: set[tuple[int, ...]],
) -> list[Detection]:
    digit_lines = sorted(
        (
            line
            for line in lines
            if len(line.words) == 1 and line.text.isdigit()
        ),
        key=lambda line: (line.rect.y0, line.rect.x0),
    )
    if not digit_lines:
        return []

    rows: list[list[LineData]] = [[digit_lines[0]]]
    for line in digit_lines[1:]:
        prev = rows[-1][-1]
        same_row = abs(line.rect.y0 - prev.rect.y0) <= 2 and abs(line.rect.y1 - prev.rect.y1) <= 2
        if same_row:
            rows[-1].append(line)
        else:
            rows.append([line])

    detections: list[Detection] = []
    for row in rows:
        row = sorted(row, key=lambda line: line.rect.x0)
        for start_index in range(len(row)):
            selected: list[LineData] = []
            lengths: list[int] = []
            total = 0
            prev_x1: float | None = None
            for candidate in row[start_index:]:
                if prev_x1 is not None and candidate.rect.x0 - prev_x1 > 20:
                    break
                selected.append(candidate)
                lengths.append(len(candidate.text))
                total += len(candidate.text)
                prev_x1 = candidate.rect.x1
                if total == target_length:
                    if tuple(lengths) in valid_partitions or (
                        pii_type in {"ssn", "ein"} and all(len(item.text) == 1 for item in selected)
                    ):
                        selected_words = [item.words[0] for item in selected]
                        if pii_type == "ein":
                            if not EIN_HINT_PATTERN.search(_nearby_rect_context(lines, _union_rect(item.rect for item in selected))):
                                break
                        if pii_type == "ssn":
                            if not re.search(r"\bssn|social security\b", _nearby_rect_context(lines, _union_rect(item.rect for item in selected)), re.IGNORECASE):
                                break
                        detections.append(
                            Detection(
                                pii_type=pii_type,
                                value="".join(item.text for item in selected),
                                rect=_union_rect(word.rect for word in selected_words),
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
        lines.append(
            LineData(
                key=sorted_words[0].line_key,
                words=sorted_words,
                text="".join(parts),
                spans=spans,
                rect=_union_rect(word.rect for word in sorted_words),
            )
        )
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


def _candidate_value_groups(
    lines: list[LineData],
    label_rect: fitz.Rect,
    label_words: list[WordBox],
    pii_type: str,
    label_end: int,
    next_label_start: int,
) -> list[list[WordBox]]:
    groups: list[list[WordBox]] = []
    label_line = next((line for line in lines if any(word in line.words for word in label_words)), None)
    if label_line is not None:
        groups.extend(_same_line_value_groups(label_line, label_words, pii_type, label_end, next_label_start))
    groups.extend(_right_of_label_value_groups(lines, label_rect, pii_type))
    groups.extend(_above_label_value_groups(lines, label_rect, pii_type))
    groups.extend(_below_label_value_groups(lines, label_rect, pii_type))
    groups.extend(_column_value_groups(lines, label_rect, pii_type))
    split_groups: list[list[WordBox]] = []
    for group in groups:
        split_groups.extend(_split_word_group(group, pii_type))
    return _dedupe_word_groups(split_groups)


def _same_line_value_groups(
    line: LineData,
    label_words: list[WordBox],
    pii_type: str,
    label_end: int,
    next_label_start: int,
) -> list[list[WordBox]]:
    groups: list[list[WordBox]] = []
    after_label = _words_covering_span(line, _skip_separators(line.text, label_end), next_label_start)
    if after_label:
        groups.append(after_label)
    return groups


def _right_of_label_value_groups(
    lines: list[LineData],
    label_rect: fitz.Rect,
    pii_type: str,
) -> list[list[WordBox]]:
    groups: list[list[WordBox]] = []
    x_min, x_max = _horizontal_window(label_rect, pii_type)
    label_mid_y = (label_rect.y0 + label_rect.y1) / 2
    candidate_lines = sorted(
        (
            line
            for line in lines
            if line.rect.x0 >= label_rect.x1 + 2
            and line.rect.x0 <= x_max
            and abs(((line.rect.y0 + line.rect.y1) / 2) - label_mid_y) <= 14
        ),
        key=lambda line: (line.rect.x0, line.rect.y0),
    )
    for candidate_line in candidate_lines:
        candidate_words = [
            word
            for word in candidate_line.words
            if x_min <= _word_center_x(word) <= x_max
        ]
        candidate_words = _trim_labeled_value_words(candidate_words, pii_type)
        if candidate_words:
            groups.append(candidate_words)
    return groups


def _below_label_value_groups(
    lines: list[LineData],
    label_rect: fitz.Rect,
    pii_type: str,
) -> list[list[WordBox]]:
    groups: list[list[WordBox]] = []
    x_min, x_max = _horizontal_window(label_rect, pii_type)
    candidate_lines = sorted(
        (
            line
            for line in lines
            if line.rect.y0 >= label_rect.y0 + 2
            and ((line.rect.y0 + line.rect.y1) / 2) > ((label_rect.y0 + label_rect.y1) / 2)
            and line.rect.y0 - label_rect.y0 <= 90
            and line.rect.x1 >= x_min
            and line.rect.x0 <= x_max
        ),
        key=lambda line: (line.rect.y0, line.rect.x0),
    )
    accepted_groups = 0
    for next_line in candidate_lines:
        if _line_looks_like_header(next_line.text):
            continue
        candidate_words = [
            word
            for word in next_line.words
            if _word_center_x(word) >= x_min and _word_center_x(word) <= x_max
        ]
        candidate_words = _trim_labeled_value_words(candidate_words, pii_type)
        if candidate_words:
            groups.append(candidate_words)
            accepted_groups += 1
            if accepted_groups >= ROW_VALUE_SCAN_LIMIT:
                break
    return groups


def _above_label_value_groups(
    lines: list[LineData],
    label_rect: fitz.Rect,
    pii_type: str,
) -> list[list[WordBox]]:
    groups: list[list[WordBox]] = []
    x_min, x_max = _horizontal_window(label_rect, pii_type)
    candidate_lines = sorted(
        (
            line
            for line in lines
            if line.rect.y1 <= label_rect.y1
            and label_rect.y0 - line.rect.y1 <= 70
            and label_rect.y0 - line.rect.y1 >= -4
            and line.rect.x1 >= x_min
            and line.rect.x0 <= x_max
        ),
        key=lambda line: (label_rect.y0 - line.rect.y1, line.rect.x0),
    )
    for prev_line in candidate_lines:
        if _line_looks_like_header(prev_line.text):
            continue
        candidate_words = [
            word
            for word in prev_line.words
            if _word_center_x(word) >= x_min and _word_center_x(word) <= x_max
        ]
        candidate_words = _trim_labeled_value_words(candidate_words, pii_type)
        if candidate_words:
            groups.append(candidate_words)
    return groups


def _column_value_groups(
    lines: list[LineData],
    label_rect: fitz.Rect,
    pii_type: str,
) -> list[list[WordBox]]:
    if pii_type not in FIELD_COLUMN_TYPES:
        return []
    header_line = next((line for line in lines if line.rect.intersects(label_rect)), None)
    if header_line is None or not _line_is_column_header(header_line.text):
        return []

    groups: list[list[WordBox]] = []
    x_min, x_max = _horizontal_window(label_rect, pii_type, column_mode=True)
    candidate_lines = sorted(
        (
            line
            for line in lines
            if line.rect.y0 > label_rect.y1 and line.rect.y0 - label_rect.y1 <= 140
        ),
        key=lambda line: (line.rect.y0, line.rect.x0),
    )
    for next_line in candidate_lines:
        if _line_looks_like_header(next_line.text):
            break
        candidate_words = [
            word for word in next_line.words if x_min <= _word_center_x(word) <= x_max
        ]
        candidate_words = _trim_labeled_value_words(candidate_words, pii_type)
        if candidate_words:
            groups.append(candidate_words)
    return groups


def _line_looks_like_header(text: str) -> bool:
    lowered = text.lower()
    return any(
        token in lowered
        for token in (
            "name",
            "address",
            "first",
            "last",
            "middle",
            "suffix",
            "state id",
            "state no",
            "control number",
            "zip",
            "ssn",
            "ein",
        )
    )


def _line_is_column_header(text: str) -> bool:
    words = re.findall(r"[A-Za-z0-9']+", text)
    if not words or len(words) > 5:
        return False
    lowered = text.lower()
    return any(
        token in lowered
        for token in ("name", "address", "zip", "state", "control", "ein", "ssn")
    )


def _next_label_start(text: str, start: int) -> int:
    candidates: list[int] = []
    for patterns in LABEL_PATTERNS.values():
        for pattern in patterns:
            for match in pattern.finditer(text):
                if match.start() > start:
                    candidates.append(match.start())
    return min(candidates) if candidates else len(text)


def _supports_ein_context(
    lines: list[LineData],
    line: LineData,
    selected: list[WordBox],
) -> bool:
    if EIN_HINT_PATTERN.search(_nearby_context(lines, line, selected)):
        return True
    return False


def _supports_ssn_context(
    lines: list[LineData],
    line: LineData,
    selected: list[WordBox],
) -> bool:
    return bool(
        re.search(r"\bssn|social security\b", _nearby_context(lines, line, selected), re.IGNORECASE)
    )


def _dedupe_word_groups(groups: list[list[WordBox]]) -> list[list[WordBox]]:
    seen: set[tuple[tuple[int, int, int, int], ...]] = set()
    deduped: list[list[WordBox]] = []
    for group in groups:
        if not group:
            continue
        key = tuple(
            (round(word.rect.x0), round(word.rect.y0), round(word.rect.x1), round(word.rect.y1))
            for word in group
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(group)
    return deduped


def _word_center_x(word: WordBox) -> float:
    return (word.rect.x0 + word.rect.x1) / 2


def _looks_like_label_word(text: str) -> bool:
    lowered = text.lower().strip(" :,-")
    return lowered in {
        "name",
        "address",
        "street",
        "physical",
        "employee",
        "company",
        "trade",
        "business",
        "aggregation",
    }


def _split_word_group(words: list[WordBox], pii_type: str) -> list[list[WordBox]]:
    if len(words) <= 1 or pii_type == "address":
        return [words]
    sorted_words = sorted(words, key=lambda word: (word.rect.y0, word.rect.x0))
    groups: list[list[WordBox]] = [[sorted_words[0]]]
    for word in sorted_words[1:]:
        prev = groups[-1][-1]
        gap = word.rect.x0 - prev.rect.x1
        if gap > 35:
            groups.append([word])
        else:
            groups[-1].append(word)
    return groups


def _horizontal_window(label_rect: fitz.Rect, pii_type: str, column_mode: bool = False) -> tuple[float, float]:
    x_min = label_rect.x0 - 12
    width = label_rect.x1 - label_rect.x0
    if pii_type == "control_number":
        margin = 200 if column_mode else 260
    elif pii_type == "state_id":
        margin = 140 if column_mode else 180
    elif pii_type == "address":
        margin = 120 if column_mode else 140
    elif pii_type == "name":
        margin = 70 if column_mode else 90
    elif pii_type in {"ssn", "ein"}:
        margin = 120 if column_mode else 140
    else:
        margin = 80 if column_mode else 100
    x_max = max(label_rect.x1 + margin, label_rect.x0 + width + 40)
    return x_min, x_max


def _looks_like_value(words: list[WordBox], pii_type: str) -> bool:
    if not words:
        return False
    text = " ".join(word.text for word in words).strip()
    lowered = text.lower()
    if len(text) <= 1:
        return False
    if any(token in lowered for token in ("instructions", "attach", "complete", "see ", "part ", "line ")):
        return False

    if pii_type == "name":
        alpha_tokens = [word.text for word in words if re.search(r"[A-Za-z]", word.text)]
        if not alpha_tokens or len(alpha_tokens) > 6:
            return False
        if any(re.search(r"\d", word.text) for word in words):
            return False
        if len(alpha_tokens) == 1:
            token = alpha_tokens[0].strip(".,")
            return token.lower() in COMPANY_SUFFIXES or (
                token[:1].isupper() and token.lower() not in NAME_STOPWORDS
            )
        return all(
            token.strip(".,'()/-")[:1].isupper() or token.strip(".,").lower() in COMPANY_SUFFIXES
            for token in alpha_tokens
        )

    if pii_type == "address":
        return bool(
            STREET_ADDRESS_PATTERN.search(text)
            or CITY_STATE_ZIP_PATTERN.search(text)
            or (
                any(word.text.lower().strip(".,") in ADDRESS_HINT_WORDS for word in words)
                and any(re.search(r"\d", word.text) for word in words)
            )
            or (
                len(words) <= 4
                and any(word.text[:1].isupper() for word in words if word.text)
                and not any(token in lowered for token in ("instructions", "attach", "complete", "line", "part"))
            )
        )

    if pii_type == "zip":
        return any(PII_PATTERNS["zip"].fullmatch(word.text) for word in words)

    if pii_type == "control_number":
        compact = re.sub(r"\s+", "", text)
        return (
            bool(re.search(r"\d", text))
            and len(words) <= 4
            and len(text) <= 24
            and len(compact) >= 5
            and lowered not in {"w-2", "w-3"}
            and "for" not in lowered
            and not re.fullmatch(r"\d+[—-][a-z]+", lowered)
        )

    if pii_type == "state_id":
        return (
            bool(re.search(r"\d", text))
            and len(words) <= 4
            and len(text) <= 24
            and bool(re.search(r"[A-Za-z-]", text))
            and lowered not in {"w-2", "w-3"}
            and "for" not in lowered
            and not re.fullmatch(r"\d+[—-][a-z]+", lowered)
        )

    return True


def _classify_widget_value(
    value: str,
    rect: fitz.Rect,
    lines: list[LineData],
    field_name: str,
    pii_types: list[str],
) -> str | None:
    lowered_field = field_name.lower()
    context = _widget_context(lines, rect)
    lowered_context = context.lower()
    combined_context = f"{lowered_field} {lowered_context}"
    compact_digits = re.sub(r"\D", "", value)

    if "ssn" in pii_types and "table_dependents" in lowered_field and len(compact_digits) in {2, 3, 4, 9}:
        return "ssn"

    if "ssn" in pii_types and (
        "social security" in combined_context
        or re.search(r"\bssn\b", combined_context)
        or "identifying number" in combined_context
        or "taxpayer identification number" in combined_context
        or "ssn" in lowered_field
    ):
        if len(compact_digits) == 9:
            return "ssn"

    if "ein" in pii_types and (
        EIN_HINT_PATTERN.search(combined_context) or "ein" in lowered_field
    ):
        if len(compact_digits) == 9:
            return "ein"

    if "control_number" in pii_types and "control number" in combined_context:
        if _looks_like_widget_value(value, "control_number"):
            return "control_number"

    if "state_id" in pii_types and (
        WIDGET_STATE_ID_CONTEXT_PATTERN.search(combined_context)
        or "boxes15_readorder" in lowered_field
    ):
        if _looks_like_widget_value(value, "state_id"):
            return "state_id"

    if "zip" in pii_types and ("zip" in combined_context or "postal code" in combined_context):
        if _looks_like_widget_value(value, "zip"):
            return "zip"

    if "address" in pii_types and (
        WIDGET_ADDRESS_CONTEXT_PATTERN.search(combined_context)
        or "table_line1a" in lowered_field
        or (
            rect.height >= 24
            and re.search(r"(employer|employee|payer|recipient)", combined_context)
        )
    ):
        if _looks_like_widget_value(value, "address"):
            return "address"

    if "name" in pii_types and (
        WIDGET_NAME_CONTEXT_PATTERN.search(combined_context)
        or ("table_parti" in lowered_field and rect.x0 < 340)
        or any(token in lowered_field for token in ("firstname", "lastname", "middle"))
        or "dependents_readorder" in lowered_field
        or "table_dependents" in lowered_field
    ):
        if _looks_like_widget_value(value, "name"):
            return "name"

    return None


def _looks_like_widget_value(value: str, pii_type: str) -> bool:
    stripped = value.strip()
    lowered = stripped.lower()
    compact = re.sub(r"\s+", "", stripped)
    if not stripped:
        return False
    if pii_type == "ssn":
        return len(re.sub(r"\D", "", stripped)) == 9
    if pii_type == "ein":
        return len(re.sub(r"\D", "", stripped)) == 9
    if pii_type == "zip":
        return bool(PII_PATTERNS["zip"].fullmatch(stripped))
    if pii_type == "state_id":
        return len(compact) >= 4 and bool(re.search(r"\d", stripped))
    if pii_type == "control_number":
        return len(compact) >= 4 and bool(re.search(r"\d", stripped))
    if pii_type == "address":
        return bool(
            STREET_ADDRESS_PATTERN.search(stripped)
            or CITY_STATE_ZIP_PATTERN.search(stripped)
            or "\n" in stripped
            or "," in stripped
            or len(compact) >= 3
        )
    if pii_type == "name":
        parts = [
            part
            for part in re.split(r"\s+", stripped.replace("\n", " ").strip())
            if part and part not in {"&", "/", "and"}
        ]
        if not parts or len(parts) > 10:
            return False
        if any(re.search(r"\d", part) for part in parts):
            return False
        return all(
            bool(re.match(r"[A-Za-z]", part.strip(".,'()/-")))
            or part.strip(".,").lower() in COMPANY_SUFFIXES
            for part in parts
        )
    return True


def _widget_context(lines: list[LineData], rect: fitz.Rect) -> str:
    context_lines: list[str] = []
    nearby = sorted(
        (
            line
            for line in lines
            if line.rect.x1 >= rect.x0 - 24
            and line.rect.x0 <= rect.x1 + 24
            and line.rect.y1 <= rect.y0 + 6
            and rect.y0 - line.rect.y1 <= 48
        ),
        key=lambda line: (rect.y0 - line.rect.y1, abs(line.rect.x0 - rect.x0)),
    )
    context_lines.extend(line.text for line in nearby[:4])

    left_neighbors = sorted(
        (
            line
            for line in lines
            if line.rect.y1 >= rect.y0 - 6
            and line.rect.y0 <= rect.y1 + 6
            and line.rect.x1 <= rect.x0 + 12
            and rect.x0 - line.rect.x1 <= 220
        ),
        key=lambda line: (rect.x0 - line.rect.x1, abs(line.rect.y0 - rect.y0)),
    )
    context_lines.extend(line.text for line in left_neighbors[:3])

    same_row_neighbors = sorted(
        (
            line
            for line in lines
            if line.rect.y1 >= rect.y0 - 10
            and line.rect.y0 <= rect.y1 + 10
            and line.rect.x1 >= rect.x0 - 280
            and line.rect.x0 <= rect.x1 + 280
            and not line.rect.intersects(rect)
        ),
        key=lambda line: (
            min(abs(line.rect.x0 - rect.x1), abs(rect.x0 - line.rect.x1)),
            abs(((line.rect.y0 + line.rect.y1) / 2) - ((rect.y0 + rect.y1) / 2)),
        ),
    )
    context_lines.extend(line.text for line in same_row_neighbors[:4])

    below_neighbors = sorted(
        (
            line
            for line in lines
            if line.rect.x1 >= rect.x0 - 40
            and line.rect.x0 <= rect.x1 + 40
            and line.rect.y0 >= rect.y1 - 2
            and line.rect.y0 - rect.y1 <= 36
        ),
        key=lambda line: (line.rect.y0 - rect.y1, abs(line.rect.x0 - rect.x0)),
    )
    context_lines.extend(line.text for line in below_neighbors[:2])
    return " ".join(context_lines)


def _allow_direct_match(line_text: str, pii_type: str) -> bool:
    lowered = line_text.lower()
    if pii_type == "phone":
        blocked_tokens = (
            "visit",
            "call",
            "questions",
            "information",
            "ssa",
            "social security",
            "www.",
            "website",
            "toll free",
            "technical services",
            "electronically",
        )
        if any(token in lowered for token in blocked_tokens):
            return False
    return True


def _direct_match_context(lines: list[LineData], line_index: int) -> str:
    parts = [lines[line_index].text]
    if line_index > 0 and lines[line_index].words[0].rect.y0 - lines[line_index - 1].words[0].rect.y0 <= 28:
        parts.insert(0, lines[line_index - 1].text)
    return " ".join(parts)


def _nearby_context(
    lines: list[LineData],
    line: LineData,
    selected: list[WordBox],
) -> str:
    selected_ids = {id(word) for word in selected}
    parts = [
        " ".join(
            word.text
            for word in line.words
            if id(word) not in selected_ids and word.rect.x1 <= selected[0].rect.x0 + 2
        )
    ]
    nearby_above = sorted(
        (
            other
            for other in lines
            if other.rect.y1 <= line.rect.y0 and line.rect.y0 - other.rect.y1 <= 60
        ),
        key=lambda other: (line.rect.y0 - other.rect.y1, abs(other.rect.x0 - line.rect.x0)),
    )
    parts.extend(other.text for other in nearby_above[:3])
    return " ".join(part for part in parts if part)


def _nearby_rect_context(lines: list[LineData], rect: fitz.Rect) -> str:
    nearby = sorted(
        (
            line
            for line in lines
            if line.rect.x1 >= rect.x0 - 260
            and line.rect.x0 <= rect.x1 + 40
            and line.rect.y0 >= rect.y0 - 60
            and line.rect.y1 <= rect.y1 + 20
            and not line.rect.intersects(rect)
        ),
        key=lambda line: (
            abs(((line.rect.y0 + line.rect.y1) / 2) - ((rect.y0 + rect.y1) / 2)),
            abs(line.rect.x0 - rect.x0),
        ),
    )
    return " ".join(line.text for line in nearby[:8])
