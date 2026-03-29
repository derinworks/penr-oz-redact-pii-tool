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
    key: tuple[int, int]
    words: list[WordBox]
    text: str
    spans: list[tuple[int, int]]


LABEL_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "name": (
        re.compile(r"\bemployee name\b", re.IGNORECASE),
        re.compile(r"\bemployee'?s first name and (?:middle )?initial\b", re.IGNORECASE),
        re.compile(r"\bfirst name(?: and (?:middle )?initial)?\b", re.IGNORECASE),
        re.compile(r"\blast name\b", re.IGNORECASE),
        re.compile(r"\bmiddle initial\b", re.IGNORECASE),
        re.compile(r"\bcompany name\b", re.IGNORECASE),
        re.compile(r"\btrade name\b", re.IGNORECASE),
        re.compile(r"\bbusiness name\b", re.IGNORECASE),
        re.compile(r"\baggregation name\b", re.IGNORECASE),
        re.compile(r"\bname of (?:person|business|company|trade|aggregation)\b", re.IGNORECASE),
        re.compile(r"\bfull name\b", re.IGNORECASE),
        re.compile(r"^name$", re.IGNORECASE),
    ),
    "address": (
        re.compile(r"\bemployee address\b", re.IGNORECASE),
        re.compile(r"\bphysical address\b", re.IGNORECASE),
        re.compile(r"\bmailing address\b", re.IGNORECASE),
        re.compile(r"\bhome address\b", re.IGNORECASE),
        re.compile(r"\bstreet address\b", re.IGNORECASE),
    ),
    "zip": (
        re.compile(r"\bzip code\b", re.IGNORECASE),
        re.compile(r"\bpostal code\b", re.IGNORECASE),
        re.compile(r"\bzip\b", re.IGNORECASE),
    ),
    "state_id": (
        re.compile(r"\bemployer'?s state id number\b", re.IGNORECASE),
        re.compile(r"\bpayer'?s state (?:no|number)\b", re.IGNORECASE),
        re.compile(r"\bstate id number\b", re.IGNORECASE),
        re.compile(r"\bstate id\b", re.IGNORECASE),
        re.compile(r"\bstate no\b", re.IGNORECASE),
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
                        line_index,
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
                    line_index,
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
                    line_index,
                    line,
                    source=source,
                    pii_type="ein",
                    target_length=9,
                    valid_partitions={(2, 7)},
                    require_hint=False,
                )
            )
    return detections


def _scan_digit_sequences(
    lines: list[LineData],
    line_index: int,
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
                    if pii_type == "ein" and not _supports_ein_context(lines, line_index, line, selected):
                        break
                    if pii_type == "ssn" and not _supports_ssn_context(lines, line_index, line, selected):
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
        lines.append(LineData(key=sorted_words[0].line_key, words=sorted_words, text="".join(parts), spans=spans))
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
    line_index: int,
    label_rect: fitz.Rect,
    label_words: list[WordBox],
    pii_type: str,
    label_end: int,
    next_label_start: int,
) -> list[list[WordBox]]:
    groups: list[list[WordBox]] = []
    groups.extend(_same_line_value_groups(lines[line_index], label_words, pii_type, label_end, next_label_start))
    groups.extend(_below_label_value_groups(lines, line_index, label_rect, pii_type))
    groups.extend(_column_value_groups(lines, line_index, label_rect, pii_type))
    return _dedupe_word_groups(groups)


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


def _below_label_value_groups(
    lines: list[LineData],
    line_index: int,
    label_rect: fitz.Rect,
    pii_type: str,
) -> list[list[WordBox]]:
    groups: list[list[WordBox]] = []
    x_min = label_rect.x0 - 12
    x_max = max(label_rect.x1 + 220, label_rect.x0 + 140)
    for next_line in lines[line_index + 1 : line_index + 1 + ROW_VALUE_SCAN_LIMIT]:
        if next_line.words[0].rect.y0 - label_rect.y1 > 36:
            break
        candidate_words = [
            word
            for word in next_line.words
            if _word_center_x(word) >= x_min and _word_center_x(word) <= x_max
        ]
        candidate_words = _trim_labeled_value_words(candidate_words, pii_type)
        if candidate_words:
            groups.append(candidate_words)
            if pii_type not in {"address", "name"}:
                break
    return groups


def _column_value_groups(
    lines: list[LineData],
    line_index: int,
    label_rect: fitz.Rect,
    pii_type: str,
) -> list[list[WordBox]]:
    if pii_type not in FIELD_COLUMN_TYPES:
        return []
    if not _line_is_column_header(lines[line_index].text):
        return []

    groups: list[list[WordBox]] = []
    x_min = label_rect.x0 - 4
    x_max = max(label_rect.x1 + 80, label_rect.x0 + 110)
    for next_line in lines[line_index + 1 :]:
        if next_line.words[0].rect.y0 - label_rect.y1 > 120:
            break
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
    line_index: int,
    line: LineData,
    selected: list[WordBox],
) -> bool:
    if EIN_HINT_PATTERN.search(_nearby_context(lines, line_index, line, selected)):
        return True
    return False


def _supports_ssn_context(
    lines: list[LineData],
    line_index: int,
    line: LineData,
    selected: list[WordBox],
) -> bool:
    return bool(
        re.search(r"\bssn|social security\b", _nearby_context(lines, line_index, line, selected), re.IGNORECASE)
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
        if any(re.search(r"\d", token) for token in alpha_tokens):
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
        )

    if pii_type == "zip":
        return any(PII_PATTERNS["zip"].fullmatch(word.text) for word in words)

    if pii_type in {"state_id", "control_number"}:
        return (
            bool(re.search(r"\d", text))
            and len(words) <= 4
            and len(text) <= 24
            and bool(re.search(r"[A-Za-z-]", text))
        )

    return True


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
    line_index: int,
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
    for previous_line in lines[max(0, line_index - 2) : line_index]:
        if line.words[0].rect.y0 - previous_line.words[0].rect.y0 > 48:
            continue
        parts.append(previous_line.text)
    return " ".join(part for part in parts if part)
