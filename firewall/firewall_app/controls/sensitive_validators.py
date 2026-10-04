"""Checks that confirm a regex match is real Sensitive Data. Policy categories refer to them
by name (`validator: luhn`). Adding one here is the only code change a new category can need."""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Callable


def _digits(text: str) -> str:
    return re.sub(r"\D", "", text)  # \d also matches full-width digits; int() accepts them


def luhn(text: str) -> bool:
    digits = [int(d) for d in _digits(text)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2:
            digit = digit * 2 - 9 if digit > 4 else digit * 2
        total += digit
    return total % 10 == 0


def iban(text: str) -> bool:
    value = re.sub(r"\s", "", text).upper()
    if not 15 <= len(value) <= 34 or not value.isascii() or not value.isalnum():
        return False
    rearranged = value[4:] + value[:4]
    return int("".join(str(int(ch, 36)) for ch in rearranged)) % 97 == 1


def pesel_checksum(text: str) -> bool:
    digits = [int(d) for d in _digits(text)]
    if len(digits) != 11:
        return False
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    return (10 - sum(w * d for w, d in zip(weights, digits)) % 10) % 10 == digits[10]


def entropy(text: str, threshold: float = 4.0) -> bool:
    """Shannon entropy per character: random keys are high, words and hex hashes are lower."""
    if not text:
        return False
    counts = Counter(text)
    bits = -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())
    return bits >= threshold


VALIDATORS: dict[str, Callable[[str], bool]] = {
    "luhn": luhn,
    "iban": iban,
    "pesel_checksum": pesel_checksum,
    "entropy": entropy,
}
