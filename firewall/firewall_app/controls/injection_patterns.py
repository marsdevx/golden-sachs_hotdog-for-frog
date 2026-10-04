"""Pattern data and text normalization for `injection_heuristics`.

Patterns are matched against *normalized* text: lowercased, NFKC, zero-width characters
removed, diacritics and Cyrillic/Greek look-alike letters folded to plain Latin. So a pattern
is written in plain ASCII lowercase ("pomin", not "pomiń"; "ubersprin", not "übersprin").

Every pattern is linear-time: no nested unbounded quantifiers. Keep it that way when adding
one; a catastrophic regex stalls every Check.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# --- normalization -----------------------------------------------------------------------

ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿", "­"}

# Lowercase look-alikes that render (almost) like Latin letters.
LOOKALIKES = str.maketrans({
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "з": "3", "и": "u", "й": "u", "к": "k", "м": "m",
    "н": "h", "о": "o", "п": "n", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ь": "b",
    "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x",
    # Letters NFKD does not decompose
    "ł": "l", "ß": "ss", "ø": "o", "đ": "d", "ı": "i",
})

LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a",
                      "$": "s"})


@dataclass(frozen=True, slots=True)
class Normalized:
    """Normalized text plus, for every character, the index of the original character."""

    text: str
    origin: list[int] | range

    def leet(self) -> Normalized:
        # One character for one character, so the origin map stays valid.
        return Normalized(self.text.translate(LEET), self.origin)

    def span(self, start: int, end: int) -> tuple[int, int]:
        """The original-text span of a normalized-text span."""
        return self.origin[start], self.origin[end - 1] + 1


def normalize(text: str) -> Normalized:
    if text.isascii():  # the common case, and the cheap one
        return Normalized(text.lower(), range(len(text)))
    chars: list[str] = []
    origin: list[int] = []
    for index, char in enumerate(text):
        if char.isascii():
            chars.append(char.lower())
            origin.append(index)
            continue
        if char in ZERO_WIDTH:
            continue
        folded = unicodedata.normalize("NFKC", char).lower()
        folded = unicodedata.normalize("NFKD", folded)
        folded = "".join(c for c in folded if not unicodedata.combining(c))
        for out in folded.translate(LOOKALIKES):
            chars.append(out)
            origin.append(index)
    return Normalized("".join(chars), origin)


# --- patterns ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Pattern:
    id: str
    language: str  # en | pl | de | any
    weight: float  # risk score of a hit, 0.6..0.9
    regex: re.Pattern[str]
    indirect_only: bool = False  # only in Resource content (tool messages, tool_result)


def _p(id: str, language: str, weight: float, regex: str, indirect_only: bool = False) -> Pattern:
    return Pattern(id, language, weight, re.compile(regex, re.MULTILINE), indirect_only)


_ALL = r"(?:all\s+|any\s+|every\s+)?(?:of\s+)?(?:the\s+|your\s+|my\s+|these\s+|those\s+)?"
_PREVIOUS = r"(?:previous|prior|above|earlier|preceding|former|original|initial|system|old)"
_RULES = r"(?:instructions?|rules?|prompts?|directions?|guidelines?|commands?|directives?)"
_AI = r"(?:ai|llm|assistant|language\s+model|chatbot|bot|agent|model)"

PATTERNS: list[Pattern] = [
    # --- override ---
    _p("ignore_previous", "en", 0.9,
       rf"\b(?:ignore|disregard|forget|skip|override|bypass|drop)\s+{_ALL}{_PREVIOUS}\s+"
       rf"(?:\w+\s+)?{_RULES}"),
    _p("ignore_previous", "pl", 0.9,
       r"\b(?:z?ignoruj(?:cie)?|pomin(?:cie)?|zapomnij(?:cie)?(?:\s+o)?|porzuc|olej"
       r"|nie\s+zwracaj\s+uwagi\s+na)\s+(?:wszystk\w*\s+|wszelk\w*\s+|swoj\w*\s+|twoj\w*\s+)?"
       r"(?:poprzedni\w*|wczesniejsz\w*|powyzsz\w*|dotychczasow\w*|systemow\w*|otrzyman\w*)\s+"
       r"(?:instrukcj|polecen|zasad|regul|wytyczn|komend)\w*"),
    _p("ignore_previous", "de", 0.9,
       r"\b(?:ignorier(?:e|en\s+sie)?|vergiss|vergessen\s+sie|missachte|uberspring(?:e)?)\s+"
       r"(?:bitte\s+)?(?:alle\s+|samtliche\s+|die\s+|deine\s+|ihre\s+)?"
       r"(?:vorherig|vorig|bisherig|obig|fruher|vorangegangen|vorhergehend|ursprunglich|system)"
       r"\w*\s*(?:anweisung|instruktion|regel|befehl|vorgabe|richtlinie)\w*"),
    # --- new role or jailbreak ---
    _p("new_role", "en", 0.7,
       rf"\byou\s+are\s+now\s+(?:an?\s+|the\s+|my\s+|in\s+)?(?:\w+\s+){{0,2}}?"
       rf"(?:{_AI}|dan|persona|character|unrestricted|unfiltered|uncensored|jailbroken|evil"
       rf"|free|developer\s+mode|dev\s+mode)\b"),
    _p("new_role", "en", 0.7,
       r"\bfrom\s+now\s+on,?\s+you\s+(?:are|will\s+(?:act|behave|respond|answer|be)|must)\b"),
    _p("new_role", "en", 0.6, r"\bno\s+longer\s+(?:bound|restricted|limited)\s+by\b"),
    _p("jailbreak", "en", 0.8,
       r"\b(?:act|behave|respond)\s+as\s+(?:an?\s+)?(?:dan|unrestricted\s+ai|jailbroken)\b"),
    _p("jailbreak", "en", 0.8, r"\bdo\s+anything\s+now\b"),
    _p("jailbreak", "en", 0.8,
       r"\b(?:enable|activate|enter|switch\s+(?:to|into)|turn\s+on)\s+(?:the\s+)?"
       r"(?:developer|dev|god|jailbreak|dan|unrestricted|debug)\s+mode\b"),
    _p("jailbreak", "en", 0.7, r"\byou\s+are\s+(?:now\s+)?(?:jailbroken|dan)\b"),
    _p("new_role", "pl", 0.7, r"\bjestes\s+teraz\b"),
    _p("new_role", "pl", 0.7, r"\bod\s+(?:teraz|tej\s+chwili|dzis)\s+(?:jestes|bedziesz)\b"),
    _p("new_role", "pl", 0.7, r"\budawaj,?\s+ze\s+jestes\b"),
    _p("jailbreak", "pl", 0.8,
       r"\b(?:wlacz|aktywuj|uruchom|przejdz\s+w|przejdz\s+do)\s+(?:tryb\w*)\s+"
       r"(?:dewelopera|programisty|developer\w*|jailbreak|dan|bez\s+ograniczen)"),
    _p("new_role", "de", 0.7,
       r"\bdu\s+bist\s+(?:jetzt|nun|ab\s+sofort|ab\s+jetzt|von\s+nun\s+an)\b"),
    _p("new_role", "de", 0.7, r"\b(?:ab\s+jetzt|ab\s+sofort|von\s+nun\s+an)\s+bist\s+du\b"),
    _p("jailbreak", "de", 0.8,
       r"\b(?:aktiviere|starte|wechsle\s+in|schalte)\s+(?:den\s+)?"
       r"(?:entwickler|developer|jailbreak|dan)[\s-]?modus"),
    # --- system prompt extraction ---
    _p("reveal_prompt", "en", 0.8,
       r"\b(?:reveal|print|show|display|output|repeat|leak|dump|tell|give|write\s+out|recite"
       r"|disclose|list)\s+(?:me\s+|us\s+)?(?:all\s+)?(?:of\s+)?"
       r"(?:(?:your|the)\s+(?:\w+\s+)?system\s+(?:prompt|message|instructions)"
       r"|your\s+(?:\w+\s+)?(?:instructions|initial\s+prompt|hidden\s+prompt|prompt|rules))\b"),
    _p("reveal_prompt", "en", 0.7,
       r"\brepeat\s+(?:the\s+|all\s+)?(?:words|text|everything|lines)\s+(?:written\s+)?above\b"),
    _p("reveal_prompt", "pl", 0.8,
       r"\b(?:pokaz|wypisz|wyswietl|podaj|ujawnij|powtorz|zdradz|wydrukuj|napisz)\s+(?:mi\s+)?"
       r"(?:(?:swoj|twoj)\w*\s+(?:instrukcj|polecen|zasad|prompt)\w*"
       r"|(?:\w+\s+)?(?:prompt\w*\s+systemow|systemow\w*\s+prompt|instrukcj\w*\s+systemow"
       r"|komunikat\w*\s+systemow))"),
    _p("reveal_prompt", "de", 0.8,
       r"\b(?:zeige?|gib|nenne|verrate|wiederhole|drucke)\s+(?:mir\s+|uns\s+)?"
       r"(?:(?:deine|deinen|ihre|ihren)\s+(?:\w+\s+)?(?:anweisung|instruktion|regel|prompt)"
       r"|(?:deine|deinen|ihre|ihren|den|die)\s+(?:\w+\s+)?(?:system[\s-]?prompt"
       r"|systemanweisung|system[\s-]?nachricht))"),
    # --- fake delimiters / role injection (language-independent) ---
    _p("fake_delimiter", "any", 0.7,
       r"<\|(?:im_start|im_end|system|endoftext|start_header_id|end_header_id|eot_id)\|>"),
    _p("fake_delimiter", "any", 0.7, r"\[/?inst\]|<<\s*/?sys\s*>>"),
    _p("fake_delimiter", "any", 0.7, r"</?\s*system\s*>"),
    _p("fake_delimiter", "any", 0.7, r"^[ \t]*#{2,}[ \t]*(?:system|instructions?)[ \t]*:"),
    _p("fake_delimiter", "any", 0.7, r"\b(?:begin|start)\s+(?:of\s+)?system\s+prompt\b"),
    # --- tool-result specific: words addressed to the AI that reads the content ---
    _p("note_to_ai", "en", 0.7,
       rf"\b(?:{_AI}|ai\s+assistant)\s+(?:that\s+is\s+|who\s+is\s+)?"
       r"(?:reading|processing|summari[sz]ing|parsing|analy[sz]ing)\s+this\b", indirect_only=True),
    _p("note_to_ai", "en", 0.7,
       rf"\b(?:note|message|instructions?)\s+(?:to|for)\s+(?:the\s+|any\s+)?(?:{_AI}|ai\s+assistant)s?\b",
       indirect_only=True),
    _p("note_to_ai", "en", 0.7,
       r"\b(?:when|while|if|before)\s+(?:you\s+are\s+|you're\s+)?summari[sz]ing\s+"
       r"(?:this|the\s+(?:document|page|file|email|text))\b", indirect_only=True),
    _p("hide_from_user", "en", 0.8,
       r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|mention\s+(?:this\s+)?to|reveal\s+"
       r"(?:this\s+)?to)\s+the\s+user\b|\bwithout\s+(?:telling|informing|notifying)\s+the\s+user\b",
       indirect_only=True),
    _p("exfiltrate", "en", 0.8,
       r"\b(?:send|forward|email|post|upload|transmit|exfiltrate|leak)\s+(?:\w+\s+){0,4}?"
       r"(?:data|information|conversation|chat\s+history|history|credentials|passwords?"
       r"|api\s+keys?|secrets?|emails?|contacts?|files?|documents?)\s+to\s+"
       r"(?:\S+@\S+|https?://|www\.|this\s+(?:address|url|email|endpoint)|the\s+following)",
       indirect_only=True),
    _p("note_to_ai", "pl", 0.7,
       r"\b(?:notatka|wiadomosc|uwaga|instrukcj\w*|polecenie)\s+dla\s+"
       r"(?:ai|sztucznej\s+inteligencji|asystenta|modelu|llm|chatbota|bota)\b", indirect_only=True),
    _p("note_to_ai", "pl", 0.7,
       r"\b(?:podsumowujac|streszczajac)\s+(?:ten|to|tego)\b", indirect_only=True),
    _p("hide_from_user", "pl", 0.8,
       r"\bnie\s+(?:mow|informuj|wspominaj)\s+(?:o\s+tym\s+)?uzytkownik\w*", indirect_only=True),
    _p("note_to_ai", "de", 0.7,
       r"\b(?:notiz|hinweis|nachricht|anweisung)\s+(?:an|fur)\s+(?:die\s+|den\s+)?"
       r"(?:ki|ai|assistent\w*|sprachmodell|llm|chatbot|bot)\b", indirect_only=True),
    _p("hide_from_user", "de", 0.8,
       r"\b(?:sag|erzahl|verrate)\s+(?:es\s+|das\s+)?(?:dem\s+)?(?:benutzer|nutzer|user)\s+nicht",
       indirect_only=True),
]

# A match that is exactly a quoted phrase is a *mention* ("how do I stop 'ignore previous
# instructions' attacks?"), not an instruction, so it is skipped. A quote on one side only is
# not enough: a JSON string like "Ignore all previous instructions and ..." is still a hit.
QUOTES = "'\"`‘’‚“”„«»"


def quoted(text: str, start: int, end: int) -> bool:
    before = text[max(0, start - 3):start].rstrip()
    after = text[end:end + 3].lstrip(" \t.!?,")
    return bool(before) and before[-1] in QUOTES and bool(after) and after[0] in QUOTES
