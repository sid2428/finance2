"""Pure-Python fuzzy string matching.

The spec calls for Jaro-Winkler (typos/transliteration) plus Double Metaphone
(phonetic equivalence). To keep the reference implementation dependency-free we
implement Jaro-Winkler exactly and a compact phonetic key (Soundex-family) that
captures the phonetic-equivalence signal Double Metaphone is used for. Swap in
``jellyfish``/``metaphone`` in production without changing call sites.
"""

from __future__ import annotations


def jaro_similarity(s1: str, s2: str) -> float:
    if s1 == s2:
        return 1.0
    if not s1 or not s2:
        return 0.0

    len1, len2 = len(s1), len(s2)
    match_distance = max(len1, len2) // 2 - 1
    match_distance = max(match_distance, 0)

    s1_matches = [False] * len1
    s2_matches = [False] * len2

    matches = 0
    for i in range(len1):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len2)
        for j in range(start, end):
            if s2_matches[j] or s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    # Count transpositions.
    transpositions = 0
    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1
    transpositions //= 2

    m = matches
    return (m / len1 + m / len2 + (m - transpositions) / m) / 3.0


def jaro_winkler_similarity(s1: str, s2: str, prefix_weight: float = 0.1) -> float:
    """Jaro-Winkler: boosts scores for strings sharing a common prefix."""
    jaro = jaro_similarity(s1, s2)
    # Common prefix up to 4 chars.
    prefix = 0
    for c1, c2 in zip(s1, s2):
        if c1 != c2:
            break
        prefix += 1
        if prefix == 4:
            break
    return jaro + prefix * prefix_weight * (1 - jaro)


_SOUNDEX_MAP = {
    **dict.fromkeys("BFPV", "1"),
    **dict.fromkeys("CGJKQSXZ", "2"),
    **dict.fromkeys("DT", "3"),
    **dict.fromkeys("L", "4"),
    **dict.fromkeys("MN", "5"),
    **dict.fromkeys("R", "6"),
}


def phonetic_key(name: str) -> str:
    """A Soundex-style phonetic key.

    Collapses a name to a leading letter + up to three consonant codes so that
    transliteration variants that *sound* alike (Iosif / Yosef, Muhammad /
    Mohammed) collide. Multi-token names are keyed on their most significant
    (longest) token.
    """
    name = "".join(ch for ch in name.upper() if ch.isalpha() or ch.isspace())
    tokens = [t for t in name.split() if t]
    if not tokens:
        return ""
    token = max(tokens, key=len)

    first = token[0]
    key = first
    prev = _SOUNDEX_MAP.get(first, "")
    for ch in token[1:]:
        code = _SOUNDEX_MAP.get(ch, "")
        if code and code != prev:
            key += code
        # Vowels (and H/W/Y) reset the "previous code" so real repeats survive.
        if ch in "AEIOUYHW":
            prev = ""
        else:
            prev = code
        if len(key) >= 4:
            break
    return (key + "000")[:4]
