"""normalize() - cheap, deterministic de-obfuscation run BEFORE pattern matching.

Source: 01-AI-SPEC.md S4. Mitigates trivial obfuscation (Pitfall 4): NFKC fold
(homoglyph / compatibility chars), strip zero-width / bidi / BOM smuggling chars,
and opportunistically base64-decode long blobs so the plaintext is also matchable.

This is a PARTIAL, honest mitigation - paraphrase / novel-encoding / typoglycemia
evasion is out of Phase-1 scope (deferred to the Phase-3 classifier). stdlib only:
re / unicodedata / base64. No network, no model.
"""

import base64
import re
import unicodedata

# Zero-width / bidi / BOM smuggling codepoints, declared NUMERICALLY (never as literal
# invisible characters in source - the repo's injection hook correctly flags literal
# invisibles, and an invisible char in a regex literal is unreviewable):
#   U+200B..U+200F, U+202A..U+202E, U+2060, U+FEFF.
_SMUGGLING_CODEPOINTS = (
    tuple(range(0x200B, 0x2010))  # U+200B..U+200F zero-width + bidi marks
    + tuple(range(0x202A, 0x202F))  # U+202A..U+202E bidi embedding/override
    + (0x2060, 0xFEFF)  # word joiner, BOM / zero-width no-break space
)
_ZERO_WIDTH = re.compile("[" + "".join(chr(c) for c in _SMUGGLING_CODEPOINTS) + "]")

# A long ASCII base64 blob (bounded lower bound; the input is already 32 KB-capped
# upstream, so the unbounded run is not a ReDoS vector). The trailing edge uses a
# negative lookahead rather than \b: a padded blob ends in '='/'==' (non-word), and a
# trailing \b would refuse to include the padding, yielding an unpadded - and thus
# undecodable - substring (Rule 1 fix to the AI-SPEC verbatim pattern).
_B64 = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")


def normalize(text: str) -> str:
    """Fold homoglyphs, strip zero-width smuggling, opportunistically decode base64."""
    text = unicodedata.normalize("NFKC", text)  # fold homoglyphs / compatibility chars
    text = _ZERO_WIDTH.sub("", text)  # strip zero-width smuggling
    # Opportunistically append decoded base64 so _EXFIL/_OVERRIDE match the plaintext too.
    decoded: list[str] = []
    for m in _B64.finditer(text):
        try:
            decoded.append(base64.b64decode(m.group(), validate=True).decode("utf-8", "ignore"))
        except Exception:
            pass  # not valid base64 - ignore, never raise
    if decoded:
        text += "\n" + "\n".join(decoded)
    return text
