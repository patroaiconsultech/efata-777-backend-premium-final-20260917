from __future__ import annotations

import re


_TERMINAL = re.compile(r"[.!?](?=\s|$)|\n{2,}")
_ABBREVIATIONS = {
    "sr.", "sra.", "srta.", "dr.", "dra.", "prof.", "profa.",
    "etc.", "ex.", "p.ex.", "a.k.a.", "st.", "vs.", "fig.",
}


class SentenceSegmenter:
    """Emit safe speech-sized text segments without cutting words or URLs."""

    def __init__(self, max_chars: int = 420):
        if max_chars < 80:
            raise ValueError("REALTIME_SEGMENT_MAX_CHARS_TOO_SMALL")
        self.max_chars = max_chars
        self._buffer = ""

    def push(self, delta: str) -> list[str]:
        if delta:
            self._buffer += str(delta)
        return self._extract()

    def flush(self) -> list[str]:
        value = self._buffer.strip()
        self._buffer = ""
        return [value] if value else []

    def _extract(self) -> list[str]:
        segments: list[str] = []
        while self._buffer:
            paragraph = self._buffer.find("\n\n")
            if paragraph > 0:
                value = self._buffer[:paragraph].strip()
                self._buffer = self._buffer[paragraph + 2 :].lstrip()
                if value:
                    segments.append(value)
                continue
            match = self._safe_boundary()
            if match is not None:
                value = self._buffer[: match.end()].strip()
                self._buffer = self._buffer[match.end() :].lstrip()
                if value:
                    segments.append(value)
                continue

            if len(self._buffer) <= self.max_chars:
                break

            cut = self._buffer.rfind(" ", 0, self.max_chars + 1)
            if cut < 80:
                cut = self._buffer.find(" ", self.max_chars)
            if cut <= 0:
                break
            value = self._buffer[:cut].strip()
            self._buffer = self._buffer[cut:].lstrip()
            if value:
                segments.append(value)
        return segments

    def _safe_boundary(self):
        for match in _TERMINAL.finditer(self._buffer):
            boundary = self._buffer[: match.end()].rstrip()
            last_word = boundary.split()[-1].casefold() if boundary.split() else ""
            if last_word in _ABBREVIATIONS:
                continue
            # A terminal mark inside a URL or decimal is not followed by the
            # whitespace/end condition enforced by the regex above.
            return match
        return None
