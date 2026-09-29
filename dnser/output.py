"""Terminal output for dnser: markup, colors and tables, standard library only.

cli.py writes a small markup language — ``[green]ok[/green]``,
``[bold yellow]warning[/]`` — and prints it through the Console and Table
defined here.

Color follows the usual CLI conventions: on when writing to a terminal; off
when output is piped or redirected, when NO_COLOR is set
(https://no-color.org), when TERM=dumb, or after set_color(False), which the
--no-color flag calls. Without color the tags are simply dropped, so the text
is the same either way.

escape() and the renderer are a matched pair: anything passed through
escape() prints verbatim and can never become a tag. The renderer also strips
control characters, so text from providers.json or a backup filename can't
put terminal escape sequences on the user's screen.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import textwrap
import unicodedata
from typing import TextIO

__all__ = ["Console", "Table", "escape", "render_markup", "set_color"]

# SGR parameters for the style words markup may use. A bracketed word that
# isn't listed here is plain text, not a tag: '[0]', '[y/N]' and '[default]'
# print as written.
_SGR = {
    "bold": "1",
    "dim": "2",
    "italic": "3",
    "underline": "4",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
}
_RESET = "\x1b[0m"

# An escaped backslash, an escaped '[', or a candidate tag: [style words],
# [/style words] or [/]. render_markup decides whether a candidate is a tag.
_TOKEN_RE = re.compile(r"\\\\|\\\[|\[(/?)([a-z ]*)\]")

# C0/C1 control characters other than tab and newline (ESC is \x1b).
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

# None means auto-detect per stream; see _color_enabled().
_color_setting: bool | None = None


def set_color(enabled: bool | None) -> None:
    """Force color on (True) or off (False); None restores auto-detection."""
    global _color_setting
    _color_setting = enabled


def _color_enabled(stream: TextIO) -> bool:
    if _color_setting is not None:
        return _color_setting
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    try:
        return stream.isatty()
    except (AttributeError, ValueError):  # no isatty, or a closed stream
        return False


def escape(text: str) -> str:
    """Make `text` print literally, whatever brackets or backslashes it holds."""
    return text.replace("\\", "\\\\").replace("[", "\\[")


def _sgr(codes: list[str]) -> str:
    return f"\x1b[{';'.join(codes)}m" if codes else ""


def _style_codes(style: str) -> list[str]:
    return [_SGR[word] for word in style.split() if word in _SGR]


def render_markup(text: str, *, color: bool = False, style: str = "") -> str:
    """Resolve markup to plain text, or to ANSI-colored text when `color`.

    `style` applies to the whole string underneath any tags, e.g. the
    "bold red" of the error console.
    """
    base = _style_codes(style)
    stack: list[tuple[str, list[str]]] = []  # open tags: (style words, codes)

    def active() -> list[str]:
        return base + [code for _, codes in stack for code in codes]

    def render_token(match: re.Match[str]) -> str:
        found = match.group()
        if found == "\\\\":
            return "\\"
        if found == "\\[":
            return "["
        closing, words = match.group(1) == "/", match.group(2).split()
        if not all(word in _SGR for word in words) or not (words or closing):
            return found  # brackets, but not a tag
        name = " ".join(words)
        if not closing:
            codes = [_SGR[word] for word in words]
            stack.append((name, codes))
            return _sgr(codes) if color else ""
        # '[/]' closes the innermost tag, '[/red]' the innermost red one.
        for index in range(len(stack) - 1, -1, -1):
            if not name or stack[index][0] == name:
                del stack[index]
                return _RESET + _sgr(active()) if color else ""
        return ""  # closes nothing that is open

    # Control characters go first, before any escape codes of ours exist.
    body = _TOKEN_RE.sub(render_token, _CONTROL_RE.sub("", text))
    if not color:
        return body
    return _sgr(base) + body + (_RESET if active() else "")


def _width(text: str) -> int:
    """Display width in terminal cells: wide characters take two, combining none."""
    width = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        width += 2 if unicodedata.east_asian_width(ch) in "WF" else 1
    return width


def _styled(text: str, style: str, color: bool) -> str:
    """Wrap already-plain `text` in `style` when color is on."""
    codes = _style_codes(style) if color else []
    return _sgr(codes) + text + _RESET if codes else text


class Table:
    """A box-drawn table whose cells are markup::

        ┏━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
        ┃ Protocol ┃ State         ┃
        ┡━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
        │ LLMNR    │ no            │
        └──────────┴───────────────┘

    Columns size to their widest cell. When that is wider than the terminal,
    the widest columns give up space first and their cells wrap onto extra
    lines, but no column gets narrower than its longest word.
    """

    def __init__(
        self,
        *,
        title: str | None = None,
        show_header: bool = True,
        header_style: str = "bold",
        show_lines: bool = False,
    ) -> None:
        self.title = title
        self.show_header = show_header
        self.header_style = header_style
        self.show_lines = show_lines
        self._headers: list[str] = []
        self._justify: list[str] = []
        self._styles: list[str] = []
        self._rows: list[list[str] | None] = []  # None marks a section break

    def add_column(self, header: str = "", *, justify: str = "left", style: str = "") -> None:
        self._headers.append(header)
        self._justify.append(justify)
        self._styles.append(style)

    def add_row(self, *cells: str) -> None:
        if len(cells) > len(self._headers):
            raise ValueError(f"{len(cells)} cells for {len(self._headers)} columns")
        self._rows.append(list(cells) + [""] * (len(self._headers) - len(cells)))

    def add_section(self) -> None:
        """Draw a rule before the next row."""
        self._rows.append(None)

    def _fit_widths(self, headers: list[str], rows: list[list[str]]) -> list[int]:
        """Column widths: natural if they fit the terminal, else shrunk to fit."""
        widths, minimum = [], []
        for index, header in enumerate(headers):
            texts = [row[index] for row in rows] + ([header] if self.show_header else [])
            widths.append(max(map(_width, texts), default=0))
            words = [word for text in texts for word in text.split()]
            minimum.append(max(map(_width, words), default=0))

        # Each column also costs '│ ' before and a space after, plus the final '│'.
        excess = sum(widths) + 3 * len(widths) + 1 - shutil.get_terminal_size().columns
        while excess > 0:
            shrinkable = [i for i, width in enumerate(widths) if width > minimum[i]]
            if not shrinkable:
                break  # can't fit: let the terminal wrap the lines
            widest = max(shrinkable, key=lambda i: widths[i])
            widths[widest] -= 1
            excess -= 1
        return widths

    def render(self, *, color: bool = False) -> str:
        if not self._headers:
            return ""
        headers = [render_markup(h) for h in self._headers]
        plain_rows = [
            None if row is None else [render_markup(c) for c in row] for row in self._rows
        ]
        widths = self._fit_widths(headers, [row for row in plain_rows if row is not None])

        def rule(left: str, fill: str, cross: str, right: str) -> str:
            return left + cross.join(fill * (w + 2) for w in widths) + right

        def line(cells: list[tuple[str, str]], edge: str) -> str:
            """Lay out (display text, plain text) pairs, padded by plain width."""
            out = []
            for (shown, plain), width, justify in zip(cells, widths, self._justify, strict=True):
                pad = " " * (width - _width(plain))
                out.append(pad + shown if justify == "right" else shown + pad)
            return f"{edge} " + f" {edge} ".join(out) + f" {edge}"

        def row_lines(markup: list[str], plain: list[str]) -> list[str]:
            columns = []
            for cell, text, width, style in zip(markup, plain, widths, self._styles, strict=True):
                if _width(text) <= width:
                    columns.append([(render_markup(cell, color=color, style=style), text)])
                else:
                    # Wrapping works on the plain text, so a wrapped cell
                    # keeps its column style but loses any inline tags.
                    chunks = textwrap.wrap(text, width) or [""]
                    columns.append([(_styled(chunk, style, color), chunk) for chunk in chunks])
            height = max(len(column) for column in columns)
            return [
                line([column[i] if i < len(column) else ("", "") for column in columns], "│")
                for i in range(height)
            ]

        lines = []
        if self.title:
            title = render_markup(self.title)
            total = sum(widths) + 3 * len(widths) + 1
            lines.append(
                " " * max(0, (total - _width(title)) // 2) + _styled(title, "italic", color)
            )

        if self.show_header:
            lines.append(rule("┏", "━", "┳", "┓"))
            lines.append(line([(_styled(h, self.header_style, color), h) for h in headers], "┃"))
            lines.append(rule("┡", "━", "╇", "┩"))
        else:
            lines.append(rule("┌", "─", "┬", "┐"))

        first, section = True, False
        for markup, plain in zip(self._rows, plain_rows, strict=True):
            if markup is None or plain is None:
                section = True
                continue
            if not first and (section or self.show_lines):
                lines.append(rule("├", "─", "┼", "┤"))
            first, section = False, False
            lines.extend(row_lines(markup, plain))

        lines.append(rule("└", "─", "┴", "┘"))
        return "\n".join(lines)


class Console:
    """Prints markup strings and Tables to stdout, or to stderr."""

    def __init__(self, *, stderr: bool = False, style: str = "") -> None:
        self._stderr = stderr
        self._style = style

    def print(self, *objects: str | Table, sep: str = " ", end: str = "\n") -> None:
        # Look the stream up on every call so redirection after construction
        # (including pytest's capsys) is honoured.
        stream = sys.stderr if self._stderr else sys.stdout
        color = _color_enabled(stream)
        text = sep.join(
            obj.render(color=color)
            if isinstance(obj, Table)
            else render_markup(obj, color=color, style=self._style)
            for obj in objects
        )
        try:
            stream.write(text + end)
        except UnicodeEncodeError:
            # A terminal that can't show box drawing or symbols gets '?'
            # in their place rather than a crash.
            encoding = getattr(stream, "encoding", None) or "ascii"
            stream.write((text + end).encode(encoding, "replace").decode(encoding))
