"""Convert Jira wiki markup to Markdown as Gitea and GitHub render it.

Written for copying an issue to another system: text, URLs and file names stay as they are, only
the markup changes. Embedded images stay at their place as ``![name](name)`` with the attachment
file name as target, so the caller can replace the target with the URL of the uploaded file.

The older ``JiraPreprocessor.jira_to_markdown`` is kept for the other tools. It works with global
regular expressions that change text: ``_`` in URLs becomes ``*``, ``* item`` lists become bold
text, the query string of smart links is dropped, and a ``|`` in a link text breaks the link.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

__all__ = ["WikiConversion", "wiki_to_markdown"]

_SMART_PARTS = {"smart-link", "smart-card", "smart-embed"}
_KNOWN_MACROS = {"code", "noformat", "quote", "panel", "color", "anchor"}
_EMOTICONS = {
    "(/)": "✅",
    "(x)": "❌",
    "(!)": "⚠️",
    "(i)": "ℹ️",
    "(?)": "❓",
    "(y)": "👍",
    "(n)": "👎",
    "(on)": "💡",
    "(off)": "💡",
    "(*)": "⭐",
    "(+)": "➕",
    "(-)": "➖",
}
_URL_SCHEMES = ("http://", "https://", "ftp://", "mailto:", "file:")
_FILE_NAME = re.compile(r"\.[A-Za-z0-9]{1,6}$")
_PH = "\x00"


@dataclass
class WikiConversion:
    """Result of :func:`wiki_to_markdown`."""

    markdown: str
    images: list[str] = field(default_factory=list)
    """File names of embedded images, in the order of the text (URLs not included)."""
    attachment_links: list[str] = field(default_factory=list)
    """File names linked with ``[^name]``."""
    unconverted: list[str] = field(default_factory=list)
    """Names of macros left as text, e.g. ``{status}``."""
    mentions: list[str] = field(default_factory=list)
    """Account IDs of ``[~accountid:…]`` mentions that could not be resolved."""


def wiki_to_markdown(
    text: str | None, mention: Callable[[str], str | None] | None = None
) -> WikiConversion:
    """Convert Jira wiki markup to Markdown.

    Args:
        text: Jira wiki markup, e.g. the description of an issue from REST API v2.
        mention: Optional function from an account ID (or user name) to a display name.

    Returns:
        The Markdown text and what the conversion found.
    """
    result = WikiConversion(markdown="")
    if not text:
        return result
    converter = _Converter(result, mention)
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    result.markdown = "\n".join(converter.blocks(lines)).strip("\n")
    return result


class _Converter:
    def __init__(
        self, result: WikiConversion, mention: Callable[[str], str | None] | None
    ) -> None:
        self.result = result
        self.mention = mention

    # --- blocks ------------------------------------------------------------------------------

    def blocks(self, lines: list[str]) -> list[str]:
        out: list[str] = []
        widths: list[int] = []  # marker width per open list level
        in_list = False
        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            m = re.match(r"^\s*\{(code|noformat)((?::[^}]*)?)\}(.*)$", line)
            if m:
                i = self._fenced(lines, i, m, out)
                widths, in_list = [], False
                continue

            m = re.match(r"^\s*\{(quote|panel)((?::[^}]*)?)\}(.*)$", line)
            if m:
                i = self._quoted(lines, i, m, out)
                widths, in_list = [], False
                continue

            if not stripped:
                out.append("")
                widths, in_list = [], False
                i += 1
                continue

            if stripped.startswith("|"):
                rows = []
                while i < len(lines) and lines[i].strip().startswith("|"):
                    rows.append(lines[i].strip())
                    i += 1
                if out and out[-1] != "":
                    out.append("")
                out.extend(self._table(rows))
                if i < len(lines) and lines[i].strip():
                    out.append("")
                widths, in_list = [], False
                continue

            m = re.match(r"^\s*((?:[*#]+)|-)\s+(\S.*)$", line)
            if m and not re.fullmatch(r"-{2,}", m.group(2).strip()):
                markers, content = m.groups()
                depth = len(markers)
                marker = "1." if markers[-1] == "#" else "-"
                widths = (widths + [0] * depth)[: depth - 1]
                indent = " " * sum(widths)
                widths.append(len(marker) + 1)
                if not in_list and out and out[-1] != "":
                    out.append("")
                out.append(f"{indent}{marker} {self.inline(content)}")
                in_list = True
                i += 1
                continue

            if in_list:
                out.append("")
                widths, in_list = [], False

            m = re.match(r"^\s*h([1-6])\.\s*(.*)$", line)
            if m:
                out.append("#" * int(m.group(1)) + " " + self.inline(m.group(2)))
            elif re.match(r"^\s*bq\.", line):
                out.append("> " + self.inline(re.sub(r"^\s*bq\.\s?", "", line)))
            elif re.fullmatch(r"-{4,}", stripped):
                out.append("---")
            else:
                out.append(self._paragraph_line(stripped))
            i += 1
        return out

    def _paragraph_line(self, stripped: str) -> str:
        converted = self.inline(stripped)
        if re.fullmatch(r"[=-]+", converted) or re.match(r"^(?:>|\+\s|#)", converted):
            return "\\" + converted
        return converted

    def _collect(
        self, lines: list[str], i: int, rest: str, close: re.Pattern
    ) -> tuple[list[str], str, int]:
        """Collect lines up to the closing tag; returns (body lines, text after tag, next index)."""
        body: list[str] = []
        cm = close.search(rest)
        if cm:
            return [rest[: cm.start()]], rest[cm.end() :], i + 1
        body.append(rest)
        i += 1
        while i < len(lines):
            cm = close.search(lines[i])
            if cm:
                body.append(lines[i][: cm.start()])
                return body, lines[i][cm.end() :], i + 1
            body.append(lines[i])
            i += 1
        return body, "", i

    def _fenced(self, lines: list[str], i: int, m: re.Match, out: list[str]) -> int:
        kind, params, rest = m.group(1), m.group(2), m.group(3)
        body, after, i = self._collect(lines, i, rest, re.compile(rf"\{{{kind}\}}"))
        while body and not body[0].strip():
            body.pop(0)
        while body and not body[-1].strip():
            body.pop()
        lang = ""
        if kind == "code" and params:
            for part in params[1:].split("|"):
                part = part.strip()
                if part and "=" not in part:
                    lang = part.lower()
                    break
        fence = "```"
        while any(fence in b for b in body):
            fence += "`"
        if out and out[-1] != "":
            out.append("")
        out.append(fence + lang)
        out.extend(body)
        out.append(fence)
        if after.strip():
            out.append("")
            out.append(self._paragraph_line(after.strip()))
        return i

    def _quoted(self, lines: list[str], i: int, m: re.Match, out: list[str]) -> int:
        kind, params, rest = m.group(1), m.group(2), m.group(3)
        body, after, i = self._collect(lines, i, rest, re.compile(rf"\{{{kind}\}}"))
        inner = self.blocks(body)
        while inner and not inner[-1].strip():
            inner.pop()
        while inner and not inner[0].strip():
            inner.pop(0)
        if kind == "panel":
            title = re.search(r"title=([^|}]*)", params or "")
            if title and title.group(1).strip():
                inner = ["**" + self.inline(title.group(1).strip()) + "**", ""] + inner
        if out and out[-1] != "":
            out.append("")
        out.extend(("> " + b) if b else ">" for b in inner)
        if after.strip():
            out.append("")
            out.append(self._paragraph_line(after.strip()))
        return i

    def _table(self, rows: list[str]) -> list[str]:
        parsed = [self._cells(r) for r in rows]
        width = max(len(cells) for _, cells in parsed)
        out = []
        start = 0
        if parsed[0][0]:
            out.append(self._row(parsed[0][1], width))
            start = 1
        else:
            out.append(self._row([], width))
        out.append("|" + " --- |" * width)
        for header, cells in parsed[start:]:
            if header:
                cells = [f"**{c}**" if c.strip() else c for c in cells]
            out.append(self._row(cells, width))
        return out

    def _row(self, cells: list[str], width: int) -> str:
        cells = cells + [""] * (width - len(cells))
        return "| " + " | ".join(cells) + " |"

    def _cells(self, row: str) -> tuple[bool, list[str]]:
        header = row.startswith("||")
        cells: list[str] = []
        buf = ""
        depth = 0
        i = 0
        while i < len(row):
            ch = row[i]
            if ch == "\\" and i + 1 < len(row) and row[i + 1] == "|":
                buf += "\\|"
                i += 2
                continue
            if row.startswith("{{", i):
                end = row.find("}}", i + 2)
                if end > 0:
                    buf += row[i : end + 2]
                    i = end + 2
                    continue
            if ch == "[":
                depth += 1
            elif ch == "]" and depth:
                depth -= 1
            if ch == "|" and depth == 0:
                cells.append(buf)
                buf = ""
                i += 2 if row.startswith("||", i) else 1
                continue
            buf += ch
            i += 1
        cells.append(buf)
        if cells and not cells[0].strip():
            cells = cells[1:]
        if cells and not cells[-1].strip():
            cells = cells[:-1]
        return header, [
            self.inline(c.strip()).replace("|", "\\|").replace("\\\\|", "\\|")
            for c in cells
        ]

    # --- inline ------------------------------------------------------------------------------

    def inline(self, text: str) -> str:
        tokens: list[str] = []

        def keep(value: str) -> str:
            tokens.append(value)
            return f"{_PH}{len(tokens) - 1}{_PH}"

        def code_span(content: str) -> str:
            ticks = "`"
            while ticks in content:
                ticks += "`"
            pad = " " if content.startswith("`") or content.endswith("`") else ""
            return keep(f"{ticks}{pad}{content}{pad}{ticks}")

        text = re.sub(r"\{\{(.+?)\}\}", lambda m: code_span(m.group(1)), text)
        text = re.sub(
            r"\{(code|noformat)(?::[^}]*)?\}(.*?)\{\1\}",
            lambda m: code_span(m.group(2)),
            text,
        )
        text = re.sub(r"\{color(?::[^}]*)?\}", "", text)
        text = re.sub(r"\{anchor(?::[^}]*)?\}", "", text)
        for macro in re.findall(r"(?<!\{)\{([A-Za-z][\w-]*)(?::[^}]*)?\}(?!\})", text):
            if macro not in _KNOWN_MACROS and macro not in self.result.unconverted:
                self.result.unconverted.append(macro)
        text = text.replace("\\\\", keep("<br>"))
        text = re.sub(r"\\([^\w\s])", lambda m: keep("\\" + m.group(1)), text)
        text = re.sub(r"\[([^\[\]\n]+)\]", lambda m: self._link(m, keep), text)
        text = re.sub(
            r"(?<![\w!])!([^\s!|)][^!|\n]*?)(?:\|([^!\n]*))?!",
            lambda m: self._image(m, keep),
            text,
        )
        text = re.sub(
            r"(?:https?|ftp)://[^\s\[\]<>\"]+", lambda m: keep(m.group(0)), text
        )
        for code, emoji in _EMOTICONS.items():
            text = re.sub(
                r"(?<!\w)" + re.escape(code), lambda m, e=emoji: keep(e), text
            )
        text = self._format(text)
        while _PH in text:
            text = re.sub(f"{_PH}(\\d+){_PH}", lambda m: tokens[int(m.group(1))], text)
        return text

    def _link(self, m: re.Match, keep: Callable[[str], str]) -> str:
        content = m.group(1)
        if content.startswith("~"):
            account = content[1:]
            if account.startswith("accountid:"):
                account = account[len("accountid:") :]
            name = self.mention(account) if self.mention else None
            if name:
                return keep("@" + name)
            if account not in self.result.mentions:
                self.result.mentions.append(account)
            return keep(m.group(0))
        parts = content.split("|")
        while len(parts) > 2 and parts[-1].strip() in _SMART_PARTS:
            parts.pop()
        if len(parts) == 2 and parts[1].strip() in _SMART_PARTS:
            parts.pop()
        target = parts[-1].strip()
        label = "|".join(parts[:-1]).strip() if len(parts) > 1 else ""
        if target.startswith("^"):
            name = target[1:].strip()
            if name not in self.result.attachment_links:
                self.result.attachment_links.append(name)
            return keep(f"[{self._label(label or name)}]({_destination(name)})")
        if target.startswith("#") and len(parts) == 1:
            return keep(f"[{self._label(target[1:])}]({_destination(target)})")
        if target.lower().startswith(_URL_SCHEMES) or (
            len(parts) > 1 and (target.startswith(("/", "#")))
        ):
            return keep(f"[{self._label(label or target)}]({_destination(target)})")
        return m.group(0)

    def _label(self, label: str) -> str:
        if label.lower().startswith(_URL_SCHEMES) and " " not in label:
            return label
        return self.inline(label).replace("]", "\\]").replace("[", "\\[")

    def _image(self, m: re.Match, keep: Callable[[str], str]) -> str:
        target = m.group(1).strip()
        is_url = target.lower().startswith(("http://", "https://"))
        if not is_url and not _FILE_NAME.search(target):
            return m.group(0)
        alt = None
        for param in (m.group(2) or "").split(","):
            param = param.strip()
            if param.startswith("alt="):
                alt = param[4:].strip().strip("\"'")
        if not is_url and target not in self.result.images:
            self.result.images.append(target)
        if alt is None:
            alt = "" if is_url else target
        alt = alt.replace("]", "\\]").replace("[", "\\[")
        return keep(f"![{alt}]({_destination(target)})")

    # (marker, escaped marker, Markdown open, Markdown close, only at word boundaries)
    _SPANS = [
        ("??", r"\?\?", "<cite>", "</cite>", True),
        ("*", r"\*", "**", "**", True),
        ("_", r"_", "*", "*", True),
        ("-", r"-", "~~", "~~", True),
        ("+", r"\+", "<ins>", "</ins>", True),
        ("^", r"\^", "<sup>", "</sup>", False),
        ("~", r"~", "<sub>", "</sub>", False),
    ]

    def _format(self, text: str) -> str:
        alternatives = []
        for idx, (_, esc, _o, _c, bounded) in enumerate(self._SPANS):
            word = r"\w" if bounded else ""
            alternatives.append(
                rf"(?<![{word}{esc}]){esc}(?P<s{idx}>[^\s{esc}](?:.*?[^\s{esc}])?){esc}(?![{word}{esc}])"
            )
        pattern = re.compile("|".join(alternatives))
        out = []
        pos = 0
        for m in pattern.finditer(text):
            out.append(_escape(text[pos : m.start()]))
            idx = next(int(k[1:]) for k, v in m.groupdict().items() if v is not None)
            _, _, open_md, close_md, _ = self._SPANS[idx]
            out.append(open_md + self._format(m.group(f"s{idx}")) + close_md)
            pos = m.end()
        out.append(_escape(text[pos:]))
        return "".join(out)


def _escape(text: str) -> str:
    """Escape characters that Markdown would read as markup but Jira shows as text."""
    text = re.sub(r"(?<=\s)---(?=\s)", "—", text)
    text = re.sub(r"(?<=\s)--(?=\s)", "–", text)
    text = text.replace("*", "\\*").replace("`", "\\`").replace("~", "\\~")
    text = re.sub(r"<(?=[A-Za-z/!?])", r"\\<", text)
    text = text.replace("](", "\\](").replace("][", "\\][")
    return text


def _destination(target: str) -> str:
    if re.search(r"[\s()<>]", target):
        return "<" + target.replace("<", "%3C").replace(">", "%3E") + ">"
    return target
