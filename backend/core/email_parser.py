"""Read real email files (.eml) into the parts PhishGuard analyzes.

Uses only Python's built-in `email` module. Shared by POST /analyze-eml and
the own test set (scripts/anonymize_emails.py, scripts/evaluate_own.py).

Body selection: the HTML part converted to text if there is one (that is what
mail clients show, and the only place where a link's visible text can differ
from its target), otherwise the text/plain part. Attachments are ignored.
"""

import re
from dataclasses import dataclass, field
from email import policy
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.parser import BytesParser
from html.parser import HTMLParser


@dataclass(frozen=True)
class Link:
    """An HTML link: the text the reader sees and where it really leads."""

    text: str
    href: str


@dataclass
class ParsedEmail:
    subject: str
    sender: str  # From header as shown, e.g. 'PayPal <service@paypal.com>'
    reply_to: str
    body: str
    links: list[str] = field(default_factory=list)  # href targets found in the HTML part
    anchors: list[Link] = field(default_factory=list)  # visible text + target of each HTML link

    @property
    def text(self) -> str:
        """Subject + blank line + body: the same layout as data/prepared.csv."""
        return f"{self.subject}\n\n{self.body}".strip()


class _HTMLToText(HTMLParser):
    """Very small HTML-to-text converter: keeps visible text, line breaks for blocks, collects links."""

    BLOCK_TAGS = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "table", "section"}
    SKIP_TAGS = {"script", "style", "head", "title"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[str] = []
        self.anchors: list[Link] = []
        self._skip_depth = 0
        self._anchor_href: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP_TAGS:
            self._skip_depth += 1
        if tag in self.BLOCK_TAGS:
            self.parts.append("\n")
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)
                self._anchor_href, self._anchor_text = href, []

    def handle_endtag(self, tag):
        if tag in self.SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1
        if tag in self.BLOCK_TAGS:
            self.parts.append("\n")
        if tag == "a" and self._anchor_href is not None:
            text = " ".join("".join(self._anchor_text).split())
            if text:
                self.anchors.append(Link(text, self._anchor_href))
            self._anchor_href = None

    def handle_data(self, data):
        if not self._skip_depth:
            self.parts.append(data)
            if self._anchor_href is not None:
                self._anchor_text.append(data)

    def text(self) -> str:
        raw = "".join(self.parts)
        lines = [" ".join(line.split()) for line in raw.splitlines()]
        return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def html_to_text(html: str) -> tuple[str, list[str]]:
    text, links, _ = _convert_html(html)
    return text, links


def _convert_html(html: str) -> tuple[str, list[str], list[Link]]:
    parser = _HTMLToText()
    parser.feed(html)
    parser.close()
    return parser.text(), parser.links, parser.anchors


def _part_content(part: EmailMessage) -> str:
    """Decode a text part. Many (phishing) emails declare the wrong charset, e.g.
    "utf-8" for Windows-1252 bytes, so the declared charset is tried strictly first,
    then Windows-1252, and only then UTF-8 with replacement characters."""
    payload = part.get_payload(decode=True) or b""
    for charset in (part.get_content_charset(), "cp1252"):
        if not charset:
            continue
        try:
            return payload.decode(charset)
        except (LookupError, UnicodeDecodeError):
            continue
    return payload.decode("utf-8", errors="replace")


def parse_eml(raw: bytes) -> ParsedEmail:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    plain = message.get_body(preferencelist=("plain",))
    html = message.get_body(preferencelist=("html",))

    # Prefer the HTML version: it is what mail clients show, and only there can a
    # link's visible text differ from its real target. Fall back to plain text.
    links: list[str] = []
    anchors: list[Link] = []
    body = ""
    if html is not None:
        body, links, anchors = _convert_html(_part_content(html))
    if not body and plain is not None:
        body = _part_content(plain).strip()

    return ParsedEmail(
        subject=_header(raw, message, "Subject"),
        sender=_header(raw, message, "From"),
        reply_to=_header(raw, message, "Reply-To"),
        body=body,
        links=links,
        anchors=anchors,
    )


def _header(raw: bytes, message: EmailMessage, name: str) -> str:
    """A header as readable text.

    Headers should be ASCII (non-ASCII text encoded as =?utf-8?...?=), and then
    Python's parser handles them. Many phishing emails put raw UTF-8 or
    Windows-1252 bytes into headers instead, which the parser turns into
    replacement characters. For those, the raw bytes are decoded here directly.
    """
    value = str(message.get(name, "") or "")
    if "�" not in value and not any("\udc80" <= c <= "\udcff" for c in value):
        return value.strip()
    head = raw.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
    match = re.search(rb"^" + name.encode() + rb":[ \t]*(.*(?:\r?\n[ \t].*)*)", head, re.IGNORECASE | re.MULTILINE)
    if not match:
        return value.strip()
    folded = re.sub(rb"\r?\n[ \t]+", b" ", match.group(1))
    for charset in ("utf-8", "cp1252"):
        try:
            return str(make_header(decode_header(folded.decode(charset)))).strip()
        except (UnicodeDecodeError, LookupError, ValueError):
            continue
    return value.strip()


def parse_txt(text: str) -> ParsedEmail:
    """Plain-text email: optional 'Subject:' / 'From:' header lines, a blank line, then the body."""
    headers: dict[str, str] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines) and re.match(r"^(Subject|From|Reply-To):", lines[i], re.IGNORECASE):
        key, value = lines[i].split(":", 1)
        headers[key.lower()] = value.strip()
        i += 1
    body = "\n".join(lines[i:]).strip()
    return ParsedEmail(
        subject=headers.get("subject", ""),
        sender=headers.get("from", ""),
        reply_to=headers.get("reply-to", ""),
        body=body,
    )
