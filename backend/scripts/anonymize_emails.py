"""Anonymize the raw test emails before they are used anywhere.

Run from backend/:  python -m scripts.anonymize_emails
Reads:   data/own_test_raw/{phishing,legitimate}/*.eml or *.txt
         data/own_test_raw/personal_terms.txt   (optional: your name, addresses, ... one per line)
Writes:  data/own_test/{phishing,legitimate}/<name>.txt   (Subject/From/Reply-To lines + body)

What is replaced:
  - every term from personal_terms.txt (case-insensitive)      -> [REDACTED]
  - email addresses: the part before @ (domain stays)           -> user@domain
      The domain is a signal for the rules (paypa1.com); the person is not.
  - display name of the sender in LEGITIMATE emails             -> Sender
      (usually a real person; in phishing it is chosen by the attacker and kept)
  - IBANs, phone numbers, other long numbers                    -> [IBAN] / [NUMBER]
  - link query strings and long ID-like path parts              -> removed / [TOKEN]
      (tracking links often contain IDs that identify the recipient)

Automatic anonymization is never perfect: read the output files before you
share them or use them in screenshots. Everything stays in data/ (never committed).
"""

import re
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from app.config import DATA_DIR
from core.email_parser import ParsedEmail, parse_eml, parse_txt
from core.signals import unwrap_safelink

RAW_DIR = DATA_DIR / "own_test_raw"
OUT_DIR = DATA_DIR / "own_test"
LABELS = ("phishing", "legitimate")

_EMAIL = re.compile(r"\b[\w.+-]+@([\w-]+(?:\.[\w-]+)+)\b")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,4})?\b")
_LONG_NUMBER = re.compile(r"(?<![\w$€£.,])\+?\d[\d \t/().-]{5,}\d(?![\w.,])")
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_TOKEN = re.compile(r"^(?=.*\d)[A-Za-z0-9_-]{16,}$")
# Always removed: the Phishing Pot honeypot address that phishers paste into subjects and greetings.
ALWAYS_REDACT = ["phishing@pot"]


def load_personal_terms(path: Path = RAW_DIR / "personal_terms.txt") -> list[str]:
    terms = list(ALWAYS_REDACT)
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()
        terms += [t.strip() for t in lines if t.strip() and not t.startswith("#")]
    return sorted(terms, key=len, reverse=True)  # longest first: "Jan Weller" before "Jan"


def _clean_path(path: str) -> str:
    return "/".join("[TOKEN]" if _TOKEN.match(seg) else seg for seg in path.split("/"))


def clean_url(url: str) -> str:
    """Unwrap Safe Links, drop query string and fragment, replace ID-like path segments."""
    try:
        parts = urlsplit(unwrap_safelink(url))
        return urlunsplit((parts.scheme, parts.netloc, _clean_path(parts.path), "", ""))
    except ValueError:
        # Malformed URLs are common in phishing (e.g. stray brackets): just cut off ? and #.
        return _clean_path(re.split(r"[?#]", url, maxsplit=1)[0])


def anonymize_text(text: str, personal_terms: list[str]) -> str:
    for term in personal_terms:
        text = re.sub(re.escape(term), "[REDACTED]", text, flags=re.IGNORECASE)
    text = _URL.sub(lambda m: clean_url(m.group(0)), text)
    text = _EMAIL.sub(lambda m: f"user@{m.group(1)}", text)
    text = _IBAN.sub("[IBAN]", text)
    return _LONG_NUMBER.sub(lambda m: "[NUMBER]" if sum(c.isdigit() for c in m.group(0)) >= 7 else m.group(0), text)


def anonymize_address(header: str, personal_terms: list[str], keep_name: bool) -> str:
    if not header:
        return ""
    name, address = parseaddr(header)
    domain = address.rsplit("@", 1)[1] if "@" in address else ""
    address = f"user@{domain}" if domain else ""
    name = anonymize_text(name, personal_terms) if keep_name else ("Sender" if name else "")
    # Built by hand: email.utils.formataddr fails on domains with non-ASCII characters.
    if not address:
        return name
    return f"{name} <{address}>" if name else address


def anonymize(email: ParsedEmail, label: str, personal_terms: list[str]) -> ParsedEmail:
    keep_name = label == "phishing"
    return ParsedEmail(
        subject=anonymize_text(email.subject, personal_terms),
        sender=anonymize_address(email.sender, personal_terms, keep_name),
        reply_to=anonymize_address(email.reply_to, personal_terms, keep_name),
        body=anonymize_text(email.body, personal_terms),
    )


def to_txt(email: ParsedEmail) -> str:
    headers = [f"Subject: {email.subject}", f"From: {email.sender}"]
    if email.reply_to:
        headers.append(f"Reply-To: {email.reply_to}")
    return "\n".join(headers) + "\n\n" + email.body + "\n"


def main() -> None:
    terms = load_personal_terms()
    if not terms:
        print("Note: no data/own_test_raw/personal_terms.txt found; only generic patterns are replaced.")
    total = 0
    for label in LABELS:
        source, target = RAW_DIR / label, OUT_DIR / label
        if not source.exists():
            continue
        target.mkdir(parents=True, exist_ok=True)
        for path in sorted(source.iterdir()):
            if path.suffix.lower() == ".eml":
                email = parse_eml(path.read_bytes())
            elif path.suffix.lower() == ".txt":
                email = parse_txt(path.read_text(encoding="utf-8", errors="replace"))
            else:
                continue
            if not email.body.strip():
                print(f"  skipped {label}/{path.name}: no readable body")
                continue
            (target / f"{path.stem}.txt").write_text(to_txt(anonymize(email, label, terms)), encoding="utf-8")
            total += 1
    print(f"Anonymized {total} emails into {OUT_DIR}. Please skim them before sharing anything.")


if __name__ == "__main__":
    main()
