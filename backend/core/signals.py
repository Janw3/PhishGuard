"""Rule-based phishing signals (Phase 3, layer A).

Unlike the ML model, these rules do not depend on the writing style of a
training corpus. Each signal has an exact position in the ORIGINAL text, a
category, a severity between 0 and 1 and a curated plain-language explanation.

Three kinds of signals:
  - text rules:   urgency, threats, requests for passwords or bank data, money, ...
  - link checks:  IP-address links, URL shorteners, punycode, look-alike domains
  - sender checks (no position in the body): look-alike sender domains and
    display names that claim a brand the address does not belong to

The rules were written from general phishing knowledge, NOT tuned on the
evaluation data. Tuning them on those corpora would make the evaluation optimistic.
"""

import ipaddress
import math
import re
from dataclasses import dataclass
from email.utils import parseaddr
from urllib.parse import parse_qs, urlsplit


@dataclass(frozen=True)
class Signal:
    category: str
    feature: str  # the matched text, exactly as it appears
    explanation: str
    severity: float  # 0..1, how strongly this alone suggests phishing
    start: int = -1  # -1 for sender signals (they are not in the body)
    end: int = -1


# --------------------------------------------------------------------------- text rules


@dataclass(frozen=True)
class TextRule:
    category: str
    severity: float
    explanation: str
    patterns: tuple[re.Pattern, ...]


def _words(*alternatives: str) -> re.Pattern:
    """Case-insensitive regex that matches any alternative as whole words."""
    return re.compile(r"\b(?:" + "|".join(alternatives) + r")\b", re.IGNORECASE)


# Currency amounts start with a symbol, so they cannot begin with \b.
_AMOUNT = re.compile(r"(?:US\$|\$|€|£)\s?\d+(?:[.,]\d+)*(?:\s?(?:million|billion|m|bn)\b)?", re.IGNORECASE)

TEXT_RULES = (
    TextRule(
        "credentials",
        0.7,
        "This is an indicator of an attempt to collect your login data. Legitimate companies do not "
        "ask for passwords or identity checks by email, so never enter them via a link in a message.",
        (
            _words(
                r"passwords?",
                "passcode",
                r"log ?in (?:details|credentials|information)",
                "credentials",
                r"verify your (?:identity|account|information|details|email)",
                r"confirm your (?:identity|account|password|details|information)",
                r"security questions?",
                r"(?:pin|one-time) (?:code|number)",
            ),
        ),
    ),
    TextRule(
        "financial_data",
        0.7,
        "This is an indicator of an attempt to obtain your financial or identity details. Reputable "
        "organisations do not request card numbers, bank details or social security numbers by email.",
        (
            _words(
                r"credit ?card(?: (?:number|details|information))?",
                r"card (?:number|details)",
                "cvv",
                "cvc",
                r"bank (?:account|details)",
                "account number",
                "routing number",
                r"social security(?: number)?",
                "ssn",
                "iban",
            ),
        ),
    ),
    TextRule(
        "threat",
        0.5,
        "This is an indicator of a scare tactic: threatening to close or lock your account pushes you "
        "to act quickly. If you are worried, open the official website or app yourself instead of using this email.",
        (
            _words(
                r"suspend(?:ed|sion)?",
                r"terminat(?:ed|ion)",
                r"deactivat(?:ed|ion)",
                "locked",
                "restricted",
                "limited access",
                r"unusual (?:activity|sign-?in|login)",
                r"suspicious (?:activity|sign-?in|login)",
                r"unauthori[sz]ed (?:access|use|login|transactions?)",
                "legal action",
                r"permanently (?:deleted|closed|disabled)",
            ),
        ),
    ),
    TextRule(
        "money",
        0.5,
        "This is an indicator of a money scam: unexpected funds, fees or transfer requests are a classic "
        "fraud pattern. Never pay a fee to receive money, and check such requests through a channel you already know.",
        (
            _words(
                "wire transfer",
                "western union",
                r"money ?gram",
                r"(?:processing|transfer|release|clearance|administrative) fee",
                "bank transfer",
                "bitcoin",
                r"gift ?cards?",
                "inheritance",
                "next of kin",
                "beneficiary",
                r"\d[\d,.]* ?(?:million|billion)(?: (?:dollars|usd|pounds|euros))?",
            ),
            _AMOUNT,
        ),
    ),
    TextRule(
        "prize",
        0.5,
        "This is an indicator of a prize scam: you cannot win a lottery or competition you never entered. "
        "Be careful with emails that promise rewards in exchange for a reply or your details.",
        (
            _words(
                "lottery",
                r"you (?:have )?won",
                r"winners?",
                r"prizes?",
                "jackpot",
                r"(?:have been|were|was) selected",
                r"claim (?:your|the) (?:prize|reward|funds|money)",
            ),
        ),
    ),
    TextRule(
        "urgency",
        0.4,
        "This is an indicator of artificial time pressure, which is meant to make you act before you think. "
        "Real companies rarely demand a reaction within hours, so take your time and check the email first.",
        (
            _words(
                r"urgent(?:ly)?",
                "immediately",
                "immediate action",
                "act now",
                "as soon as possible",
                "right away",
                r"within \d+\s?(?:hours?|hrs?|days?|minutes?)",
                r"(?:expires?|expiring|expiration)(?: (?:today|soon))?",
                r"final (?:notice|warning|reminder)",
                "last chance",
                "action required",
            ),
        ),
    ),
    TextRule(
        "generic_greeting",
        0.3,
        "This is an indicator of a mass email: a company that knows you would usually use your name. "
        "Ask yourself whether the sender really knows who you are.",
        (
            _words(
                r"dear (?:customer|user|member|client|account (?:holder|user)|valued (?:customer|member|client)"
                r"|sir(?:/| or )madam|friend|beneficiary|employee|webmail user|e-?mail user)",
            ),
        ),
    ),
    TextRule(
        "call_to_action",
        0.3,
        "This is an indicator of a vague link: phrases like 'click here' hide where a link really leads. "
        "Check the real address of the link before you click it.",
        (
            _words(
                r"click (?:here|the link|below|on the link|the button)",
                "follow the link",
                r"(?:open|download) the attach(?:ment|ed file)",
                r"(?:log|sign) ?in (?:here|now|below)",
            ),
        ),
    ),
)


def find_text_signals(text: str) -> list[Signal]:
    signals = []
    for rule in TEXT_RULES:
        for pattern in rule.patterns:
            for match in pattern.finditer(text):
                signals.append(
                    Signal(rule.category, match.group(0), rule.explanation, rule.severity, match.start(), match.end())
                )
    return signals


# --------------------------------------------------------------------------- domains

# Brand -> its official registered domains. Kept short on purpose; extend as needed.
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"},
    "amazon": {"amazon.com", "amazon.de", "amazon.co.uk", "amazonaws.com"},
    "google": {"google.com", "gmail.com", "googleapis.com", "googleusercontent.com", "youtube.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "ebay": {"ebay.com", "ebay.de"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "sparkasse": {"sparkasse.de"},
    "whatsapp": {"whatsapp.com"},
}
OFFICIAL_DOMAINS = set().union(*BRANDS.values())
DISPLAY_NAMES = {
    "paypal": "PayPal",
    "bankofamerica": "Bank of America",
    "wellsfargo": "Wells Fargo",
    "dhl": "DHL",
    "linkedin": "LinkedIn",
    "docusign": "DocuSign",
    "whatsapp": "WhatsApp",
    "fedex": "FedEx",
    "ebay": "eBay",
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc",
    "rb.gy",
}

# Characters scammers swap for similar-looking letters, e.g. paypa1 -> paypal.
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"})
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}


def brand_name(brand: str) -> str:
    return DISPLAY_NAMES.get(brand, brand.capitalize())


def registered_domain(host: str) -> str:
    """The part of a host name that the owner registered, e.g. 'mail.paypal.com' -> 'paypal.com'.

    Simplified: handles 'example.co.uk'-style endings, but not the full public suffix list.
    """
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def levenshtein(a: str, b: str) -> int:
    """Number of single-character edits needed to turn a into b."""
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i]
        for j, char_b in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (char_a != char_b)))
        previous = current
    return previous[-1]


def impersonated_brand(host: str) -> tuple[str, str] | None:
    """Return (brand, kind) if host pretends to be a brand, else None.

    kind is "lookalike" (paypa1.com, paypall.com) or "brand_misuse"
    (paypal-security.com, paypal.com.evil.net): the brand name appears, but the
    registered domain does not belong to the brand.
    """
    reg = registered_domain(host)
    if reg in OFFICIAL_DOMAINS:
        return None
    tokens = [t for t in re.split(r"[.\-_]", host.lower()) if t]
    for token in tokens:
        cleaned = token.translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
        uses_homoglyphs = cleaned != token
        for brand in BRANDS:
            if cleaned == brand:
                return brand, "lookalike" if uses_homoglyphs else "brand_misuse"
            if len(brand) >= 5 and levenshtein(cleaned, brand) == 1:  # paypall, amazom
                return brand, "lookalike"
            if len(brand) >= 6 and (cleaned.startswith(brand) or cleaned.endswith(brand)):  # paypalsecurity
                return brand, "lookalike" if uses_homoglyphs else "brand_misuse"
    return None


# --------------------------------------------------------------------------- link checks

_URL = re.compile(
    r"(?:https?://|www\.|\b(?:" + "|".join(re.escape(s) for s in sorted(URL_SHORTENERS)) + r")/)"
    r"[^\s<>\"'()\[\]]*",
    re.IGNORECASE,
)


def _host(url: str) -> str | None:
    try:
        return urlsplit(url if "://" in url else f"http://{url}").hostname
    except ValueError:
        return None


def unwrap_safelink(url: str) -> str:
    """Outlook 'Safe Links' hide the real target in the url= parameter; return that target."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if parts.hostname and parts.hostname.endswith("safelinks.protection.outlook.com"):
        target = parse_qs(parts.query).get("url")
        if target:
            return target[0]
    return url


def host_findings(host: str) -> list[tuple[float, str]]:
    """(severity, explanation) for everything suspicious about a link's host."""
    try:
        ipaddress.ip_address(host)
        return [
            (
                0.8,
                "This is an indicator of a disguised link: it points to a bare number address instead of a "
                "company name. Legitimate companies almost always use their normal web address.",
            )
        ]
    except ValueError:
        pass

    findings = []
    if "xn--" in host:
        findings.append(
            (
                0.7,
                "This is an indicator of a disguised web address that uses look-alike characters from other "
                "alphabets. Type the company's address yourself instead of clicking.",
            )
        )
    impersonation = impersonated_brand(host)
    if impersonation:
        brand, kind = impersonation
        reg = registered_domain(host)
        if kind == "lookalike":
            findings.append(
                (
                    0.9,
                    f"This is an indicator of a fake web address: '{reg}' imitates {brand_name(brand)} but is "
                    "not one of its official addresses. Check the spelling letter by letter, or open the "
                    "official website yourself.",
                )
            )
        else:
            findings.append(
                (
                    0.8,
                    f"This is an indicator of a misleading web address: it contains the name "
                    f"{brand_name(brand)}, but the site actually belongs to '{reg}'. Only the part right "
                    "before .com (or similar) tells you who owns a website.",
                )
            )
    if registered_domain(host) in URL_SHORTENERS:
        findings.append(
            (
                0.4,
                "This is an indicator of a hidden destination: link shorteners hide where you will end up. "
                "Be careful, because you cannot see the real address before clicking.",
            )
        )
    return findings


def find_link_signals(text: str) -> list[Signal]:
    """Links written visibly in the text."""
    signals = []
    for match in _URL.finditer(text):
        url = match.group(0).rstrip(".,;:!?")
        start, end = match.start(), match.start() + len(url)
        host = _host(unwrap_safelink(url))
        if host:
            for severity, explanation in host_findings(host):
                signals.append(Signal("link", url, explanation, severity, start, end))
    return signals


_SHOWN_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)


def find_anchor_signals(text: str, anchors: list | None) -> list[Signal]:
    """HTML links: check the HIDDEN target behind each visible link text.

    `anchors` are objects with `.text` (what the reader sees) and `.href`
    (where the link really goes), e.g. core.email_parser.Link. The highlight is
    placed on the visible link text in `text`.
    """
    signals: list[Signal] = []
    cursor = 0
    for anchor in anchors or []:
        if not anchor.href.lower().startswith(("http://", "https://")):
            continue  # mailto:, tel:, #anchors
        host = _host(unwrap_safelink(anchor.href))
        start = text.find(anchor.text, cursor)
        if not host or start == -1:
            continue
        end = start + len(anchor.text)
        cursor = end

        def add(severity: float, explanation: str, start: int = start, end: int = end, feature: str = anchor.text):
            signals.append(Signal("link", feature, explanation, severity, start, end))

        shown = _SHOWN_DOMAIN.search(anchor.text)
        if shown and registered_domain(shown.group(0)) != registered_domain(host):
            add(
                0.8,
                # The full host, not just the registered domain: on hosting platforms
                # (e.g. *.run.app) the registered domain alone would hide who runs the site.
                f"This is an indicator of a disguised link: it shows '{registered_domain(shown.group(0))}', but "
                f"actually leads to '{host}'. Hover over a link to see its real address before you click.",
            )
        for severity, explanation in host_findings(host):
            add(severity, explanation)
    return signals


# --------------------------------------------------------------------------- sender checks


FREE_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "aol.com",
    "icloud.com", "gmx.de", "gmx.net", "web.de", "proton.me", "protonmail.com", "mail.ru", "yandex.ru",
}  # fmt: skip


def _domain(header: str | None) -> str:
    address = parseaddr(header or "")[1]
    return address.rsplit("@", 1)[1].lower() if "@" in address else ""


def find_reply_to_signals(sender: str | None, reply_to: str | None) -> list[Signal]:
    """Replies that go somewhere other than the sender's domain."""
    sender_domain, reply_domain = _domain(sender), _domain(reply_to)
    if not sender_domain or not reply_domain:
        return []
    if registered_domain(sender_domain) == registered_domain(reply_domain):
        return []
    if reply_domain in FREE_MAIL_DOMAINS and sender_domain not in FREE_MAIL_DOMAINS:
        return [
            Signal(
                "sender",
                reply_domain,
                f"This is an indicator of a redirected reply: the email claims to come from '{sender_domain}', "
                f"but answers go to a private '{reply_domain}' account. Companies do not ask you to reply to "
                "free email accounts.",
                0.8,
            )
        ]
    return [
        Signal(
            "sender",
            reply_domain,
            f"This is an indicator of a redirected reply: answers go to '{reply_domain}', not to the sender's "
            f"domain '{sender_domain}'. Mailing lists do this too, but check where your reply would end up.",
            0.6,
        )
    ]


def find_sender_signals(sender: str | None, reply_to: str | None = None) -> list[Signal]:
    return _from_signals(sender) + find_reply_to_signals(sender, reply_to)


def _from_signals(sender: str | None) -> list[Signal]:
    if not sender:
        return []
    name, address = parseaddr(sender)
    if "@" not in address:
        return []
    domain = address.rsplit("@", 1)[1].lower()
    signals = []

    impersonation = impersonated_brand(domain)
    if impersonation:
        brand, kind = impersonation
        if kind == "lookalike":
            signals.append(
                Signal(
                    "sender",
                    domain,
                    f"This is an indicator of a fake sender address: '{domain}' imitates {brand_name(brand)} but is not "
                    "one of its official domains. Look closely at the sender address, not just the name shown.",
                    0.9,
                )
            )
        else:
            signals.append(
                Signal(
                    "sender",
                    domain,
                    f"This is an indicator of a misleading sender address: it contains the name {brand_name(brand)}, "
                    f"but the email comes from '{registered_domain(domain)}'. Check whether this is really the "
                    "company's official address.",
                    0.8,
                )
            )
        return signals

    words = set(re.findall(r"[a-z]+", name.lower()))
    joined = "".join(re.findall(r"[a-z]+", name.lower()))  # "Bank of America" -> "bankofamerica"
    for brand, official in BRANDS.items():
        named = brand in words or (len(brand) >= 6 and brand in joined)
        if named and registered_domain(domain) not in official:
            signals.append(
                Signal(
                    "sender",
                    name,
                    f"This is an indicator of a faked sender name: the name says {brand_name(brand)}, but the email "
                    f"comes from '{domain}'. Anyone can type any name, so always check the actual address.",
                    0.8,
                )
            )
            break
    return signals


# --------------------------------------------------------------------------- combined


def detect_signals(
    text: str,
    sender: str | None = None,
    reply_to: str | None = None,
    anchors: list | None = None,
) -> tuple[list[Signal], list[Signal]]:
    """Return (signals with a position in the text, sender signals).

    `reply_to` and `anchors` (HTML links) are only available for full emails (.eml).
    """
    positioned = find_text_signals(text) + find_link_signals(text) + find_anchor_signals(text, anchors)
    return positioned, find_sender_signals(sender, reply_to)


def rule_score(signals: list[Signal]) -> float:
    """Combine signals into one score between 0 and 1.

    Only the strongest signal per category counts, so ten mentions of "account
    suspended" do not add up. Different categories combine like independent
    pieces of evidence: score = 1 - product(1 - severity).
    """
    strongest: dict[str, float] = {}
    for s in signals:
        strongest[s.category] = max(strongest.get(s.category, 0.0), s.severity)
    return 1.0 - math.prod(1.0 - severity for severity in strongest.values())
