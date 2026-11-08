"""Download recent legitimate emails from public Apache mailing lists for the own test set.

Run from backend/:  python -m scripts.fetch_mailing_lists [--per-list 15] [--months 6]
Writes:  data/own_test_raw/legitimate/ml-<list>-<n>.eml  and  data/own_test_raw/legitimate/MANIFEST.json

Source: the public archives of the Apache Software Foundation (https://lists.apache.org),
downloaded as monthly mbox files. The emails are public, but their content belongs
to their authors: they are only used locally for evaluation and never committed
or redistributed. Reports contain numbers only.

Why mailing lists: there is no public dataset of recent, real legitimate emails
(see README). Mailing lists are real, recent and reproducible. Several kinds of
lists are mixed so the set is not only developer chat:
  announcements (newsletter-like, many links), user support, developer
  discussion, and automated issue-tracker notifications (system emails).
Limitation: they contain no personal transactional mail (password resets,
bank or delivery notices), the hardest legitimate cases. The report says so.
"""

import argparse
import hashlib
import json
import mailbox
import random
import tempfile
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path

from app.config import DATA_DIR
from core.email_parser import parse_eml

LISTS = {
    "announce": ("announce", "apache.org"),
    "tomcat-users": ("users", "tomcat.apache.org"),
    "httpd-dev": ("dev", "httpd.apache.org"),
    "arrow-issues": ("issues", "arrow.apache.org"),  # automated GitHub issue notifications
}
CUTOFF = datetime(2024, 11, 1, tzinfo=UTC)
OUT_DIR = DATA_DIR / "own_test_raw" / "legitimate"
SEED = 42
MIN_BODY_CHARS = 80
USER_AGENT = "PhishGuard-test-set-fetcher"


def months_back(count: int, today: datetime | None = None) -> list[str]:
    """The last `count` complete months as 'YYYY-MM', newest first."""
    today = today or datetime.now(UTC)
    year, month = today.year, today.month
    result = []
    for _ in range(count):
        month -= 1
        if month == 0:
            year, month = year - 1, 12
        result.append(f"{year:04d}-{month:02d}")
    return result


def download_mbox(list_name: str, domain: str, month: str) -> bytes:
    query = urllib.parse.urlencode({"list": list_name, "domain": domain, "d": month})
    request = urllib.request.Request(
        f"https://lists.apache.org/api/mbox.lua?{query}", headers={"User-Agent": USER_AGENT}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def messages_from_mbox(data: bytes) -> list[bytes]:
    """Split an mbox file into raw messages (via a temporary file, which mailbox needs)."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "month.mbox"
        path.write_bytes(data)
        box = mailbox.mbox(path)
        try:
            return [box.get_bytes(key) for key in box.keys()]
        finally:
            box.close()


def is_usable(raw: bytes) -> bool:
    """Dated after the cutoff and with a readable body of some length."""
    email = parse_eml(raw)
    if len(email.body.strip()) < MIN_BODY_CHARS:
        return False
    date_header = next((line for line in raw.split(b"\n")[:80] if line.lower().startswith(b"date:")), b"")
    try:
        date = parsedate_to_datetime(date_header[5:].decode("ascii", errors="ignore").strip())
    except (TypeError, ValueError):
        return False
    date = date if date.tzinfo else date.replace(tzinfo=UTC)
    return date >= CUTOFF


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--per-list", type=int, default=15, help="emails per mailing list (default 15)")
    parser.add_argument("--months", type=int, default=6, help="how many recent months to sample from (default 6)")
    args = parser.parse_args()

    rng = random.Random(SEED)
    months = months_back(args.months)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    manifest_lists = {}

    for key, (list_name, domain) in LISTS.items():
        candidates: dict[str, bytes] = {}
        for month in months:
            for raw in messages_from_mbox(download_mbox(list_name, domain, month)):
                digest = hashlib.sha1(raw).hexdigest()
                if digest not in candidates and is_usable(raw):
                    candidates[digest] = raw
        chosen = rng.sample(sorted(candidates), min(args.per_list, len(candidates)))
        for i, digest in enumerate(chosen, 1):
            (OUT_DIR / f"ml-{key}-{i:02d}.eml").write_bytes(candidates[digest])
        manifest_lists[key] = {
            "list": f"{list_name}@{domain}",
            "candidates": len(candidates),
            "chosen": len(chosen),
            "sha1": chosen,
        }
        print(f"  {list_name}@{domain}: {len(chosen)} of {len(candidates)} usable emails", flush=True)

    manifest = {
        "source": "https://lists.apache.org (public archives of the Apache Software Foundation)",
        "note": "Public emails; content belongs to its authors. Used locally for evaluation only, never redistributed.",
        "months": months,
        "cutoff": CUTOFF.isoformat(),
        "seed": SEED,
        "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "lists": manifest_lists,
    }
    (OUT_DIR / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    total = sum(v["chosen"] for v in manifest_lists.values())
    print(f"\nKept {total} emails in {OUT_DIR}. Next: python -m scripts.anonymize_emails")


if __name__ == "__main__":
    main()
