"""Download recent real phishing emails from Phishing Pot for the own test set.

Run from backend/:  python -m scripts.fetch_phishing_pot [--count 50]
Writes:  data/own_test_raw/phishing/pp-<number>.eml  and  data/own_test_raw/phishing/MANIFEST.json

Source: https://github.com/rf-peixoto/phishing_pot, real phishing emails
collected via honeypots, licensed CC BY-NC 4.0 (non-commercial use, link to the
repository). The files stay in data/ and are never committed.

Only English emails are kept, because PhishGuard only analyzes English emails.

Why only RECENT emails: the pretrained cybersectony model was trained on data
published in October 2024. Emails dated after CUTOFF cannot be in its training
data, so the test stays fair for every model. The script walks from the newest
sample backwards and keeps emails whose Date header is after CUTOFF.
"""

import argparse
import json
import re
import urllib.request
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

from app.config import DATA_DIR
from core.email_parser import parse_eml
from core.language import is_english

REPO = "rf-peixoto/phishing_pot"
CUTOFF = datetime(2024, 11, 1, tzinfo=UTC)
OUT_DIR = DATA_DIR / "own_test_raw" / "phishing"
USER_AGENT = "PhishGuard-test-set-fetcher"


def _get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def latest_commit() -> str:
    return json.loads(_get(f"https://api.github.com/repos/{REPO}/commits/main"))["sha"]


def sample_numbers(commit: str) -> list[int]:
    """All sample numbers in email/, newest (highest) first."""
    tree = json.loads(_get(f"https://api.github.com/repos/{REPO}/git/trees/{commit}?recursive=1"))
    numbers = [
        int(m.group(1)) for item in tree["tree"] if (m := re.fullmatch(r"email/sample-(\d+)\.eml", item["path"]))
    ]
    return sorted(numbers, reverse=True)


def email_date(raw: bytes) -> datetime | None:
    match = re.search(rb"^Date:\s*(.+)$", raw, re.MULTILINE | re.IGNORECASE)
    if not match:
        return None
    try:
        date = parsedate_to_datetime(match.group(1).decode("ascii", errors="ignore").strip())
    except (TypeError, ValueError):
        return None
    return date if date.tzinfo else date.replace(tzinfo=UTC)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--count", type=int, default=50, help="how many English emails to keep (default 50)")
    args = parser.parse_args()

    commit = latest_commit()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    kept, skipped_old, skipped_no_date, skipped_language = [], 0, 0, 0

    for number in sample_numbers(commit):
        if len(kept) >= args.count:
            break
        target = OUT_DIR / f"pp-{number}.eml"
        raw = (
            target.read_bytes()
            if target.exists()
            else _get(f"https://raw.githubusercontent.com/{REPO}/{commit}/email/sample-{number}.eml")
        )
        date = email_date(raw)
        if date is None:
            skipped_no_date += 1
            continue
        if date < CUTOFF:
            skipped_old += 1
            continue
        email = parse_eml(raw)
        if not is_english(email.text):  # PhishGuard only supports English
            skipped_language += 1
            target.unlink(missing_ok=True)
            continue
        target.write_bytes(raw)
        kept.append({"file": target.name, "sample": number, "date": date.isoformat()})
        print(f"  kept sample-{number} ({date.date()})", flush=True)

    manifest = {
        "source": f"https://github.com/{REPO}",
        "license": "CC BY-NC 4.0 (non-commercial use, attribution: link to the repository)",
        "commit": commit,
        "cutoff": CUTOFF.isoformat(),
        "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "emails": kept,
        "skipped_before_cutoff": skipped_old,
        "skipped_without_date": skipped_no_date,
        "skipped_not_english": skipped_language,
    }
    (OUT_DIR / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\nKept {len(kept)} emails in {OUT_DIR} (commit {commit[:8]}). Next: python -m scripts.anonymize_emails")


if __name__ == "__main__":
    main()
