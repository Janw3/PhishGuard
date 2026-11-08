"""Evaluate every model on the own, modern test set.

Run from backend/:  python -m scripts.evaluate_own
Reads:   data/own_test/{phishing,legitimate}/*.txt   (written by scripts.anonymize_emails)
Writes:  reports/own_test_set.md   (numbers only, no email content)

This is the fairest comparison in the project: none of the models was trained
on these emails (phishing from Phishing Pot after the cutoff in
scripts/fetch_phishing_pot.py, legitimate emails from public Apache mailing lists).

The set is small, so every rate comes with a 95% confidence interval (Wilson).
Two models whose intervals overlap strongly are not reliably different.
"""

import json
import math
from pathlib import Path

import numpy as np
import pandas as pd

from app.config import ARTIFACTS_DIR, DATA_DIR, PRETRAINED_MODELS, REPORTS_DIR
from core.analysis import RULE_ALERT
from core.classifiers import load_registry
from core.email_parser import parse_txt
from core.language import detected_language, is_english
from core.preprocessing import normalize
from core.pretrained import load_pretrained
from core.signals import detect_signals, rule_score
from scripts.reporting import markdown_table

TEST_DIR = DATA_DIR / "own_test"
MANIFEST = DATA_DIR / "own_test_raw" / "phishing" / "MANIFEST.json"
LEGIT_MANIFEST = DATA_DIR / "own_test_raw" / "legitimate" / "MANIFEST.json"
LABELS = {"legitimate": 0, "phishing": 1}


def load_test_set(test_dir: Path = TEST_DIR) -> pd.DataFrame:
    rows = []
    for folder, label in LABELS.items():
        for path in sorted((test_dir / folder).glob("*.txt")):
            email = parse_txt(path.read_text(encoding="utf-8"))
            rows.append({"label": label, "text": email.text, "sender": email.sender, "reply_to": email.reply_to})
    return pd.DataFrame(rows, columns=["label", "text", "sender", "reply_to"])


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% confidence interval for a proportion; well-behaved for small n and rates near 0 or 1."""
    if n == 0:
        return float("nan"), float("nan")
    p = successes / n
    denominator = 1 + z**2 / n
    centre = (p + z**2 / (2 * n)) / denominator
    margin = z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)


def rate_with_interval(successes: int, n: int) -> str:
    if n == 0:
        return "n/a"
    low, high = wilson_interval(successes, n)
    return f"{successes / n:.2f} [{low:.2f}–{high:.2f}]"


def summarize(y_true: np.ndarray, flagged: np.ndarray) -> dict:
    phishing, legit = y_true == 1, y_true == 0
    caught, false_alarms = int((flagged & phishing).sum()), int((flagged & legit).sum())
    return {
        "phishing recall [95% CI]": rate_with_interval(caught, int(phishing.sum())),
        "false positive rate [95% CI]": rate_with_interval(false_alarms, int(legit.sum())),
        "missed phishing (FN)": int(phishing.sum()) - caught,
        "false alarms (FP)": false_alarms,
    }


def results_table(data: pd.DataFrame, predictions: dict[str, np.ndarray]) -> pd.DataFrame:
    y_true, rule_alert = data["label"].to_numpy(), data["rule_alert"].to_numpy()
    rows = {"rules alone": summarize(y_true, rule_alert)}
    for name, predicted in predictions.items():
        rows[name] = summarize(y_true, predicted)
        rows[f"{name} + rules"] = summarize(y_true, predicted | rule_alert)
    return pd.DataFrame.from_dict(rows, orient="index").rename_axis("model")


def main() -> None:
    data = load_test_set()
    if data.empty:
        raise SystemExit(f"No emails in {TEST_DIR}. Run scripts.fetch_phishing_pot and scripts.anonymize_emails first.")

    # Campaigns often send the same email many times; count each text once.
    before = len(data)
    data = data.loc[~data["text"].map(normalize).duplicated()].reset_index(drop=True)
    duplicates = before - len(data)
    # PhishGuard only analyzes English emails (the API rejects others), so only those are evaluated.
    data["language"] = data["text"].map(detected_language)
    english = data["text"].map(is_english)
    excluded = data.loc[~english].groupby(["language", "label"]).size().unstack(fill_value=0)
    excluded = excluded.reindex(columns=[1, 0], fill_value=0)
    excluded.columns = ["phishing", "legitimate"]
    data = data.loc[english].reset_index(drop=True)
    data["rule_alert"] = [
        rule_score(sum(detect_signals(t, s, r), [])) >= RULE_ALERT
        for t, s, r in zip(data["text"], data["sender"], data["reply_to"], strict=True)
    ]
    print(
        f"Own test set: {len(data)} unique English emails ({duplicates} duplicates, {int(excluded.values.sum())} non-English removed)"
    )

    models = {**load_registry(ARTIFACTS_DIR), **load_pretrained(PRETRAINED_MODELS)}
    predictions = {name: clf.predict_proba(data["text"].tolist())[:, 1] >= 0.5 for name, clf in models.items()}
    table = results_table(data, predictions)
    (REPORTS_DIR / "own_test_set.json").write_text(
        json.dumps(
            {
                "phishing": int(data["label"].sum()),
                "legitimate": int((data["label"] == 0).sum()),
                "results": {name: dict(row) for name, row in table.iterrows()},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    excluded_section = markdown_table(excluded.rename_axis("detected language")) if len(excluded) else "None."

    source = "Phishing Pot"
    if MANIFEST.exists():
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        source = (
            f"[Phishing Pot]({manifest['source']}) (CC BY-NC 4.0), commit `{manifest['commit'][:8]}`, "
            f"emails dated after {manifest['cutoff'][:10]}"
        )
    legit_source = "own emails, anonymized, not published"
    if LEGIT_MANIFEST.exists():
        legit = json.loads(LEGIT_MANIFEST.read_text(encoding="utf-8"))
        lists = ", ".join(f"`{v['list']}` ({v['chosen']})" for v in legit["lists"].values())
        legit_source = (
            f"public Apache mailing lists ([lists.apache.org](https://lists.apache.org)), months "
            f"{min(legit['months'])} to {max(legit['months'])}, random sample (seed {legit['seed']}): {lists}. "
            "Real and recent, but no personal transactional mail (password resets, bank or delivery notices), "
            "which are the hardest legitimate cases, so the false positive rate here is probably optimistic"
        )
    n_phishing, n_legit = int(data["label"].sum()), int((data["label"] == 0).sum())

    out = REPORTS_DIR / "own_test_set.md"
    out.write_text(
        "# Own modern test set\n\n"
        "Generated by `python -m scripts.evaluate_own`. Do not edit by hand.\n\n"
        f"- **Phishing ({n_phishing}):** {source}.\n"
        f"- **Legitimate ({n_legit}):** {legit_source}.\n"
        f"- Duplicates removed: {duplicates} (same text after normalization).\n"
        "- None of the models was trained on these emails. Emails are anonymized before use "
        "(placeholders like [REDACTED], user@domain), which slightly changes the text.\n"
        "- **English only:** PhishGuard only analyzes English emails (models, rules and explanations are "
        "English; the API rejects other languages), so non-English emails are excluded here, see below.\n"
        f"- **Model + rules**: flagged if the model says phishing OR the rule score reaches {RULE_ALERT}.\n\n"
        "## Results\n\n"
        "Values in brackets are 95% confidence intervals (Wilson). With a small test set they are wide: "
        "if two models' intervals overlap a lot, this set cannot tell which one is better.\n\n"
        f"{markdown_table(table)}\n\n"
        "## Excluded non-English emails\n\n"
        f"{excluded_section}\n",
        encoding="utf-8",
    )
    print(f"\nWritten to {out}")


if __name__ == "__main__":
    main()
