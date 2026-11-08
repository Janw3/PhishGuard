"""Merge the Zenodo source CSVs into one clean training file.

Dataset: "Phishing Email Curated Datasets", https://zenodo.org/records/8339691
Please cite (required by the authors):
  1. A. I. Champa, M. F. Rabbi, and M. F. Zibran, "Why phishing emails escape
     detection: A closer look at the failure points," ISDFS 2024, pp. 1-6.
  2. A. I. Champa, M. F. Rabbi, and M. F. Zibran, "Curated datasets and feature
     analysis for phishing email detection with machine learning," ICMI 2024, pp. 1-7.

What it does:
  1. Loads every known source CSV that exists in data/ (missing ones are skipped).
  2. Brings them into one schema: source, label, subject, body, sender, date, text.
     `text` is subject + body, kept RAW (capitals, newlines), so later phases can
     run rules and LIME on it. The model normalizes it itself.
  3. Keeps the task about PHISHING: label 1 only counts from sources whose
     positives are phishing or fraud (PHISHING_SOURCES). Spam from the other
     sources is dropped. It is neither phishing nor legitimate, and labeling it
     0 would teach the model that scam-like text is safe.
  4. Removes duplicates, compared on normalize(text), across all sources.
     If the same text appears with different labels, all copies are dropped,
     because we cannot know which label is right.
  5. Caps legitimate emails at MAX_LEGIT_PER_SOURCE per source (random sample,
     fixed seed), so no single corpus dominates the "legitimate" class and the
     model cannot simply learn the style of one big source.
  6. Writes data/prepared.csv and reports/data_summary.md.

Run from backend/:  python -m scripts.prepare_data
"""

import pandas as pd

from app.config import DATA_DIR, PREPARED_DATA_PATH, REPORTS_DIR
from core.preprocessing import normalize
from scripts.reporting import DATASET_CITATION

# Zenodo file name (spelled exactly as in the record) -> source name.
# Label 1 means "spam/phishing" in every file, but for most sources that is
# general spam, not phishing (see PHISHING_SOURCES).
#
# Deliberately NOT used: Nazario_5.csv and Nigerian_5.csv. They are balanced
# mixes that add legitimate emails from other corpora, so their rows have no
# single source and would duplicate emails from the files below.
SOURCE_FILES = {
    "CEAS_08.csv": "ceas_08",
    "Enron.csv": "enron",
    "Ling.csv": "ling",
    "Nazario.csv": "nazario",
    "Nigerian_Fraud.csv": "nigerian_fraud",
    "SpamAssasin.csv": "spamassassin",
    "TREC_05.csv": "trec_05",
    "TREC_06.csv": "trec_06",
    "TREC_07.csv": "trec_07",
}
# Sources whose positive class is actual phishing or fraud rather than general spam.
PHISHING_SOURCES = {"nazario", "nigerian_fraud"}

COLUMNS = ["source", "label", "subject", "body", "sender", "date", "text"]

# Enron alone has ~15,000 legitimate emails, about 3x all phishing emails.
# Capping every source at the same size keeps the legitimate class a mix of
# corpora instead of mostly Enron. Train with class_weight="balanced" for the
# remaining phishing/legitimate imbalance.
MAX_LEGIT_PER_SOURCE = 4000
SEED = 42


def load_source(df: pd.DataFrame, source: str) -> pd.DataFrame:
    """Bring one raw source table into the common schema."""
    out = pd.DataFrame(
        {
            "source": source,
            "label": pd.to_numeric(df["label"], errors="coerce"),
            "subject": df.get("subject", pd.Series("", index=df.index)).fillna("").astype(str),
            "body": df["body"].fillna("").astype(str),
            "sender": df.get("sender", pd.Series("", index=df.index)).fillna("").astype(str),
            "date": df.get("date", pd.Series("", index=df.index)).fillna("").astype(str),
        }
    )
    out = out[out["label"].isin([0, 1]) & (out["body"].str.strip() != "")].copy()
    out["label"] = out["label"].astype(int)
    out["text"] = (out["subject"].str.strip() + "\n\n" + out["body"]).str.strip()
    return out[COLUMNS]


def keep_phishing_positives(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Drop label-1 rows from spam-only sources; return the drop count per source."""
    is_spam = (df["label"] == 1) & ~df["source"].isin(PHISHING_SOURCES)
    dropped = df[is_spam].groupby("source").size().to_dict()
    return df[~is_spam].reset_index(drop=True), {k: int(v) for k, v in dropped.items()}


def cap_legitimate_per_source(
    df: pd.DataFrame, max_per_source: int = MAX_LEGIT_PER_SOURCE, seed: int = SEED
) -> tuple[pd.DataFrame, dict]:
    """Randomly keep at most max_per_source legitimate emails per source.

    Phishing emails are never removed. Returns the number removed per source.
    """
    legit = df[df["label"] == 0]
    # Shuffle once with a fixed seed, then keep the first N rows of each source.
    sampled = legit.sample(frac=1, random_state=seed).groupby("source").head(max_per_source)
    removed = (legit.groupby("source").size() - sampled.groupby("source").size()).to_dict()
    kept = pd.concat([df[df["label"] == 1], sampled]).sort_index()
    return kept.reset_index(drop=True), {k: int(v) for k, v in removed.items() if v > 0}


def deduplicate(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Drop duplicate texts across all sources; drop texts with conflicting labels."""
    key = df["text"].map(normalize)
    labels_per_key = df.groupby(key)["label"].nunique()
    conflicting = key.isin(labels_per_key[labels_per_key > 1].index)

    kept = df[~conflicting]
    duplicated = key[~conflicting].duplicated(keep="first")
    stats = {
        "conflicting_label_rows": int(conflicting.sum()),
        "duplicate_rows": int(duplicated.sum()),
    }
    return kept[~duplicated].reset_index(drop=True), stats


def summary_report(
    raw_counts: dict, prepared: pd.DataFrame, stats: dict, spam_dropped: dict, missing: list[str]
) -> str:
    per_source = prepared.groupby("source")["label"].agg(emails="count", phishing="sum")
    per_source["legitimate"] = per_source["emails"] - per_source["phishing"]
    per_source["raw rows"] = pd.Series(raw_counts)
    per_source["spam dropped"] = pd.Series(spam_dropped).reindex(per_source.index).fillna(0).astype(int)
    per_source["over cap"] = pd.Series(stats["capped"]).reindex(per_source.index).fillna(0).astype(int)
    per_source["role"] = [
        "phishing/fraud source" if s in PHISHING_SOURCES else "legitimate emails only" for s in per_source.index
    ]
    per_source = per_source[["raw rows", "spam dropped", "over cap", "emails", "phishing", "legitimate", "role"]]

    lines = ["| source | " + " | ".join(per_source.columns) + " |", "|---" * (len(per_source.columns) + 1) + "|"]
    for source, row in per_source.iterrows():
        lines.append(f"| {source} | " + " | ".join(str(v) for v in row) + " |")

    return (
        "# Data summary\n\n"
        "Generated by `python -m scripts.prepare_data`. Do not edit by hand.\n\n"
        f"{DATASET_CITATION}\n"
        "## Per source (after cleaning)\n\n" + "\n".join(lines) + "\n\n## Cleaning\n\n"
        f"- Total emails kept: {len(prepared)} "
        f"({int(prepared['label'].sum())} phishing, {int((prepared['label'] == 0).sum())} legitimate)\n"
        f"- Spam dropped from spam-only sources: {sum(spam_dropped.values())}\n"
        f"- Duplicates removed (same normalized text, also across sources): {stats['duplicate_rows']}\n"
        f"- Rows removed because the same text had conflicting labels: {stats['conflicting_label_rows']}\n"
        f"- Legitimate emails removed by the cap of {MAX_LEGIT_PER_SOURCE} per source "
        f"(random sample, seed {SEED}): {sum(stats['capped'].values())}\n"
        f"- Source files not found in `data/`: {', '.join(missing) if missing else 'none'}\n\n"
        "## Caveats\n\n"
        "- The task is phishing vs. legitimate. Label 1 in the raw files means *spam* for most sources, "
        "so those positives are dropped. Only "
        + ", ".join(sorted(PHISHING_SOURCES))
        + " provide phishing/fraud emails.\n"
        "- Phishing and legitimate emails therefore come from different sources. A model can learn the "
        "*style of a source* instead of phishing, so the random-split score is optimistic. "
        "The source-held-out evaluation and the own modern test set are the honest numbers.\n"
    )


def main() -> None:
    frames, raw_counts, missing = [], {}, []
    for filename, source in SOURCE_FILES.items():
        path = DATA_DIR / filename
        if not path.exists():
            missing.append(filename)
            continue
        raw = pd.read_csv(path, encoding_errors="replace", low_memory=False)
        raw_counts[source] = len(raw)
        frames.append(load_source(raw, source))
        print(f"Loaded {filename}: {len(raw)} rows")

    if not frames:
        raise SystemExit(f"No source files found in {DATA_DIR}. Expected any of: {', '.join(SOURCE_FILES)}")

    # Drop spam BEFORE deduplicating, so a spam copy can never win over a phishing original.
    phishing_task, spam_dropped = keep_phishing_positives(pd.concat(frames, ignore_index=True))
    deduplicated, stats = deduplicate(phishing_task)
    # Cap AFTER deduplicating, so the cap counts unique emails.
    prepared, stats["capped"] = cap_legitimate_per_source(deduplicated)
    prepared.to_csv(PREPARED_DATA_PATH, index=False)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORTS_DIR / "data_summary.md"
    report_path.write_text(summary_report(raw_counts, prepared, stats, spam_dropped, missing), encoding="utf-8")

    print(
        f"\nKept {len(prepared)} emails ({int(prepared['label'].sum())} phishing). "
        f"Dropped {sum(spam_dropped.values())} spam, {stats['duplicate_rows']} duplicates "
        f"and {stats['conflicting_label_rows']} rows with conflicting labels, "
        f"plus {sum(stats['capped'].values())} legitimate emails over the per-source cap."
    )
    if prepared["label"].sum() == 0:
        print("WARNING: no phishing emails yet. Add Nazario.csv and/or Nigerian_Fraud.csv to data/.")
    print(f"Written to {PREPARED_DATA_PATH} and {report_path}")


if __name__ == "__main__":
    main()
