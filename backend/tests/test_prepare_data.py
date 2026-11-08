"""Data preparation on tiny hand-made tables (no real data needed)."""

import pandas as pd

from scripts.prepare_data import (
    COLUMNS,
    cap_legitimate_per_source,
    deduplicate,
    keep_phishing_positives,
    load_source,
)


def test_load_source_builds_common_schema():
    raw = pd.DataFrame(
        {
            "sender": ["a@x.com", None],
            "subject": ["Hello", None],
            "body": ["Line one\nLine two", "No subject here"],
            "label": [0, 1],
        }
    )
    out = load_source(raw, "ceas_08")
    assert list(out.columns) == COLUMNS
    assert (out["source"] == "ceas_08").all()
    assert out["text"].tolist() == ["Hello\n\nLine one\nLine two", "No subject here"]
    assert out["sender"].tolist() == ["a@x.com", ""]


def test_load_source_without_optional_columns():
    raw = pd.DataFrame({"subject": ["Hi"], "body": ["text"], "label": [1]})
    out = load_source(raw, "enron")
    assert out["date"].tolist() == [""]
    assert out["label"].tolist() == [1]


def test_load_source_drops_empty_bodies_and_invalid_labels():
    raw = pd.DataFrame({"body": ["ok", "   ", "ok too", "fine"], "label": [0, 1, "spam", None]})
    out = load_source(raw, "ling")
    assert out["body"].tolist() == ["ok"]


def make(texts_and_labels, source="s"):
    return pd.DataFrame(
        [
            {"source": source, "label": label, "subject": "", "body": text, "sender": "", "date": "", "text": text}
            for text, label in texts_and_labels
        ]
    )


def test_deduplicate_ignores_formatting_and_works_across_sources():
    df = pd.concat([make([("Click HERE now!", 1)], "a"), make([("click here now !", 1)], "b")])
    kept, stats = deduplicate(df.reset_index(drop=True))
    assert len(kept) == 1
    assert kept.loc[0, "source"] == "a"  # first occurrence wins
    assert stats["duplicate_rows"] == 1


def test_spam_is_dropped_but_phishing_and_legitimate_are_kept():
    df = pd.concat(
        [
            make([("cheap pills", 1), ("meeting notes", 0)], "ceas_08"),
            make([("verify your password", 1)], "nazario"),
            make([("send the processing fee", 1)], "nigerian_fraud"),
        ],
        ignore_index=True,
    )
    kept, dropped = keep_phishing_positives(df)
    assert sorted(kept["text"]) == ["meeting notes", "send the processing fee", "verify your password"]
    assert dropped == {"ceas_08": 1}


def test_cap_limits_legitimate_per_source_and_never_drops_phishing():
    df = pd.concat(
        [
            make([(f"enron {i}", 0) for i in range(10)], "enron"),
            make([(f"sa {i}", 0) for i in range(3)], "spamassassin"),
            make([(f"phish {i}", 1) for i in range(8)], "nazario"),
        ],
        ignore_index=True,
    )
    kept, removed = cap_legitimate_per_source(df, max_per_source=4, seed=0)
    counts = kept.groupby(["source", "label"]).size().to_dict()
    assert counts == {("enron", 0): 4, ("spamassassin", 0): 3, ("nazario", 1): 8}
    assert removed == {"enron": 6}


def test_cap_is_reproducible():
    df = make([(f"mail {i}", 0) for i in range(20)], "enron")
    first, _ = cap_legitimate_per_source(df, max_per_source=5, seed=42)
    second, _ = cap_legitimate_per_source(df, max_per_source=5, seed=42)
    assert first["text"].tolist() == second["text"].tolist()


def test_deduplicate_drops_conflicting_labels_entirely():
    df = make([("same text", 0), ("Same text", 1), ("other", 0)])
    kept, stats = deduplicate(df)
    assert kept["text"].tolist() == ["other"]
    assert stats["conflicting_label_rows"] == 2
