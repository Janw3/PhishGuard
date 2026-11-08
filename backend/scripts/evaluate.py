"""Compare all models on a random split AND on a source-held-out split.

Run from backend/:  python -m scripts.evaluate
Writes reports/model_comparison.md. Trains fresh models per split; the models in
artifacts/ are not touched.

Why two splits?
  Phishing comes only from some corpora (Nazario, Nigerian Fraud) and legitimate
  emails only from others (Enron, SpamAssassin). On a random split the test
  emails come from the same corpora as the training emails, so a model can score
  well just by recognizing a corpus's writing style.

  The source-held-out split removes that shortcut: it holds out one phishing
  source AND one legitimate source together, trains on the remaining sources and
  tests only on the two held-out ones. Every combination is tried. The drop from
  the random split shows how much a model relied on source style.
"""

import hashlib
import io
import itertools
import json
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from app.config import DATA_DIR, PRETRAINED_MODELS, REPORTS_DIR
from core.analysis import RULE_ALERT
from core.pretrained import PRETRAINED, HuggingFaceClassifier, load_pretrained
from core.signals import detect_signals, rule_score
from scripts.reporting import DATASET_CITATION, markdown_table
from scripts.train import MODELS, SEED, build_pipeline, load_data

LATENCY_SAMPLE = 200


def compute_metrics(y_true, y_pred, p_phishing) -> dict:
    """Metrics with phishing (label 1) as the positive class."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    both_classes = len(set(y_true)) == 2
    return {
        "phishing recall": tp / (tp + fn) if tp + fn else float("nan"),
        "precision": precision_score(y_true, y_pred, zero_division=0.0),
        "F1": f1_score(y_true, y_pred, zero_division=0.0),
        "PR-AUC": average_precision_score(y_true, p_phishing) if both_classes else float("nan"),
        "false positive rate": fp / (fp + tn) if fp + tn else float("nan"),
        "accuracy": accuracy_score(y_true, y_pred),
        "missed phishing (FN)": int(fn),
        "false alarms (FP)": int(fp),
        "Brier score": float(np.mean((np.asarray(p_phishing) - np.asarray(y_true)) ** 2)),
        "ECE": expected_calibration_error(y_true, p_phishing),
    }


def expected_calibration_error(y_true, p_phishing, bins: int = 10) -> float:
    """How far "x% phishing" is from the real share of phishing, averaged over 10 confidence bins.

    0 = perfectly calibrated. Example: if the emails scored 0.8-0.9 are only 60%
    phishing, that bin contributes |0.85 - 0.60| weighted by its size.
    """
    y, p = np.asarray(y_true, dtype=float), np.asarray(p_phishing, dtype=float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    error = 0.0
    for low, high in zip(edges[:-1], edges[1:], strict=True):
        in_bin = (p >= low) & ((p < high) if high < 1.0 else (p <= high))
        if in_bin.any():
            error += in_bin.mean() * abs(p[in_bin].mean() - y[in_bin].mean())
    return float(error)


def held_out_pairs(df: pd.DataFrame) -> list[tuple[str, str]]:
    """Every (phishing source, legitimate source) combination to hold out together."""
    phishing_sources = sorted(df.loc[df["label"] == 1, "source"].unique())
    legit_sources = sorted(df.loc[df["label"] == 0, "source"].unique())
    return list(itertools.product(phishing_sources, legit_sources))


def split_by_sources(df: pd.DataFrame, held_out: tuple[str, ...]) -> tuple[pd.DataFrame, pd.DataFrame]:
    is_test = df["source"].isin(held_out)
    return df[~is_test], df[is_test]


def add_rule_scores(df: pd.DataFrame) -> pd.DataFrame:
    """Run the rules on the RAW text and sender. They need no training."""
    scores = [rule_score(sum(detect_signals(t, s), [])) for t, s in zip(df["text"], df["sender"], strict=True)]
    return df.assign(rule_score=scores, rule_alert=np.array(scores) >= RULE_ALERT)


def fit_and_score(name: str, train: pd.DataFrame, test: pd.DataFrame) -> tuple[dict, Pipeline]:
    pipeline = build_pipeline(name)
    pipeline.fit(train["model_text"], train["label"])
    p_phishing = pipeline.predict_proba(test["model_text"])[:, 1]
    return score(test, p_phishing), pipeline


def score(test: pd.DataFrame, p_phishing: np.ndarray) -> dict:
    y_true = test["label"].to_numpy()
    y_pred = (p_phishing >= 0.5).astype(int)
    metrics = compute_metrics(y_true, y_pred, p_phishing)

    # "Model + rules": an email is flagged for the user if the model says phishing
    # OR the rules raise an alert (in the API that becomes "uncertain", risk medium).
    flagged = (y_pred == 1) | test["rule_alert"].to_numpy()
    with_rules = compute_metrics(y_true, flagged.astype(int), p_phishing)
    metrics["recall (model + rules)"] = with_rules["phishing recall"]
    metrics["FPR (model + rules)"] = with_rules["false positive rate"]
    return metrics


# --------------------------------------------------------------------------- pretrained models


def data_fingerprint(df: pd.DataFrame) -> str:
    return hashlib.sha1("\x00".join(df["text"]).encode("utf-8")).hexdigest()[:10]


def pretrained_probabilities(clf: HuggingFaceClassifier, df: pd.DataFrame) -> np.ndarray:
    """P(phishing) for every email, computed once and cached in data/cache/.

    Pretrained models are not trained on our data, so one pass over all emails
    serves every split. The cache key includes the model revision and the data.
    """
    cache = DATA_DIR / "cache" / f"{clf.name}_{clf.spec.revision[:8]}_{data_fingerprint(df)}.npy"
    if cache.exists():
        return np.load(cache)

    # Progress is saved after every chunk, so an interrupted run resumes where it stopped.
    partial = cache.with_suffix(".partial.npy")
    cache.parent.mkdir(parents=True, exist_ok=True)
    done = np.load(partial) if partial.exists() else np.empty(0)
    texts = df["text"].tolist()
    chunk_size = 256
    start = time.perf_counter()
    for i in range(len(done), len(texts), chunk_size):
        done = np.concatenate([done, clf.predict_proba(texts[i : i + chunk_size])[:, 1]])
        np.save(partial, done)
        print(f"  {clf.name}: {len(done)}/{len(texts)} emails ({time.perf_counter() - start:.0f}s)", flush=True)

    np.save(cache, done)
    partial.unlink(missing_ok=True)
    return done


def pretrained_size_mb(clf: HuggingFaceClassifier) -> float:
    clf._load()
    return sum(p.numel() * p.element_size() for p in clf._model.parameters()) / 1e6


def pretrained_results(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Random-split rows and source-held-out rows for every pretrained model."""
    _, random_test = random_split(df)
    random_rows, held_out_rows = {}, []
    for name, clf in load_pretrained(PRETRAINED_MODELS).items():
        print(f"pretrained {name}: predicting all emails (cached after the first run)")
        p_all = pd.Series(pretrained_probabilities(clf, df), index=df.index)

        metrics = score(random_test, p_all.loc[random_test.index].to_numpy())
        sample = random_test["text"].sample(n=min(LATENCY_SAMPLE // 4, len(random_test)), random_state=SEED)
        metrics["latency (ms/email)"] = latency_ms(clf, sample.tolist())
        metrics["size (MB)"] = pretrained_size_mb(clf)
        random_rows[name] = metrics

        for held_out in held_out_pairs(df):
            _, test = split_by_sources(df, held_out)
            held_out_rows.append(
                {
                    "model": name,
                    "held out": " + ".join(held_out),
                    "test emails": len(test),
                    **score(test, p_all.loc[test.index].to_numpy()),
                }
            )
        print(f"pretrained {name}: random-split recall {metrics['phishing recall']:.3f}")
    return pd.DataFrame.from_dict(random_rows, orient="index"), pd.DataFrame(held_out_rows)


def latency_ms(model, texts: list[str]) -> float:
    """Mean time to classify ONE email, as the API does it."""
    start = time.perf_counter()
    for text in texts:
        model.predict_proba([text])
    return (time.perf_counter() - start) / len(texts) * 1000


def size_mb(pipeline: Pipeline) -> float:
    buffer = io.BytesIO()
    joblib.dump(pipeline, buffer)
    return buffer.getbuffer().nbytes / 1e6


def random_split(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    return train_test_split(df, test_size=0.2, random_state=SEED, stratify=df["label"])


def random_split_results(df: pd.DataFrame) -> pd.DataFrame:
    train, test = random_split(df)
    rows = {}
    for name in MODELS:
        metrics, pipeline = fit_and_score(name, train, test)
        sample = test["model_text"].sample(n=min(LATENCY_SAMPLE, len(test)), random_state=SEED).tolist()
        metrics["latency (ms/email)"] = latency_ms(pipeline, sample)
        metrics["size (MB)"] = size_mb(pipeline)
        rows[name] = metrics
        print(f"random split  {name}: recall {metrics['phishing recall']:.3f}")
    return pd.DataFrame.from_dict(rows, orient="index").rename_axis("model")


def source_held_out_results(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for held_out in held_out_pairs(df):
        train, test = split_by_sources(df, held_out)
        if train["label"].nunique() < 2:
            continue
        for name in MODELS:
            metrics, _ = fit_and_score(name, train, test)
            rows.append({"model": name, "held out": " + ".join(held_out), "test emails": len(test), **metrics})
            print(f"held out {held_out}  {name}: recall {metrics['phishing recall']:.3f}")
    return pd.DataFrame(rows)


def build_report(random_df: pd.DataFrame, held_out_df: pd.DataFrame, data: pd.DataFrame) -> str:
    sources = data.groupby(["source", "label"]).size().unstack(fill_value=0)
    sources.columns = ["legitimate" if c == 0 else "phishing" for c in sources.columns]

    held_out_section = "Not enough sources: need at least two phishing and two legitimate sources.\n"
    summary_section = ""
    if not held_out_df.empty:
        detail = held_out_df.set_index(["model", "held out"])
        detail.index = [f"{m} / {h}" for m, h in detail.index]
        detail.index.name = "model / held-out sources"
        held_out_section = markdown_table(detail) + "\n"

        compare = summary_table(random_df, held_out_df)
        summary_section = (
            "## Summary: random split vs. source-held-out\n\n"
            + markdown_table(compare)
            + "\n\n**Model + rules**: an email counts as flagged if the model says phishing OR the rule score "
            f"reaches {RULE_ALERT} (in the API this shows up as `uncertain` with risk `medium`). "
            "The rules need no training, so they cannot learn a corpus's style. "
            "**ECE** (expected calibration error) shows how far a model's confidence is from reality "
            "(0 = an email scored 80% is phishing 80% of the time); **Brier score** is the mean squared "
            "error of the probabilities. Lower is better for both. The TF-IDF models are calibrated "
            "with isotonic regression (`CalibratedClassifierCV`), the pretrained models are used as published.\n\n"
        )

    return (
        "# Model comparison\n\n"
        "Generated by `python -m scripts.evaluate`. Do not edit by hand.\n\n"
        f"{DATASET_CITATION}\n"
        "Positive class = phishing. **Phishing recall** is the share of phishing emails that were caught; "
        "**missed phishing (FN)** are the dangerous errors. **False positive rate (FPR)** is the share of "
        "legitimate emails wrongly flagged. Decision threshold: 0.5.\n\n"
        + summary_section
        + "## Random split (80/20, stratified, seed 42)\n\n"
        "Test emails come from the same corpora as the training emails, so these numbers are optimistic.\n\n"
        f"{markdown_table(random_df)}\n\n"
        "Latency: mean time to classify one email (CPU, this machine). "
        "Size: pickled pipeline for trained models, weights for pretrained models.\n\n"
        "## Source-held-out\n\n"
        "One phishing source and one legitimate source are held out together; the model is trained on the "
        "remaining sources and tested only on the held-out ones. This tests whether a model learned "
        "phishing or just the writing style of a corpus. Pretrained models are not trained here; they are "
        "tested on exactly the same held-out emails.\n\n"
        f"{held_out_section}\n" + pretrained_section() + "## Rules alone, per source\n\n"
        f"Share of emails per source where the rule score reaches {RULE_ALERT} (no model involved). "
        "For phishing sources higher is better, for legitimate sources lower is better. "
        "The rules were written from general phishing knowledge and not tuned on this data.\n\n"
        f"{markdown_table(rules_per_source(data))}\n\n"
        "## Data used\n\n"
        f"{markdown_table(sources.rename_axis('source'))}\n"
    )


def pretrained_section() -> str:
    if not PRETRAINED_MODELS:
        return ""
    rows = pd.DataFrame(
        [
            {
                "model": n,
                "Hugging Face repo": PRETRAINED[n].repo_id,
                "revision": PRETRAINED[n].revision[:8],
                "license": PRETRAINED[n].license,
                "note": PRETRAINED[n].note,
            }
            for n in PRETRAINED_MODELS
        ]
    ).set_index("model")
    return (
        "## Pretrained models\n\n"
        "Downloaded from the Hugging Face Hub, pinned to a revision, used without any training on our data. "
        "If a model was trained on the same public corpora, its scores here are too optimistic.\n\n"
        f"{markdown_table(rows)}\n\n"
    )


def rules_per_source(df: pd.DataFrame) -> pd.DataFrame:
    table = df.groupby("source").agg(
        emails=("label", "size"),
        kind=("label", lambda s: "phishing" if s.iloc[0] == 1 else "legitimate"),
        flagged_by_rules=("rule_alert", "mean"),
        mean_rule_score=("rule_score", "mean"),
    )
    return table.rename(columns={"flagged_by_rules": "flagged by rules", "mean_rule_score": "mean rule score"})


def summary_table(random_df: pd.DataFrame, held_out_df: pd.DataFrame) -> pd.DataFrame:
    mean = held_out_df.groupby("model")[
        ["phishing recall", "false positive rate", "recall (model + rules)", "FPR (model + rules)", "ECE"]
    ].mean()
    return pd.DataFrame(
        {
            "random split recall": random_df["phishing recall"],
            "source-held-out recall (mean)": mean["phishing recall"],
            "source-held-out recall, model + rules": mean["recall (model + rules)"],
            "random split FPR": random_df["false positive rate"],
            "source-held-out FPR (mean)": mean["false positive rate"],
            "source-held-out FPR, model + rules": mean["FPR (model + rules)"],
            "random split ECE": random_df["ECE"],
            "random split Brier score": random_df["Brier score"],
            "source-held-out ECE (mean)": mean["ECE"],
        }
    ).rename_axis("model")


def write_json(random_df: pd.DataFrame, held_out_df: pd.DataFrame) -> None:
    """The same results as JSON, for comparing runs or building tables."""
    summary = summary_table(random_df, held_out_df)
    payload = {
        name: {
            "summary": {k: float(v) for k, v in summary.loc[name].items()},
            "random_split": {
                k: (float(v) if isinstance(v, int | float | np.floating | np.integer) else v)
                for k, v in random_df.loc[name].items()
            },
        }
        for name in summary.index
    }
    (REPORTS_DIR / "model_comparison.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> None:
    data = add_rule_scores(load_data())
    random_df = random_split_results(data)
    held_out_df = source_held_out_results(data)
    if PRETRAINED_MODELS:
        pre_random, pre_held_out = pretrained_results(data)
        random_df = pd.concat([random_df, pre_random]).rename_axis("model")
        held_out_df = pd.concat([held_out_df, pre_held_out], ignore_index=True)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out = REPORTS_DIR / "model_comparison.md"
    out.write_text(build_report(random_df, held_out_df, data), encoding="utf-8")
    write_json(random_df, held_out_df)
    print(f"\nWritten to {out} and model_comparison.json")


if __name__ == "__main__":
    np.random.seed(SEED)
    main()
