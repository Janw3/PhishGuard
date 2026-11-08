"""Evaluation helpers on tiny hand-made data (no real data needed)."""

import math

import pandas as pd
import pytest

from scripts.evaluate import compute_metrics, held_out_pairs, split_by_sources
from scripts.reporting import markdown_table


def data():
    return pd.DataFrame(
        {
            "source": ["nazario", "nigerian_fraud", "enron", "spamassassin", "enron"],
            "label": [1, 1, 0, 0, 0],
            "text": ["a", "b", "c", "d", "e"],
        }
    )


def test_held_out_pairs_combine_one_phishing_and_one_legit_source():
    assert held_out_pairs(data()) == [
        ("nazario", "enron"),
        ("nazario", "spamassassin"),
        ("nigerian_fraud", "enron"),
        ("nigerian_fraud", "spamassassin"),
    ]


def test_split_by_sources_never_leaks_held_out_sources_into_training():
    train, test = split_by_sources(data(), ("nazario", "enron"))
    assert set(test["source"]) == {"nazario", "enron"}
    assert not set(train["source"]) & {"nazario", "enron"}
    assert len(train) + len(test) == len(data())


def test_compute_metrics_counts_phishing_as_positive():
    y_true = [1, 1, 1, 1, 0, 0, 0, 0]
    y_pred = [1, 1, 1, 0, 0, 0, 0, 1]
    p = [0.9, 0.8, 0.7, 0.4, 0.1, 0.2, 0.3, 0.6]
    m = compute_metrics(y_true, y_pred, p)
    assert m["phishing recall"] == pytest.approx(0.75)
    assert m["false positive rate"] == pytest.approx(0.25)
    assert m["missed phishing (FN)"] == 1
    assert m["false alarms (FP)"] == 1


def test_compute_metrics_with_one_class_reports_nan_instead_of_crashing():
    m = compute_metrics([1, 1], [1, 0], [0.9, 0.2])
    assert m["phishing recall"] == pytest.approx(0.5)
    assert math.isnan(m["PR-AUC"])
    assert math.isnan(m["false positive rate"])


def test_markdown_table_formats_floats_and_nan():
    df = pd.DataFrame({"x": [0.123456, float("nan")], "n": [1, 2]}, index=["a", "b"])
    assert markdown_table(df).splitlines()[2:] == ["| a | 0.1235 | 1 |", "| b | n/a | 2 |"]


def test_expected_calibration_error():
    from scripts.evaluate import expected_calibration_error

    # Perfect: of the emails scored 0.25, a quarter are phishing; of those scored 0.75, three quarters.
    y = [1, 0, 0, 0, 1, 1, 1, 0]
    p = [0.25, 0.25, 0.25, 0.25, 0.75, 0.75, 0.75, 0.75]
    assert expected_calibration_error(y, p) == pytest.approx(0.0)
    # Overconfident: everything scored 0.95 but only half is phishing -> error 0.45.
    assert expected_calibration_error([1, 0, 1, 0], [0.95] * 4) == pytest.approx(0.45)


def test_compute_metrics_includes_brier_score():
    m = compute_metrics([1, 0], [1, 0], [1.0, 0.0])
    assert m["Brier score"] == pytest.approx(0.0)
    assert m["ECE"] == pytest.approx(0.0)
