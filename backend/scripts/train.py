"""Train all classic models and save them to the artifacts folder.

Run from backend/:  python -m scripts.prepare_data   (once, creates data/prepared.csv)
                    python -m scripts.train

Each model is saved as artifacts/<name>.pkl and shows up in GET /models.
The texts go through the same normalize() that is used at inference time.

Note: this is a random split. Phishing and legitimate emails come from different
sources, so these numbers are optimistic (see reports/data_summary.md).
"""

import joblib
import pandas as pd
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from app.config import ARTIFACTS_DIR, PREPARED_DATA_PATH
from core.preprocessing import normalize

SEED = 42


def tfidf() -> TfidfVectorizer:
    return TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        stop_words="english",
        sublinear_tf=True,
    )


# class_weight="balanced" weighs each class by the inverse of its size, so the
# model does not lean towards "legitimate" just because there are more of them.
MODELS = {
    "random_forest": RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=SEED, n_jobs=-1),
    "logistic_regression": LogisticRegression(max_iter=1000, class_weight="balanced", random_state=SEED),
}


def build_pipeline(name: str) -> Pipeline:
    """A fresh, untrained TF-IDF + calibrated classifier pipeline. Also used by evaluate.py.

    CalibratedClassifierCV trains the classifier on 4/5 of the data and learns on
    the remaining fifth how its raw scores map to real frequencies (isotonic
    regression), five times over. Afterwards "80% phishing" means that about 80%
    of such emails really were phishing in the training data, which matters
    because the UI shows the confidence and the "uncertain" band.
    """
    calibrated = CalibratedClassifierCV(clone(MODELS[name]), method="isotonic", cv=5)
    return Pipeline([("tfidf", tfidf()), ("clf", calibrated)])


def load_data() -> pd.DataFrame:
    if not PREPARED_DATA_PATH.exists():
        raise SystemExit(f"{PREPARED_DATA_PATH} not found. Run: python -m scripts.prepare_data")
    df = pd.read_csv(PREPARED_DATA_PATH, usecols=["source", "label", "text", "sender"], keep_default_na=False)
    # The model is trained on normalized text; `text` stays raw for the rules (links, capitals).
    df["model_text"] = df["text"].map(normalize)
    return df


def main() -> None:
    df = load_data()
    X_train, X_test, y_train, y_test = train_test_split(
        df["model_text"], df["label"], test_size=0.2, random_state=SEED, stratify=df["label"]
    )

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    for name in MODELS:
        pipeline = build_pipeline(name)
        pipeline.fit(X_train, y_train)
        y_pred = pipeline.predict(X_test)

        cm = confusion_matrix(y_test, y_pred)
        false_negatives = cm[1][0]
        phishing_recall = cm[1][1] / (cm[1][0] + cm[1][1])

        print(f"\n=== {name} ===")
        print(classification_report(y_test, y_pred, target_names=["Safe Email", "Phishing Email"]))
        print(f"Phishing recall: {phishing_recall:.3f}   False negatives (missed phishing): {false_negatives}")
        print("                  Predicted Safe  Predicted Phishing")
        print(f"Actual Safe            {cm[0][0]:>5}              {cm[0][1]:>5}")
        print(f"Actual Phishing        {cm[1][0]:>5}              {cm[1][1]:>5}")

        path = ARTIFACTS_DIR / f"{name}.pkl"
        joblib.dump(pipeline, path)
        print(f"Saved to {path}")


if __name__ == "__main__":
    main()
