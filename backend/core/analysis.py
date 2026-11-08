"""Combine the ML model and the rule-based signals into one result.

- The MODEL decides the label (phishing / legitimate).
- The RULES can raise the risk: if strong rule signals fire while the model says
  "legitimate", the result is marked uncertain and the risk goes up to medium.
  The UI then shows the honest state "the model and the rules disagree".
- Highlights: rule signals first (deterministic, curated explanations), then
  model (LIME) features, without overlaps, at most MAX_HIGHLIGHTS in total.
"""

import uuid
from collections import Counter

from core.classifiers import Classifier
from core.explainer import FALLBACK_EXPLANATION, explain
from core.llm_explanations import LLMExplainer, context_around
from core.occlusion import explain_by_occlusion
from core.signals import Signal, detect_signals, rule_score


def model_highlights(text: str, classifier: Classifier, num_features: int) -> list[dict]:
    """Word occlusion for models that expose log-odds (transformers), LIME otherwise."""
    if hasattr(classifier, "phishing_log_odds"):
        return explain_by_occlusion(text, classifier, num_features)
    return explain(text, classifier, num_features)


PHISHING_THRESHOLD = 0.5
# A rule score this high counts as "strong signals". Reached for example by one
# look-alike link, or by a password request combined with time pressure.
RULE_ALERT = 0.8
MAX_HIGHLIGHTS = 7
# Rules may take at most this many slots, so the model's view stays visible too.
# Unused model slots are filled with further rules.
MAX_RULE_HIGHLIGHTS = 5
MAX_PER_CATEGORY = 2


def risk_level(phishing_probability: float) -> str:
    """Map P(phishing) to the lowercase risk levels of the API contract."""
    if phishing_probability >= 0.8:
        return "high"
    if phishing_probability >= PHISHING_THRESHOLD:
        return "medium"
    return "low"


def _rule_reason(signal: Signal) -> dict:
    return {
        "id": f"rule_{uuid.uuid4().hex[:8]}",
        "feature": signal.feature,
        "explanation": signal.explanation,
        "impact": float(signal.severity),
        "start": int(signal.start),
        "end": int(signal.end),
        "source": "rule",
        "category": signal.category,
    }


def _sender_signal(signal: Signal) -> dict:
    return {
        "id": f"sender_{uuid.uuid4().hex[:8]}",
        "feature": signal.feature,
        "category": signal.category,
        "explanation": signal.explanation,
        "severity": float(signal.severity),
    }


def _overlaps(a: dict, b: dict) -> bool:
    return a["start"] < b["end"] and b["start"] < a["end"]


def merge_reasons(rule_reasons: list[dict], model_reasons: list[dict]) -> list[dict]:
    """Rules first (by severity), then model features; no overlaps, capped.

    1. up to MAX_RULE_HIGHLIGHTS rules (at most MAX_PER_CATEGORY per category,
       so one repeated word cannot fill the list)
    2. model features into the remaining slots
    3. if slots are still free, further rules
    """
    selected: list[dict] = []
    per_category: Counter = Counter()
    rules = sorted(rule_reasons, key=lambda r: (-r["impact"], r["start"]))

    def add_rules(limit: int) -> None:
        for reason in rules:
            if len(selected) >= limit:
                break
            if reason in selected or per_category[reason["category"]] >= MAX_PER_CATEGORY:
                continue
            if not any(_overlaps(reason, s) for s in selected):
                selected.append(reason)
                per_category[reason["category"]] += 1

    add_rules(MAX_RULE_HIGHLIGHTS)
    for reason in model_reasons:
        if len(selected) >= MAX_HIGHLIGHTS:
            break
        if not any(_overlaps(reason, s) for s in selected):
            selected.append(reason)
    add_rules(MAX_HIGHLIGHTS)
    return selected


def analyze(
    email_content: str,
    classifier: Classifier,
    sender: str | None = None,
    uncertain_band: tuple[float, float] = (0.4, 0.6),
    num_features: int = 20,
    reply_to: str | None = None,
    anchors: list | None = None,
    llm: LLMExplainer | None = None,
) -> dict:
    probability = classifier.predict_proba([email_content])
    legitimate_probability = float(probability[0][0])
    phishing_probability = float(probability[0][1])
    is_phishing = phishing_probability >= PHISHING_THRESHOLD

    text_signals, sender_signals = detect_signals(email_content, sender, reply_to, anchors)
    score = float(rule_score(text_signals + sender_signals))
    rule_alert = score >= RULE_ALERT

    if is_phishing:
        risk = risk_level(max(phishing_probability, score))
    else:
        # The model says legitimate. Strong rule signals raise the risk to medium,
        # but never to high: the two disagree, and the UI should say so.
        risk = "medium" if rule_alert else "low"

    low, high = uncertain_band
    uncertain = (low <= phishing_probability <= high) or (not is_phishing and rule_alert)

    model_reasons = model_highlights(email_content, classifier, num_features) if is_phishing else []

    return {
        "label": "phishing" if is_phishing else "legitimate",
        "risk": risk,
        "confidence": phishing_probability if is_phishing else legitimate_probability,
        "phishing_probability": phishing_probability,
        "rule_score": score,
        "uncertain": uncertain,
        "model": classifier.name,
        "reasons": add_llm_explanations(
            merge_reasons([_rule_reason(s) for s in text_signals], model_reasons), email_content, llm
        ),
        "sender_signals": [_sender_signal(s) for s in sender_signals],
    }


def add_llm_explanations(reasons: list[dict], text: str, llm: LLMExplainer | None) -> list[dict]:
    """Replace the generic fallback text of MODEL highlights with an LLM-written one, if enabled.

    `explanation_by` names the model that wrote it, so the UI can say so. Rule
    highlights keep their curated text; on any LLM problem the template stays.
    """
    for reason in reasons:
        reason.setdefault("explanation_by", None)
        if llm is None or reason["source"] != "model" or reason["explanation"] != FALLBACK_EXPLANATION:
            continue
        context = context_around(text, reason["start"], reason["end"])
        written = llm.explain(reason["feature"], reason["category"], context)
        if written:
            reason["explanation"] = written
            reason["explanation_by"] = llm.writer.name
    return reasons
