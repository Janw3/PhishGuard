from typing import Literal

from pydantic import BaseModel, Field

# Limits that protect the server from very large inputs (rules, tokenizer and LIME scale with length).
MAX_CONTENT_CHARS = 200_000  # POST /analyze: about 40 pages of text
MAX_EML_BYTES = 5_000_000  # POST /analyze-eml: 5 MB, attachments included

# Literal types make FastAPI reject anything outside the contract,
# e.g. "High" instead of "high", and show the allowed values in /docs.
Label = Literal["phishing", "legitimate"]
Risk = Literal["low", "medium", "high"]
ReasonSource = Literal["rule", "model"]


class EmailRequest(BaseModel):
    # Upper bound protects the server: rules, tokenizer and LIME all scale with length.
    content: str = Field(max_length=MAX_CONTENT_CHARS)
    # Name from GET /models. None means the default model.
    model: str | None = None
    # Sender as shown in the email, e.g. "PayPal <service@paypal.com>". Enables sender checks.
    sender: str | None = None


class Reason(BaseModel):
    id: str
    feature: str
    explanation: str
    # Rules: severity 0..1. Model: LIME weight (usually much smaller).
    impact: float
    start: int
    end: int
    source: ReasonSource
    # Rules: e.g. "credentials", "urgency", "link". Model reasons: "model".
    category: str
    # Set when an LLM wrote the explanation (name of that model); None = curated template.
    explanation_by: str | None = None


class SenderSignal(BaseModel):
    """A finding about the sender. It has no position, because the sender is not in the body."""

    id: str
    feature: str
    category: str
    explanation: str
    severity: float


class AnalysisResponse(BaseModel):
    label: Label
    risk: Risk
    confidence: float
    phishing_probability: float
    # Combined strength of the rule signals, 0..1.
    rule_score: float
    # True when the model is close to undecided, or when it says "legitimate"
    # while the rules found strong phishing signals.
    uncertain: bool
    model: str
    reasons: list[Reason]
    sender_signals: list[SenderSignal]


class ParsedEmailFields(BaseModel):
    """What was read from the .eml file. `body` is the text that reason offsets refer to."""

    subject: str
    sender: str
    reply_to: str
    body: str


class EmlAnalysisResponse(AnalysisResponse):
    email: ParsedEmailFields


class ModelInfo(BaseModel):
    name: str
    default: bool
