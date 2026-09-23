"""Inference wrapper for the DGA XGBoost model trained in DGA_detector.ipynb."""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer


BASE_FEATURES = [
    "len_full",
    "len_sld",
    "entropy",
    "tld_len",
    "high_risk_tld",
    "cv_ratio",
    "digit_ratio",
    "dict_match_ratio",
]
HERE = Path(__file__).resolve().parent
THRESHOLD = 0.68  # persisted notebook output: selected threshold was 0.68
LEXICAL_FALLBACK_THRESHOLD = 0.60


def load_english_dictionary(path: str | Path | None = None) -> set[str]:
    """Load the notebook-filtered NLTK word list bundled with this detector."""
    resource = Path(path) if path is not None else HERE / "lexical_resources" / "english_words.txt"
    if not resource.is_file():
        raise FileNotFoundError(f"DGA lexical resource is missing: {resource}")
    with resource.open(encoding="utf-8") as stream:
        return {line.strip() for line in stream if line.strip()}


def calculate_shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return float(-sum((count / length) * math.log2(count / length) for count in counts.values()))


def fast_vowel_consonant_ratio(value: str) -> float:
    vowels = sum(char in "aeiou" for char in value)
    consonants = sum(char.isalpha() and char not in "aeiou" for char in value)
    return float(consonants / max(vowels, 1))


def fast_dict_match_ratio(value: str, english_dict: set[str]) -> float:
    if not value:
        return 0.0
    matched = [False] * len(value)
    for length in range(4, min(len(value) + 1, 16)):
        for start in range(len(value) - length + 1):
            if value[start : start + length] in english_dict:
                for index in range(start, start + length):
                    matched[index] = True
    return float(sum(matched) / max(len(value), 1))


class DGADetector:
    """Score domains using the notebook's lexical and character n-gram contract."""

    def __init__(
        self,
        model_path: str | Path | None = None,
        vectorizer: TfidfVectorizer | None = None,
        english_dict: Iterable[str] | None = None,
        threshold: float = THRESHOLD,
    ) -> None:
        self.model_path = Path(model_path) if model_path else HERE / "DGA_XGBoost.pkl"
        self.model = None  # deferred: lexical features remain usable with a corrupt model file
        self.vectorizer = vectorizer
        self.english_dict = {word.lower() for word in english_dict} if english_dict is not None else load_english_dictionary()
        self.threshold = threshold

    def transform_base(self, domains: Iterable[str]) -> pd.DataFrame:
        """Generate the eight non-TF-IDF notebook features."""
        normalized = [str(domain).strip().lower() for domain in domains]
        slds = [domain.split(".")[0] if "." in domain else domain for domain in normalized]
        rows = []
        for domain, sld in zip(normalized, slds):
            rows.append(
                {
                    "len_full": len(domain),
                    "len_sld": len(sld),
                    "entropy": calculate_shannon_entropy(sld),
                    "tld_len": len(domain.split(".")[-1]) if "." in domain else 0,
                    "high_risk_tld": int(domain.endswith((".cc", ".ru", ".biz", ".info", ".top", ".ddns.net", ".xyz", ".ws"))),
                    "cv_ratio": fast_vowel_consonant_ratio(sld),
                    "digit_ratio": sum(char.isdigit() for char in sld) / max(len(sld), 1),
                    "dict_match_ratio": fast_dict_match_ratio(sld, self.english_dict),
                }
            )
        return pd.DataFrame(rows, columns=BASE_FEATURES)

    def transform(self, domains: Iterable[str]) -> pd.DataFrame:
        normalized = [str(domain).strip().lower() for domain in domains]
        slds = [domain.split(".")[0] if "." in domain else domain for domain in normalized]
        features = self.transform_base(normalized)
        if self.vectorizer is None:
            raise RuntimeError(
                "The DGA notebook saved the classifier but not its fitted TfidfVectorizer. "
                "Provide the training-time vectorizer before inference."
            )
        ngrams = self.vectorizer.transform(slds).toarray()
        ngram_columns = [f"ngram_{name}" for name in self.vectorizer.get_feature_names_out()]
        return pd.concat([features, pd.DataFrame(ngrams, columns=ngram_columns)], axis=1)

    def load_model(self):
        if self.model is None:
            try:
                self.model = joblib.load(self.model_path)
            except Exception as exc:
                raise RuntimeError(f"DGA classifier artifact cannot be loaded: {self.model_path}") from exc
        return self.model

    def predict(self, domain: str) -> tuple[int, float, dict[str, object]]:
        features = self.transform([domain])
        model = self.load_model()
        confidence = float(model.predict_proba(features)[0][1])
        alert = int(confidence >= self.threshold)
        return alert, confidence, {
            "domain": domain,
            "base_features": self.transform_base([domain]).iloc[0].to_dict(),
            "confidence": confidence,
            "threshold": self.threshold,
            "prediction": "DGA (1)" if alert else "Benign (0)",
        }

    def predict_lexical_fallback(self, domain: str) -> dict[str, object]:
        """Return an explicitly non-ML lexical heuristic result.

        This keeps a basic DGA signal available when the saved classifier and
        fitted TF-IDF vectorizer are unavailable. The score is a rule score,
        not a calibrated probability, and must not be reported as model
        confidence.
        """
        row = self.transform_base([domain]).iloc[0].to_dict()
        signals = {
            "high_entropy": float(row["entropy"]) >= 3.2,
            "many_digits": float(row["digit_ratio"]) >= 0.20,
            "few_dictionary_matches": float(row["dict_match_ratio"]) <= 0.20,
            "long_sld": float(row["len_sld"]) >= 10,
            "high_consonant_vowel_ratio": float(row["cv_ratio"]) >= 3.0,
            "high_risk_tld": bool(row["high_risk_tld"]),
        }
        weights = {
            "high_entropy": 0.25,
            "many_digits": 0.20,
            "few_dictionary_matches": 0.20,
            "long_sld": 0.10,
            "high_consonant_vowel_ratio": 0.15,
            "high_risk_tld": 0.10,
        }
        risk_score = sum(weights[name] for name, matched in signals.items() if matched)
        alert = int(risk_score >= LEXICAL_FALLBACK_THRESHOLD)
        return {
            "domain": domain,
            "prediction": alert,
            "label": "suspicious_lexical_pattern" if alert else "no_strong_lexical_signal",
            "detector_mode": "lexical_heuristic_fallback",
            "risk_score": round(risk_score, 4),
            "threshold": LEXICAL_FALLBACK_THRESHOLD,
            "calibrated_probability": None,
            "base_features": row,
            "matched_signals": [name for name, matched in signals.items() if matched],
            "evidence_note": "Rule-based triage only; not a trained DGA model prediction.",
        }
