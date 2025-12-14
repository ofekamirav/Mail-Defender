from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from .config import MODEL_PATH, VECTORIZER_MAX_FEATURES
from .features import compute_heuristics


@dataclass(frozen=True)
class PredictionResult:
    final_score: float
    ml_score: float
    rule_score: float
    label: str
    confidence: str
    reasoning: str


class MailPhishingModel:
    def __init__(self):
        self.pipeline: Optional[Pipeline] = None
        self.known_data: Optional[pd.DataFrame] = None

        if os.path.exists(MODEL_PATH):
            self.load()

        self._load_known_data_best_effort()

    def _load_known_data_best_effort(self) -> None:
        try:
            from .config import CSV_PATH
            from .storage import load_dataset

            df = load_dataset(CSV_PATH)
            if df.empty:
                self.known_data = None
                return

            labels = pd.to_numeric(df.get("label", pd.Series([])), errors="coerce")
            mask = labels.isin([0, 1])
            df = df.loc[mask].copy()
            if df.empty:
                self.known_data = None
                return

            df["label"] = labels.loc[mask].astype(int)

            df["subject"] = df.get("subject", "").fillna("").astype(str)
            df["body"] = df.get("body", "").fillna("").astype(str)
            df["sender"] = df.get("sender", "").fillna("").astype(str)

            df["text_raw"] = df["subject"] + " " + df["body"]
            df["text"] = df["text_raw"].map(self.clean_email_text)

            df = df[df["text"].str.len() > 0].copy()
            self.known_data = df[["text", "label"]].copy()

        except Exception:
            self.known_data = None

    def clean_email_text(self, text: str) -> str:
        if not isinstance(text, str):
            return ""

        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"http[s]?://\S+", "URL_LINK", text)
        text = re.sub(r"\b\d{4,}\b", "NUMBER_TOKEN", text)
        text = re.sub(r"\s+", " ", text).strip().lower()
        return text

    def train_from_dataframe(self, df: pd.DataFrame) -> None:
        required_cols = {"subject", "body", "label"}
        missing = required_cols - set(df.columns)
        if missing:
            raise ValueError(f"Missing columns for training: {missing}")

        work = df.copy()

        work["subject"] = work["subject"].fillna("").astype(str)
        work["body"] = work["body"].fillna("").astype(str)

        labels = pd.to_numeric(work["label"], errors="coerce")
        mask_valid = labels.isin([0, 1])
        work = work.loc[mask_valid].copy()
        work["label"] = labels.loc[mask_valid].astype(int)

        work["text_raw"] = work["subject"] + " " + work["body"]
        work["text"] = work["text_raw"].map(self.clean_email_text)
        work = work[work["text"].str.len() > 0].copy()

        if len(work) < 5:
            print(f"[MODEL] Not enough labeled samples to train (have {len(work)}). Skipping.")
            self.known_data = work[["text", "label"]].copy() if len(work) else None
            return

        if work["label"].nunique() < 2:
            print("[MODEL] Only one class present. Need both 0 and 1. Skipping.")
            self.known_data = work[["text", "label"]].copy()
            return

        self.known_data = work[["text", "label"]].copy()

        X = work["text"]
        y = work["label"]

        self.pipeline = Pipeline(steps=[
            ("tfidf", TfidfVectorizer(
                max_features=VECTORIZER_MAX_FEATURES,
                ngram_range=(1, 2),
                stop_words="english",
                lowercase=True,
                min_df=1,
                max_df=0.95,
                sublinear_tf=True,
            )),
            ("clf", LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=42,
                solver="lbfgs",
            )),
        ])

        self.pipeline.fit(X, y)
        self.save()
        print(f"[MODEL] Model trained successfully on {len(work)} samples.")

    def train_from_csv(self, csv_path: str) -> None:
        try:
            df = pd.read_csv(csv_path)
            self.train_from_dataframe(df)
        except Exception as e:
            print(f"[MODEL] Error training from CSV: {e}")

    def save(self, path: Optional[str] = None) -> None:
        if self.pipeline is None:
            return
        path = path or MODEL_PATH
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.pipeline, path)

    def load(self, path: Optional[str] = None) -> None:
        path = path or MODEL_PATH
        try:
            self.pipeline = joblib.load(path)
            print("[MODEL] Model loaded successfully.")
        except Exception as e:
            print(f"[MODEL] Failed to load model: {e}")
            self.pipeline = None

    def _predict_ml_proba(self, cleaned_text: str) -> float:
        if self.pipeline is None:
            return 0.5
        try:
            return float(self.pipeline.predict_proba([cleaned_text])[0][1])
        except Exception:
            return 0.5

    def _get_reasoning(self, subject: str, body: str, sender: str,
                       ml_score: float, rule_score: float, heuristics: dict) -> str:
        reasons = []

        if heuristics.get("typosquatting"):
            reasons.append("Domain typosquatting detected")
        if heuristics.get("has_ip_as_url"):
            reasons.append("Direct IP address in links")
        if heuristics.get("domain_mismatch"):
            reasons.append("Links point to different domain")

        language_risk = heuristics.get("language_risk", 0)
        if language_risk > 0.2:
            reasons.append("Suspicious language patterns")

        sender_rep = heuristics.get("sender_reputation_risk", 0)
        if sender_rep > 0.15:
            reasons.append("Questionable sender reputation")

        is_marketing = heuristics.get("is_marketing_email", 0) > 0.5
        if ml_score > 0.7:
            reasons.append("Text pattern similar to phishing" if not is_marketing else "ML recognizes marketing patterns")
        elif ml_score < 0.3:
            reasons.append("ML indicates legitimate email")

        if not reasons:
            reasons.append("Standard email - no red flags detected")

        return " | ".join(reasons[:2])

    def predict_email(self, subject: str, body: str, sender: str) -> PredictionResult:
        raw_text = (subject or "") + " " + (body or "")
        cleaned_text = self.clean_email_text(raw_text)

        ml_score = 0.5
        override_found = False

        if self.known_data is not None and len(cleaned_text) > 0:
            match = self.known_data[self.known_data["text"] == cleaned_text]
            if not match.empty:
                user_label = int(match.iloc[-1]["label"])
                ml_score = 0.95 if user_label == 1 else 0.05
                override_found = True
                print(f"[MODEL] Found exact match in known data with label {user_label}")

        if not override_found:
            ml_score = self._predict_ml_proba(cleaned_text)

        heuristics = compute_heuristics(subject, body, sender)
        rule_score = float(heuristics.get("rule_score", 0.0))

        weight_ml = 0.7
        weight_rule = 0.3

        if rule_score > 0.8:
            weight_ml = 0.3
            weight_rule = 0.7
        elif rule_score < 0.15:
            weight_ml = 0.5
            weight_rule = 0.5

        if override_found:
            weight_ml = 1.0
            weight_rule = 0.0

        final_score = (weight_ml * ml_score) + (weight_rule * rule_score)

        if final_score >= 0.70:
            label = "Phishing"
            confidence = "HIGH" if final_score >= 0.82 else "MEDIUM"
        elif final_score >= 0.40:
            label = "Suspicious"
            confidence = "MEDIUM"
        else:
            label = "Safe"
            confidence = "HIGH" if final_score <= 0.20 else "MEDIUM"

        reasoning = self._get_reasoning(subject, body, sender, ml_score, rule_score, heuristics)

        return PredictionResult(
            final_score=round(float(final_score), 3),
            ml_score=round(float(ml_score), 3),
            rule_score=round(float(rule_score), 3),
            label=label,
            confidence=confidence,
            reasoning=reasoning,
        )
