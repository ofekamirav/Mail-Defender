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


@dataclass
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
            try:
                from .config import CSV_PATH
                from .storage import load_dataset
                df = load_dataset(CSV_PATH)
                df = df[pd.to_numeric(df["label"], errors="coerce").notnull()].copy()
                df["label"] = df["label"].astype(int)
                df["text"] = df["subject"].fillna("") + " " + df["body"].fillna("")
                self.known_data = df
            except Exception:
                self.known_data = None
        else:
            print("No pre-trained model found.")


    def clean_email_text(self, text: str) -> str:
        """Clean and normalize email text"""
        if not isinstance(text, str):
            return ""
        
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'http[s]?://\S+', 'URL_LINK', text)
        text = re.sub(r'\b\d{4,}\b', 'NUMBER_TOKEN', text)
        text = re.sub(r'\s+', ' ', text).strip().lower()
        
        return text

    def train_from_dataframe(self, df: pd.DataFrame) -> None:
        """Train model from dataframe with improved handling"""
        df = df.dropna(subset=["subject", "body"])
        
        if df['label'].dtype == 'object':
            df = df[df['label'].astype(str).str.isnumeric()]
        df['label'] = df['label'].astype(int)
        
        df["text"] = df["subject"].fillna("") + " " + df["body"].fillna("")
        
        self.known_data = df
        
        X = df["text"]
        y = df["label"]
        
        self.pipeline = Pipeline(steps=[
            ("tfidf", TfidfVectorizer(
                max_features=VECTORIZER_MAX_FEATURES,
                ngram_range=(1, 2),
                stop_words='english',
                lowercase=True,
                min_df=1,
                max_df=0.95,
                sublinear_tf=True
            )),
            ("clf", LogisticRegression(
                max_iter=1000,
                class_weight='balanced',
                random_state=42,
                solver='lbfgs'
            )),
        ])
        
        self.pipeline.fit(X, y)
        self.save()

    def train_from_csv(self, csv_path: str) -> None:
        """Train from CSV file"""
        try:
            df = pd.read_csv(csv_path)
            self.train_from_dataframe(df)
        except Exception as e:
            print(f"Error training from CSV: {e}")

    def save(self, path: Optional[str] = None) -> None:
        """Save model to disk"""
        if self.pipeline is None:
            return
        
        path = path or MODEL_PATH
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.pipeline, path)

    def load(self, path: Optional[str] = None) -> None:
        """Load model from disk"""
        path = path or MODEL_PATH
        try:
            self.pipeline = joblib.load(path)
            print("✅ Model loaded successfully.")
        except Exception as e:
            print(f"❌ Failed to load model: {e}")
            self.pipeline = None

    def _predict_ml_proba(self, text_content: str) -> float:
        """Get ML model probability for phishing class"""
        if self.pipeline is None:
            return 0.5
        
        try:
            return float(self.pipeline.predict_proba([text_content])[0][1])
        except Exception:
            return 0.5

    def _get_reasoning(self, subject: str, body: str, sender: str, 
                       ml_score: float, rule_score: float, heuristics: dict) -> str:
        """Generate human-readable reasoning for prediction (in English)"""
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
            if is_marketing:
                reasons.append("But ML recognizes marketing patterns")
            else:
                reasons.append("Text pattern similar to phishing")
        elif ml_score < 0.3:
            reasons.append("ML indicates legitimate email")
        
        if not reasons:
            if is_marketing:
                reasons.append("Legitimate promotional email")
            else:
                reasons.append("Standard email - no red flags detected")
        
        return " | ".join(reasons[:2])

    def predict_email(self, subject: str, body: str, sender: str) -> PredictionResult:
        """
        Predict if email is phishing with improved logic
        """
        full_text = (subject or "") + " " + (body or "")
        ml_score = 0.5
        override_found = False
        
        if self.known_data is not None:
            match = self.known_data[self.known_data['text'] == full_text]
            if not match.empty:
                user_label = match.iloc[-1]['label']
                ml_score = 0.95 if user_label == 1 else 0.05
                override_found = True
                print(f"[MODEL] Found exact match in known data with label {user_label}")
        
        if not override_found:
            ml_score = self._predict_ml_proba(full_text)
        
        heuristics = compute_heuristics(subject, body, sender)
        rule_score = heuristics["rule_score"]
        
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
            final_score=round(final_score, 3),
            ml_score=round(ml_score, 3),
            rule_score=round(rule_score, 3),
            label=label,
            confidence=confidence,
            reasoning=reasoning
        )