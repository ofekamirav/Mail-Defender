from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import pandas as pd

from .config import CSV_PATH, RETRAIN_BATCH_SIZE
from .model import MailPhishingModel, PredictionResult
from .storage import append_email_record, update_label, load_dataset



@dataclass
class ClassifiedEmail:
    email_id: str
    prediction: PredictionResult


class DetectionService:
    def __init__(self):
        self.model = MailPhishingModel()

    def classify_and_log_email(
        self,
        subject: str,
        body: str,
        sender: str,
        source: str = "gmail_addon",
    ) -> ClassifiedEmail:
        prediction = self.model.predict_email(subject, body, sender)

        email_id = append_email_record(
            subject=subject,
            body=body,
            sender=sender,
            source=source,
            ml_score=prediction.ml_score,
            rule_score=prediction.rule_score,
            final_score=prediction.final_score,
            label="",
            csv_path=CSV_PATH,
        )

        return ClassifiedEmail(email_id=email_id, prediction=prediction)

    def apply_user_feedback(self, email_id: str, is_phishing: bool) -> bool:
        true_label = 1 if is_phishing else 0
        success = update_label(email_id=email_id, true_label=true_label, csv_path=CSV_PATH)

        if not success:
            return False

        df = load_dataset(CSV_PATH)
        labeled_mask = pd.to_numeric(df["label"], errors="coerce").notnull()
        labeled_count = int(labeled_mask.sum())

        if labeled_count > 0 and labeled_count % RETRAIN_BATCH_SIZE == 0:
            self.model.train_from_csv(CSV_PATH)

        return True
