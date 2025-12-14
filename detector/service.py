from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from .config import CSV_PATH, RETRAIN_BATCH_SIZE, MIN_LABELED_TO_TRAIN
from .model import MailPhishingModel, PredictionResult
from .storage import upsert_scan_record, update_label, load_dataset


@dataclass(frozen=True)
class AuditInfo:
    already_seen: bool
    already_labeled: bool
    label_source: str
    scan_count: int
    first_seen_at: str
    last_seen_at: str


@dataclass(frozen=True)
class ClassifiedEmail:
    email_id: str
    prediction: PredictionResult
    audit: AuditInfo


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

        upsert = upsert_scan_record(
            subject=subject,
            body=body,
            sender=sender,
            source=source,
            ml_score=prediction.ml_score,
            rule_score=prediction.rule_score,
            final_score=prediction.final_score,
            predicted_label=prediction.label,
            csv_path=CSV_PATH,
        )

        audit = AuditInfo(
            already_seen=upsert.already_seen,
            already_labeled=upsert.already_labeled,
            label_source=upsert.label_source,
            scan_count=upsert.scan_count,
            first_seen_at=upsert.first_seen_at,
            last_seen_at=upsert.last_seen_at,
        )

        return ClassifiedEmail(email_id=upsert.email_id, prediction=prediction, audit=audit)

    def apply_user_feedback(self, email_id: str, is_phishing: bool) -> bool:
        true_label = 1 if is_phishing else 0

        res = update_label(email_id=email_id, true_label=true_label, csv_path=CSV_PATH)
        if not res.success:
            return False

        if not res.newly_labeled:
            return True

        df = load_dataset(CSV_PATH)

        labels = pd.to_numeric(df["label"], errors="coerce")
        valid = labels.isin([0, 1])
        labeled_count = int(valid.sum())

        if labeled_count < MIN_LABELED_TO_TRAIN:
            return True

        if labeled_count % RETRAIN_BATCH_SIZE == 0:
            try:
                self.model.train_from_csv(str(CSV_PATH))
                print("[SERVICE] Model retrained successfully after feedback.")
            except Exception as e:
                print(f"[SERVICE] Error training from CSV: {e}")

        return True
