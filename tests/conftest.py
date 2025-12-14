import pytest

import os
import sys
from pathlib import Path
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from api.main import create_app
import detector.model as model
import detector.storage as storage
import detector.config as cfg





class FakePrediction:
    def __init__(self):
        self.label = "Suspicious"
        self.final_score = 0.55
        self.ml_score = 0.60
        self.rule_score = 0.40
        self.confidence = "MEDIUM"
        self.reasoning = "Suspicious language patterns"


class FakeAudit:
    def __init__(self):
        self.already_seen = True
        self.already_labeled = False
        self.label_source = "model"
        self.scan_count = 2
        self.first_seen_at = "2025-12-13T20:00:00Z"
        self.last_seen_at = "2025-12-13T20:05:00Z"


class FakeClassified:
    def __init__(self):
        self.email_id = "test-id-123"
        self.prediction = FakePrediction()
        self.audit = FakeAudit()


class FakeService:
    def __init__(self):
        self.known_ids = {"test-id-123"}

    def classify_and_log_email(self, subject: str, body: str, sender: str, source: str = "gmail_addon"):
        return FakeClassified()

    def apply_user_feedback(self, email_id: str, is_phishing: bool) -> bool:
        return email_id in self.known_ids


@pytest.fixture()
def client():
    app = create_app(service=FakeService())
    app.config["TESTING"] = True
    return app.test_client()

@pytest.fixture()
def sample_email():
    return {
        "subject": "Security Alert",
        "body": "Your account is compromised. Click here to verify now.",
        "sender": "security@paypa1.com",
    }

@pytest.fixture()
def sample_predict_payload(sample_email):
    return dict(sample_email)

@pytest.fixture()
def sample_feedback_payload_ok():
    return {"id": "test-id-123", "is_phishing": True}

@pytest.fixture()
def df_with_nans():
    return pd.DataFrame([
        {"subject": "A", "body": "B", "sender": "x@y.com", "label": 1},
        {"subject": "C", "body": "D", "sender": "x@y.com", "label": 0},
        {"subject": None, "body": "E", "sender": "x@y.com", "label": None},  
        {"subject": "F", "body": None, "sender": "x@y.com", "label": " "},   
    ])


@pytest.fixture()
def tmp_paths(monkeypatch, tmp_path: Path):
    data_dir = tmp_path / "data"
    models_dir = tmp_path / "models"
    data_dir.mkdir(parents=True, exist_ok=True)
    models_dir.mkdir(parents=True, exist_ok=True)

    csv_path = data_dir / "emails_dataset.csv"
    events_path = data_dir / "events.csv"
    model_path = models_dir / "phishing_model.joblib"

    monkeypatch.setattr(cfg, "DATA_DIR", data_dir, raising=False)
    monkeypatch.setattr(cfg, "CSV_PATH", csv_path, raising=False)
    monkeypatch.setattr(cfg, "MODELS_DIR", models_dir, raising=False)
    monkeypatch.setattr(cfg, "MODEL_PATH", model_path, raising=False)

    monkeypatch.setattr(storage, "DATA_DIR", data_dir, raising=False)
    monkeypatch.setattr(storage, "CSV_PATH", csv_path, raising=False)
    monkeypatch.setattr(storage, "EVENTS_CSV_PATH", str(events_path), raising=False)

    monkeypatch.setattr(model, "MODEL_PATH", model_path, raising=False)

    return {
        "data_dir": data_dir,
        "models_dir": models_dir,
        "csv_path": csv_path,
        "events_path": events_path,
        "model_path": model_path,
    }
