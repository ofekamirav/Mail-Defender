import pytest

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from api.main import create_app


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
