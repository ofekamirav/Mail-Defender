from pathlib import Path

import numpy as np
import pandas as pd
import pytest

import detector.config as cfg
import detector.model as model_mod
from detector.model import MailPhishingModel


@pytest.fixture()
def tmp_training_paths(monkeypatch, tmp_path: Path):
    data_dir = tmp_path / "data"
    models_dir = tmp_path / "models"
    data_dir.mkdir(parents=True, exist_ok=True)
    models_dir.mkdir(parents=True, exist_ok=True)

    csv_path = data_dir / "emails_dataset.csv"
    model_path = models_dir / "phishing_model.joblib"

    monkeypatch.setattr(cfg, "DATA_DIR", data_dir, raising=False)
    monkeypatch.setattr(cfg, "CSV_PATH", csv_path, raising=False)
    monkeypatch.setattr(cfg, "MODELS_DIR", models_dir, raising=False)
    monkeypatch.setattr(cfg, "MODEL_PATH", model_path, raising=False)

    monkeypatch.setattr(model_mod, "DATA_DIR", data_dir, raising=False)
    monkeypatch.setattr(model_mod, "CSV_PATH", csv_path, raising=False)
    monkeypatch.setattr(model_mod, "MODELS_DIR", models_dir, raising=False)
    monkeypatch.setattr(model_mod, "MODEL_PATH", model_path, raising=False)

    return {"data_dir": data_dir, "models_dir": models_dir, "csv_path": csv_path, "model_path": model_path}


def _is_model_trained(m: MailPhishingModel) -> bool:
    for attr in ("pipeline", "model", "clf", "vectorizer"):
        if hasattr(m, attr) and getattr(m, attr) is not None:
            return True
    return False


def test_train_from_dataframe_handles_nan(tmp_training_paths):
    df = pd.DataFrame(
        [
            {"subject": "Security Alert", "body": "Verify your account now", "sender": "security@paypa1.com", "label": 1},
            {"subject": np.nan, "body": "Click here to reset password", "sender": "support@google-security.xyz", "label": 1},
            {"subject": "Meeting", "body": np.nan, "sender": "boss@company.com", "label": 0},
            {"subject": None, "body": None, "sender": "friend@gmail.com", "label": 0},
            {"subject": "Invoice", "body": "Attached invoice", "sender": "billing@company.com", "label": 0},
            {"subject": "Win prize", "body": "urgent claim now", "sender": "lottery@winner-lucky.xyz", "label": 1},
        ]
    )

    m = MailPhishingModel()
    m.train_from_dataframe(df)

    assert _is_model_trained(m) or Path(tmp_training_paths["model_path"]).exists()



def test_train_from_csv_skips_when_not_enough_labeled_samples(tmp_training_paths):
    df = pd.DataFrame(
        [
            {"subject": "A", "body": "B", "sender": "a@a.com", "label": ""},     
            {"subject": "Security Alert", "body": "Verify your account now", "sender": "security@paypa1.com", "label": 1},
            {"subject": "Meeting", "body": "See you at 10", "sender": "boss@company.com", "label": 0},
            {"subject": "C", "body": "D", "sender": "c@c.com", "label": None},  
        ]
    )
    df.to_csv(tmp_training_paths["csv_path"], index=False)

    m = MailPhishingModel()
    m.train_from_csv(str(tmp_training_paths["csv_path"]))

    assert not Path(tmp_training_paths["model_path"]).exists()


def test_train_from_csv_trains_when_enough_labeled_samples(tmp_training_paths):
    df = pd.DataFrame(
        [
            {"subject": "Win a prize", "body": "urgent claim now", "sender": "lottery@winner-lucky.xyz", "label": 1},
            {"subject": "Security Alert", "body": "Verify your account now", "sender": "security@paypa1.com", "label": 1},
            {"subject": "Invoice", "body": "Attached is your invoice", "sender": "billing@company.com", "label": 0},
            {"subject": "Meeting", "body": "See you at 10", "sender": "boss@company.com", "label": 0},
            {"subject": "Hi", "body": "how are you", "sender": "friend@gmail.com", "label": 0},
            {"subject": np.nan, "body": "Click here to login", "sender": "support@amaz0n.xyz", "label": 1},
            {"subject": "Promo", "body": "sale discount offer", "sender": "deals@shop.com", "label": ""},  
        ]
    )
    df.to_csv(tmp_training_paths["csv_path"], index=False)

    m = MailPhishingModel()
    m.train_from_csv(str(tmp_training_paths["csv_path"]))

    assert Path(tmp_training_paths["model_path"]).exists()



