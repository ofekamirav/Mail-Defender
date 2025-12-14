import csv
from pathlib import Path

import pandas as pd
import pytest

import detector.config as cfg
import detector.storage as storage
from detector.storage import load_dataset, update_label, upsert_scan_record


@pytest.fixture()
def sample_email():
    return {
        "subject": "Security Alert",
        "body": "Your account is compromised. Click here to verify now.",
        "sender": "security@paypa1.com",
    }


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
    monkeypatch.setattr(storage, "EVENTS_CSV_PATH", events_path, raising=False)

    return {
        "data_dir": data_dir,
        "models_dir": models_dir,
        "csv_path": csv_path,
        "events_path": events_path,
        "model_path": model_path,
    }


def read_events(events_path: Path):
    if not events_path.exists():
        return []
    with open(events_path, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_upsert_creates_new_row_and_event(tmp_paths, sample_email):
    r = upsert_scan_record(
        subject=sample_email["subject"],
        body=sample_email["body"],
        sender=sample_email["sender"],
        source="gmail_addon",
        ml_score=0.10,
        rule_score=0.20,
        final_score=0.30,
        predicted_label="Suspicious",
        csv_path=tmp_paths["csv_path"],
    )

    assert r.already_seen is False
    assert r.scan_count == 1
    assert r.email_id

    df = load_dataset(tmp_paths["csv_path"])
    assert len(df) == 1
    assert df.loc[0, "id"] == r.email_id
    assert str(df.loc[0, "fingerprint"])
    assert int(pd.to_numeric(df.loc[0, "scan_count"], errors="coerce")) == 1

    events = read_events(Path(tmp_paths["events_path"]))
    assert len(events) == 1
    assert events[0]["event_type"] == "scan"
    assert events[0]["email_id"] == r.email_id


def test_upsert_dedup_increments_scan_count(tmp_paths, sample_email):
    r1 = upsert_scan_record(
        subject=sample_email["subject"],
        body=sample_email["body"],
        sender=sample_email["sender"],
        source="gmail_addon",
        ml_score=0.10,
        rule_score=0.20,
        final_score=0.30,
        predicted_label="Suspicious",
        csv_path=tmp_paths["csv_path"],
    )

    r2 = upsert_scan_record(
        subject=sample_email["subject"],
        body=sample_email["body"],
        sender=sample_email["sender"],
        source="gmail_addon",
        ml_score=0.11,
        rule_score=0.21,
        final_score=0.31,
        predicted_label="Suspicious",
        csv_path=tmp_paths["csv_path"],
    )

    assert r2.already_seen is True
    assert r2.email_id == r1.email_id
    assert r2.scan_count == 2

    df = load_dataset(tmp_paths["csv_path"])
    assert len(df) == 1
    assert int(pd.to_numeric(df.loc[0, "scan_count"], errors="coerce")) == 2
    assert float(pd.to_numeric(df.loc[0, "final_score"], errors="coerce")) == pytest.approx(0.31, rel=1e-6)

    events = read_events(Path(tmp_paths["events_path"]))
    assert len(events) == 2
    assert events[0]["event_type"] == "scan"
    assert events[1]["event_type"] == "scan"


def test_update_label_updates_row_and_appends_feedback_event(tmp_paths, sample_email):
    r = upsert_scan_record(
        subject=sample_email["subject"],
        body=sample_email["body"],
        sender=sample_email["sender"],
        source="gmail_addon",
        ml_score=0.10,
        rule_score=0.20,
        final_score=0.30,
        predicted_label="Suspicious",
        csv_path=tmp_paths["csv_path"],
    )

    res = update_label(email_id=r.email_id, true_label=1, csv_path=tmp_paths["csv_path"])
    assert res.success is True

    df = load_dataset(tmp_paths["csv_path"])
    assert len(df) == 1
    assert int(pd.to_numeric(df.loc[0, "label"], errors="coerce")) == 1
    assert str(df.loc[0, "label_source"]) == "user_feedback"
    assert str(df.loc[0, "labeled_at"])

    events = read_events(Path(tmp_paths["events_path"]))
    assert len(events) == 2
    assert events[1]["event_type"] == "feedback"
    assert events[1]["email_id"] == r.email_id


def test_update_label_missing_id_returns_false(tmp_paths):
    res = update_label(email_id="missing-id", true_label=0, csv_path=tmp_paths["csv_path"])
    assert res.success is False

    assert Path(tmp_paths["csv_path"]).exists()
