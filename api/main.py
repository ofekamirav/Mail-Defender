from __future__ import annotations

import os
from typing import Any

from flask import Flask, request, jsonify
from flask_cors import CORS

from detector.service import DetectionService


def validate_predict_payload(data: dict) -> tuple[dict, str | None]:
    subject = data.get("subject", "")
    body = data.get("body", "")
    sender = data.get("sender", "")

    subject = "" if subject is None else str(subject).strip()
    body = "" if body is None else str(body).strip()
    sender = "" if sender is None else str(sender).strip()

    if not subject and not body:
        return {}, "subject/body cannot both be empty"

    if len(subject) > 300:
        subject = subject[:300]

    if len(body) > 50_000:
        body = body[:50_000]

    if len(sender) > 320:
        sender = sender[:320]

    return {"subject": subject, "body": body, "sender": sender}, None


def parse_bool_strict(value: Any) -> tuple[bool | None, str | None]:
    if isinstance(value, bool):
        return value, None

    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value), None

    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "1", "yes", "y"):
            return True, None
        if v in ("false", "0", "no", "n"):
            return False, None

    return None, "is_phishing must be a real boolean (true/false)"


def create_app(service: DetectionService | None = None) -> Flask:
    app = Flask(__name__)
    CORS(app)

    svc = service or DetectionService()

    @app.get("/health")
    def health_check():
        return jsonify({"status": "ok"})

    @app.post("/predict")
    def predict():
        data = request.get_json(silent=True) or {}
        payload, err = validate_predict_payload(data)
        if err:
            return jsonify({"detail": err}), 400

        classified = svc.classify_and_log_email(
            subject=payload["subject"],
            body=payload["body"],
            sender=payload["sender"],
            source="gmail_addon",
        )

        resp = {
            "id": classified.email_id,
            "label": classified.prediction.label,
            "final_score": classified.prediction.final_score,
            "ml_score": classified.prediction.ml_score,
            "rule_score": classified.prediction.rule_score,
            "already_seen": classified.audit.already_seen,
            "already_labeled": classified.audit.already_labeled,
            "label_source": classified.audit.label_source,
            "scan_count": classified.audit.scan_count,
            "first_seen_at": classified.audit.first_seen_at,
            "last_seen_at": classified.audit.last_seen_at,
        }

        if hasattr(classified.prediction, "confidence"):
            resp["confidence"] = getattr(classified.prediction, "confidence")

        if hasattr(classified.prediction, "reasoning"):
            resp["reasoning"] = getattr(classified.prediction, "reasoning")

        return jsonify(resp)

    @app.post("/feedback")
    def feedback():
        data = request.get_json(silent=True) or {}

        email_id = data.get("id")
        raw_is_phishing = data.get("is_phishing")

        if email_id is None:
            return jsonify({"detail": "Missing id"}), 400

        is_phishing, err = parse_bool_strict(raw_is_phishing)
        if err:
            return jsonify({"detail": err}), 400

        updated = svc.apply_user_feedback(email_id=str(email_id), is_phishing=is_phishing)
        if not updated:
            return jsonify({"detail": "Email ID not found"}), 404

        return jsonify({"status": "ok", "message": "Feedback received"})

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
