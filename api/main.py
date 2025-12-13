from flask import Flask, request, jsonify
from flask_cors import CORS

from detector.service import DetectionService

app = Flask(__name__)
CORS(app)

service = DetectionService()

@app.get("/health")
def health_check():
    return jsonify({"status": "ok"})

@app.post("/predict")
def predict():
    data = request.get_json(silent=True) or {}

    subject = data.get("subject", "")
    body = data.get("body", "")
    sender = data.get("sender", "")

    classified = service.classify_and_log_email(
        subject=subject,
        body=body,
        sender=sender,
        source="gmail_addon",
    )

    return jsonify({
        "id": classified.email_id,
        "label": classified.prediction.label,
        "final_score": classified.prediction.final_score,
        "ml_score": classified.prediction.ml_score,
        "rule_score": classified.prediction.rule_score,
    })

@app.post("/feedback")
def feedback():
    data = request.get_json(silent=True) or {}

    email_id = data.get("id")
    is_phishing = data.get("is_phishing")

    if email_id is None or is_phishing is None:
        return jsonify({"detail": "Missing id or is_phishing"}), 400

    updated = service.apply_user_feedback(
        email_id=str(email_id),
        is_phishing=bool(is_phishing),
    )

    if not updated:
        return jsonify({"detail": "Email ID not found"}), 404

    return jsonify({"status": "ok", "message": "Feedback received"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
