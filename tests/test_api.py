def test_health_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json() == {"status": "ok"}


def test_predict_empty_rejected(client):
    r = client.post("/predict", json={"subject": "", "body": "", "sender": ""})
    assert r.status_code == 400
    assert "detail" in r.get_json()


def test_predict_success_contract(client):
    r = client.post("/predict", json={"subject": "hi", "body": "test", "sender": "a@b.com"})
    assert r.status_code == 200
    j = r.get_json()

    for k in ["id", "label", "final_score", "ml_score", "rule_score",
              "already_seen", "already_labeled", "label_source",
              "scan_count", "first_seen_at", "last_seen_at"]:
        assert k in j

    assert isinstance(j["final_score"], (int, float))
    assert isinstance(j["already_seen"], bool)
    assert isinstance(j["scan_count"], int)


def test_feedback_missing_id(client):
    r = client.post("/feedback", json={"is_phishing": True})
    assert r.status_code == 400


def test_feedback_invalid_bool(client):
    r = client.post("/feedback", json={"id": "test-id-123", "is_phishing": "maybe"})
    assert r.status_code == 400


def test_feedback_not_found(client):
    r = client.post("/feedback", json={"id": "no-such-id", "is_phishing": True})
    assert r.status_code == 404


def test_feedback_ok(client):
    r = client.post("/feedback", json={"id": "test-id-123", "is_phishing": False})
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"
