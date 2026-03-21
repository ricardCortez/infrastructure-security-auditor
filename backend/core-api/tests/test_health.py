def test_health_ready(client):
    response = client.get("/api/v1/health/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_health_live(client):
    response = client.get("/api/v1/health/live")
    assert response.status_code == 200
