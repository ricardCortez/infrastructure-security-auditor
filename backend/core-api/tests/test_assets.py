def test_list_assets(client):
    response = client.get("/api/v1/assets")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_create_asset(client):
    response = client.post("/api/v1/assets", json={
        "hostname": "test-server",
        "ip_address": "192.168.1.1",
        "asset_type": "server",
        "criticality": "high",
    })
    assert response.status_code in [200, 201]


def test_get_asset_not_found(client):
    response = client.get("/api/v1/assets/99999")
    assert response.status_code == 404
