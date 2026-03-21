def test_list_findings(client):
    response = client.get("/api/v1/findings")
    assert response.status_code == 200


def test_filter_findings_by_status(client):
    response = client.get("/api/v1/findings?status=OPEN")
    assert response.status_code == 200


def test_get_finding_not_found(client):
    response = client.get("/api/v1/findings/99999")
    assert response.status_code == 404
