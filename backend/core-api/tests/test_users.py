def test_list_users(client):
    response = client.get("/api/v1/users")
    assert response.status_code == 200


def test_create_user(client):
    response = client.post("/api/v1/users", json={
        "username": "newuser",
        "email": "newuser@test.com",
        "password": "password123",
        "role": "analyst",
    })
    assert response.status_code in [200, 201]


def test_get_user_not_found(client):
    response = client.get("/api/v1/users/99999")
    assert response.status_code == 404
