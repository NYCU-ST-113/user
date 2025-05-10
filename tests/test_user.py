import sys
import os
# This will add apply_service to the module path, allowing main.py to import correctly
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from main import app
from fastapi.testclient import TestClient
import pytest
from unittest.mock import patch, Mock
import jwt
from fastapi import FastAPI
from routers import user

client = TestClient(app)


mock_access_token = "mock_access_token"
mock_user_info = {"username": "test_user", "email": "test_user@example.com"}


def test_root_service():
    response = client.get("/user/")
    assert response.status_code == 200
    assert response.json() == {"message": "User service is working"}

def test_login():
    response = client.get("/user/login")
    first = response.history[0]
    print(first.status_code)
    assert first.status_code == 307
    assert "location" in first.headers
    assert first.headers["location"].startswith("https://id.nycu.edu.tw/o/authorize/")


#     assert "location" in response.headers  # Should have a location header for redirect

# test /user/callback success
@patch("requests.post")
@patch("requests.get")
def test_callback_success(mock_get, mock_post):
    mock_post.return_value = Mock(status_code=200, json=lambda: {"access_token": mock_access_token})
    mock_get.return_value = Mock(status_code=200, json=lambda: mock_user_info)

    response = client.get("/user/callback?code=mock_code")
    assert response.status_code == 200
    assert "jwt_token" in response.json()
    assert "user_info" in response.json()
    assert response.json()["user_info"]["username"] == "test_user"

    jwt_token = response.json()["jwt_token"]
    payload = jwt.decode(jwt_token, "super_secret_for_my_app", algorithms=["HS256"])
    assert payload["username"] == "test_user"
    assert payload["email"] == "test_user@example.com"

# Test missing authentication code
def test_callback_missing_code():
    response = client.get("/user/callback")
    assert response.status_code == 400
    assert response.json()["detail"] == "Missing code from NYCU"

# Test not get access_token
@patch("requests.post")
def test_callback_access_token_failure(mock_post):
    mock_post.return_value = Mock(status_code=400, json=lambda: {})

    response = client.get("/user/callback?code=mock_code")
    assert response.status_code == 400
    assert response.json()["detail"] == "Failed to get access token"

    mock_post.return_value = Mock(status_code=200, json=lambda: {})
    response = client.get("/user/callback?code=anycode")
    assert response.status_code == 400
    assert response.json()["detail"] == "Access token missing"

# Test get user info failure
@patch("requests.post")
@patch("requests.get")
def test_callback_userinfo_failure(mock_get, mock_post):
    mock_post.return_value = Mock(status_code=200, json=lambda: {"access_token": mock_access_token})
    mock_get.return_value = Mock(status_code=400)

    response = client.get("/user/callback?code=mock_code")
    assert response.status_code == 400
    assert response.json()["detail"] == "Failed to get profile info"
