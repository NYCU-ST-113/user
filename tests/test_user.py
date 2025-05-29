import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import pytest
import jwt
from datetime import datetime, timedelta
from unittest.mock import patch, Mock
from fastapi.testclient import TestClient
from fastapi import FastAPI
from main import app  # 假設 main.py 是你的 FastAPI 應用入口

client = TestClient(app)

# 模擬常量
JWT_SECRET = "super_secret_for_my_app"
JWT_ALGORITHM = "HS256"
MOCK_ACCESS_TOKEN = "mock_access_token"
MOCK_USER_INFO = {"username": "test_user", "email": "test_user@example.com"}
ADMIN_USER = "313581017"  # 模擬管理員用戶
NON_ADMIN_USER = "test_user"

# 輔助函數：生成模擬 JWT token
def generate_jwt_token(username, role="user", expired=False):
    exp = datetime.utcnow() - timedelta(hours=1) if expired else datetime.utcnow() + timedelta(hours=1)
    payload = {
        "username": username,
        "email": f"{username}@example.com",
        "role": role,
        "exp": exp
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

# 測試根端點
def test_root_service():
    response = client.get("/user/")
    assert response.status_code == 200
    assert response.json() == {"message": "User service is working"}

# 測試 /login 重定向

def test_login():
    response = client.get("/user/login")
    first = response.history[0]
    print(first.status_code)
    assert first.status_code == 307
    assert "location" in first.headers
    assert first.headers["location"].startswith("https://id.nycu.edu.tw/o/authorize/")


# 測試 /callback 成功（非管理員）
@patch("requests.post")
@patch("requests.get")
def test_callback_success_non_admin(mock_get, mock_post):
    mock_post.return_value = Mock(status_code=200, json=lambda: {"access_token": MOCK_ACCESS_TOKEN})
    mock_get.return_value = Mock(status_code=200, json=lambda: MOCK_USER_INFO)

    response = client.get("/user/callback?code=mock_code")
    assert response.status_code == 200
    assert "jwt_token" in response.json()
    assert "user_info" in response.json()
    assert response.json()["user_info"]["username"] == "test_user"

    jwt_token = response.json()["jwt_token"]
    payload = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    assert payload["username"] == "test_user"
    assert payload["email"] == "test_user@example.com"
    assert payload["role"] == "student"

# 測試 /callback 成功（管理員）
@patch("requests.post")
@patch("requests.get")
def test_callback_success_admin(mock_get, mock_post):
    admin_user_info = {"username": ADMIN_USER, "email": "admin@example.com"}
    mock_post.return_value = Mock(status_code=200, json=lambda: {"access_token": MOCK_ACCESS_TOKEN})
    mock_get.return_value = Mock(status_code=200, json=lambda: admin_user_info)

    response = client.get("/user/callback?code=mock_code")
    assert response.status_code == 200
    assert "jwt_token" in response.json()
    assert response.json()["user_info"]["username"] == ADMIN_USER

    jwt_token = response.json()["jwt_token"]
    payload = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    assert payload["username"] == ADMIN_USER
    assert payload["role"] == "admin"

# 測試 /callback 缺少 code
def test_callback_missing_code():
    response = client.get("/user/callback")
    assert response.status_code == 400
    assert response.json()["detail"] == "Missing code from NYCU"

# 測試 /callback 無法取得 access token
@patch("requests.post")
def test_callback_access_token_failure(mock_post):
    mock_post.return_value = Mock(status_code=400, json=lambda: {})
    response = client.get("/user/callback?code=mock_code")
    assert response.status_code == 400
    assert response.json()["detail"] == "Failed to get access token"

    mock_post.return_value = Mock(status_code=200, json=lambda: {})
    response = client.get("/user/callback?code=mock_code")
    assert response.status_code == 400
    assert response.json()["detail"] == "Access token missing"

# 測試 /callback 無法取得 user info
@patch("requests.post")
@patch("requests.get")
def test_callback_userinfo_failure(mock_get, mock_post):
    mock_post.return_value = Mock(status_code=200, json=lambda: {"access_token": MOCK_ACCESS_TOKEN})
    mock_get.return_value = Mock(status_code=400)

    response = client.get("/user/callback?code=mock_code")
    assert response.status_code == 400
    assert response.json()["detail"] == "Failed to get profile info"

# 測試 /logout
def test_logout():
    response = client.get("/user/logout")
    assert response.status_code == 200
    assert response.json() == {"message": "Logged out"}
    cookie = response.headers.get("Set-Cookie", "")
    assert "access_token=" in cookie  # 檢查 cookie 名稱
    assert "Max-Age=0" in cookie  # 檢查 cookie 被清除


# 測試 /verify-admin（管理員）
def test_verify_admin_success_admin():
    token = generate_jwt_token(ADMIN_USER, role="admin")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/user/verify-admin", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"is_admin": True, "username": ADMIN_USER}

# 測試 /verify-admin（非管理員）
def test_verify_admin_success_non_admin():
    token = generate_jwt_token(NON_ADMIN_USER, role="user")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/user/verify-admin", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"is_admin": False, "username": NON_ADMIN_USER}

# 測試 /verify-admin（缺少 token）
def test_verify_admin_missing_token():
    response = client.get("/user/verify-admin")
    assert response.status_code == 401
    assert response.json()["detail"] == "Missing token"

# 測試 /verify-admin（無效 token）
def test_verify_admin_invalid_token():
    headers = {"Authorization": "Bearer invalid_token"}
    response = client.get("/user/verify-admin", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid token"

# 測試 /verify-admin（過期 token）
def test_verify_admin_expired_token():
    token = generate_jwt_token(ADMIN_USER, role="admin", expired=True)
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/user/verify-admin", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Token expired"

# 測試 /verify-admin（缺少 username 的 token）
def test_verify_admin_missing_username():
    payload = {
        "email": "test@example.com",
        "role": "admin",
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/user/verify-admin", headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid token payload"

# 測試 /admin-only（管理員）
def test_admin_only_success():
    token = generate_jwt_token(ADMIN_USER, role="admin")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/user/admin-only", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"message": f"Hello admin {ADMIN_USER}!"}

# 測試 /admin-only（非管理員）
def test_admin_only_non_admin():
    token = generate_jwt_token(NON_ADMIN_USER, role="user")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/user/admin-only", headers=headers)
    assert response.status_code == 403
    assert response.json()["detail"] == "Permission denied"

# 測試 /admin-only（無效 token）
def test_admin_only_invalid_token():
    headers = {"Authorization": "Bearer invalid_token"}
    response = client.get("/user/admin-only", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid token"

# 測試 /me（成功）
def test_me_success():
    token = generate_jwt_token(ADMIN_USER, role="admin")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/user/me", headers=headers)
    assert response.status_code == 200
    assert response.json()["message"] == "You are logged in"
    assert response.json()["user"]["username"] == ADMIN_USER
    assert response.json()["user"]["role"] == "admin"

# 測試 /me（無效 token）
def test_me_invalid_token():
    headers = {"Authorization": "Bearer invalid_token"}
    response = client.get("/user/me", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid token"

# 測試 /me（缺少 token）
def test_me_missing_token():
    response = client.get("/user/me")
    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized"