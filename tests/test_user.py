import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from fastapi import FastAPI, HTTPException
from unittest.mock import MagicMock, patch
import mysql.connector
import jwt
import datetime
from routers.user import router, get_db_connection, get_current_user
from models import UserRole

# Mock OAuth and JWT settings
NYCU_TOKEN_RESPONSE = {
    "access_token": "mock_access_token",
    "token_type": "Bearer",
    "expires_in": 3600
}
NYCU_PROFILE_RESPONSE = {
    "username": "s123456",
    "email": "s123456@example.edu"
}
JWT_SECRET = "super_secret_for_my_app"
JWT_ALGORITHM = "HS256"
MOCK_JWT_PAYLOAD = {
    "username": "s123456",
    "email": "s123456@example.edu",
    "role": UserRole.student.value,
    "exp": (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp()
}
MOCK_JWT_PAYLOAD_NO_USERNAME = {
    "email": "s123456@example.edu",
    "role": UserRole.student.value,
    "exp": (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp()
}
MOCK_JWT_TOKEN = "mock_jwt_token"

@pytest.fixture
def mock_db_connection():
    with patch('routers.user.get_db_connection') as mock_conn:
        mock_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connection.cursor.return_value.__exit__.return_value = None
        mock_conn.return_value = mock_connection
        yield mock_connection, mock_cursor

@pytest_asyncio.fixture
async def client():
    app = FastAPI()
    app.include_router(router, prefix="/api/user")  # Match main.py prefix
    return TestClient(app)

@pytest.mark.asyncio
async def test_test_user_service(client):
    response = client.get("/api/user/")
    assert response.status_code == 200
    assert response.json() == {"message": "User service is working"}

@pytest.mark.asyncio
async def test_login(client):
    response = client.get("/api/user/login")
    assert response.status_code == 307  # RedirectResponse
    assert "https://id.nycu.edu.tw/o/authorize/" in response.headers["location"]
    assert "client_id=ZWB85FyZfKJJVEcNIHUfeJ1v3oalgaN7FjeCpb2E" in response.headers["location"]
    assert "redirect_uri=http%3A%2F%2F140.113.207.240%2Fapi%2Fuser%2Fcallback" in response.headers["location"]

@pytest.mark.asyncio
async def test_callback_success(client, mock_db_connection):
    mock_connection, mock_cursor = mock_db_connection
    mock_cursor.fetchone.return_value = None  # New user
    mock_cursor.rowcount = 1

    with patch('requests.post') as mock_post, \
         patch('requests.get') as mock_get, \
         patch('jwt.encode', return_value=MOCK_JWT_TOKEN):
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = NYCU_TOKEN_RESPONSE
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = NYCU_PROFILE_RESPONSE

        response = client.get("/api/user/callback?code=valid_code")

    assert response.status_code == 200
    assert response.json() == {
        "message": "Login success",
        "jwt_token": MOCK_JWT_TOKEN,
        "user_info": NYCU_PROFILE_RESPONSE
    }
    mock_cursor.execute.assert_any_call(
        "SELECT * FROM users WHERE username = %s", ("s123456",)
    )
    mock_cursor.execute.assert_any_call(
        "INSERT INTO users (username, email, role) VALUES (%s, %s, %s)",
        ("s123456", "s123456@example.edu", UserRole.student.value)
    )
    mock_connection.commit.assert_called()
    mock_connection.close.assert_called()

@pytest.mark.asyncio
async def test_callback_existing_user(client, mock_db_connection):
    mock_connection, mock_cursor = mock_db_connection
    mock_cursor.fetchone.return_value = {
        "username": "s123456",
        "email": "old_email@example.edu",
        "role": UserRole.student.value
    }
    mock_cursor.rowcount = 1

    with patch('requests.post') as mock_post, \
         patch('requests.get') as mock_get, \
         patch('jwt.encode', return_value=MOCK_JWT_TOKEN):
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = NYCU_TOKEN_RESPONSE
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = NYCU_PROFILE_RESPONSE

        response = client.get("/api/user/callback?code=valid_code")

    assert response.status_code == 200
    mock_cursor.execute.assert_any_call(
        "UPDATE users SET email = %s WHERE username = %s",
        ("s123456@example.edu", "s123456")
    )
    mock_connection.commit.assert_called()

@pytest.mark.asyncio
async def test_callback_missing_code(client):
    response = client.get("/api/user/callback")
    assert response.status_code == 400
    assert response.json()["detail"] == "Missing code from NYCU"

@pytest.mark.asyncio
async def test_callback_failed_token_request(client, mock_db_connection):
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 400
        response = client.get("/api/user/callback?code=valid_code")
    assert response.status_code == 400
    assert response.json()["detail"] == "Failed to get access token"

@pytest.mark.asyncio
async def test_callback_missing_access_token(client, mock_db_connection):
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {}
        response = client.get("/api/user/callback?code=valid_code")
    assert response.status_code == 400
    assert response.json()["detail"] == "Access token missing"

@pytest.mark.asyncio
async def test_callback_failed_profile_request(client, mock_db_connection):
    with patch('requests.post') as mock_post, \
         patch('requests.get') as mock_get:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = NYCU_TOKEN_RESPONSE
        mock_get.return_value.status_code = 400
        response = client.get("/api/user/callback?code=valid_code")
    assert response.status_code == 400
    assert response.json()["detail"] == "Failed to get profile info"

@pytest.mark.asyncio
async def test_callback_db_error(client, mock_db_connection):
    mock_connection, mock_cursor = mock_db_connection
    mock_cursor.execute.side_effect = mysql.connector.Error("DB Error")

    with patch('requests.post') as mock_post, \
         patch('requests.get') as mock_get, \
         patch('jwt.encode', return_value=MOCK_JWT_TOKEN):
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = NYCU_TOKEN_RESPONSE
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = NYCU_PROFILE_RESPONSE

        with pytest.raises(mysql.connector.Error) as exc:
            client.get("/api/user/callback?code=valid_code")
        assert str(exc.value) == "DB Error"

@pytest.mark.asyncio
async def test_logout(client):
    response = client.get("/api/user/logout")
    assert response.status_code == 200
    assert response.json() == {"message": "Logged out"}

@pytest.mark.asyncio
async def test_get_current_user_success():
    with patch('jwt.decode', return_value=MOCK_JWT_PAYLOAD):
        request = MagicMock()
        request.headers.get.return_value = "Bearer mock_jwt_token"
        payload = get_current_user(request)
        assert payload == MOCK_JWT_PAYLOAD

@pytest.mark.asyncio
async def test_get_current_user_no_auth_header():
    request = MagicMock()
    request.headers.get.return_value = None
    with pytest.raises(HTTPException) as exc:
        get_current_user(request)
    assert exc.value.status_code == 401
    assert exc.value.detail == "Unauthorized"

@pytest.mark.asyncio
async def test_get_current_user_invalid_token():
    with patch('jwt.decode', side_effect=jwt.InvalidTokenError):
        request = MagicMock()
        request.headers.get.return_value = "Bearer invalid_token"
        with pytest.raises(HTTPException) as exc:
            get_current_user(request)
        assert exc.value.status_code == 401
        assert exc.value.detail == "Invalid token"

@pytest.mark.asyncio
async def test_get_current_user_expired_token():
    with patch('jwt.decode', side_effect=jwt.ExpiredSignatureError):
        request = MagicMock()
        request.headers.get.return_value = "Bearer expired_token"
        with pytest.raises(HTTPException) as exc:
            get_current_user(request)
        assert exc.value.status_code == 401
        assert exc.value.detail == "Token expired"

@pytest.mark.asyncio
async def test_verify_admin_success(client, mock_db_connection):
    mock_connection, mock_cursor = mock_db_connection
    mock_cursor.fetchone.return_value = {"role": "admin"}

    with patch('jwt.decode', return_value=MOCK_JWT_PAYLOAD):
        response = client.get("/api/user/verify-admin", headers={"Authorization": "Bearer mock_jwt_token"})
    assert response.status_code == 200
    assert response.json() == {"is_admin": True, "username": "s123456"}
    mock_cursor.execute.assert_called_with("SELECT role FROM users WHERE username = %s", ("s123456",))

@pytest.mark.asyncio
async def test_verify_admin_student(client, mock_db_connection):
    mock_connection, mock_cursor = mock_db_connection
    mock_cursor.fetchone.return_value = {"role": "student"}

    with patch('jwt.decode', return_value=MOCK_JWT_PAYLOAD):
        response = client.get("/api/user/verify-admin", headers={"Authorization": "Bearer mock_jwt_token"})
    assert response.status_code == 200
    assert response.json() == {"is_admin": False, "username": "s123456"}

@pytest.mark.asyncio
async def test_verify_admin_missing_token(client):
    response = client.get("/api/user/verify-admin")
    assert response.status_code == 401
    assert response.json()["detail"] == "Missing token"

@pytest.mark.asyncio
async def test_verify_admin_missing_username(client):
    with patch('jwt.decode', return_value=MOCK_JWT_PAYLOAD_NO_USERNAME):
        response = client.get("/api/user/verify-admin", headers={"Authorization": "Bearer mock_jwt_token"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid token payload"

@pytest.mark.asyncio
async def test_verify_admin_user_not_found(client, mock_db_connection):
    mock_connection, mock_cursor = mock_db_connection
    mock_cursor.fetchone.return_value = None

    with patch('jwt.decode', return_value=MOCK_JWT_PAYLOAD):
        response = client.get("/api/user/verify-admin", headers={"Authorization": "Bearer mock_jwt_token"})
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

@pytest.mark.asyncio
async def test_verify_admin_expired_token(client):
    with patch('jwt.decode', side_effect=jwt.ExpiredSignatureError):
        response = client.get("/api/user/verify-admin", headers={"Authorization": "Bearer expired_token"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Token expired"

@pytest.mark.asyncio
async def test_verify_admin_invalid_token(client):
    with patch('jwt.decode', side_effect=jwt.InvalidTokenError):
        response = client.get("/api/user/verify-admin", headers={"Authorization": "Bearer invalid_token"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid token"

@pytest.mark.asyncio
async def test_get_me_success(client):
    with patch('jwt.decode', return_value=MOCK_JWT_PAYLOAD):
        response = client.get("/api/user/me", headers={"Authorization": "Bearer mock_jwt_token"})
    assert response.status_code == 200
    assert response.json() == {"message": "You are logged in", "user": "s123456"}

@pytest.mark.asyncio
async def test_get_me_missing_token(client):
    response = client.get("/api/user/me")
    assert response.status_code == 401
    assert response.json()["detail"] == "Missing token"

@pytest.mark.asyncio
async def test_get_me_missing_username(client):
    with patch('jwt.decode', return_value=MOCK_JWT_PAYLOAD_NO_USERNAME):
        response = client.get("/api/user/me", headers={"Authorization": "Bearer mock_jwt_token"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid token payload"

@pytest.mark.asyncio
async def test_get_me_expired_token(client):
    with patch('jwt.decode', side_effect=jwt.ExpiredSignatureError):
        response = client.get("/api/user/me", headers={"Authorization": "Bearer expired_token"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Token expired"

@pytest.mark.asyncio
async def test_get_me_invalid_token(client):
    with patch('jwt.decode', side_effect=jwt.InvalidTokenError):
        response = client.get("/api/user/me", headers={"Authorization": "Bearer invalid_token"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid token"

@pytest.mark.asyncio
async def test_db_connection_success():
    with patch('mysql.connector.connect') as mock_connect:
        mock_connect.return_value = MagicMock()
        conn = get_db_connection()
        assert conn is not None
        mock_connect.assert_called_once()

@pytest.mark.asyncio
async def test_db_connection_failure():
    with patch('mysql.connector.connect', side_effect=mysql.connector.Error("Connection failed")):
        with pytest.raises(HTTPException) as exc:
            get_db_connection()
        assert exc.value.status_code == 500
        assert "Database connection failed" in exc.value.detail