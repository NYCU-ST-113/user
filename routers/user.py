from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse, JSONResponse
from models import UserRole, User
import requests
import jwt
import datetime
import os
from typing import Dict
import mysql.connector
import json

router = APIRouter()

def get_db_connection():
    try:
        return mysql.connector.connect(
            host="data-db-1",
            port=3306,
            user="user",
            password="password",
            database="appdb"
        )
    except mysql.connector.Error as e:
        raise HTTPException(status_code=500, detail=f"Database connection failed: {str(e)}")


# OAuth settings
CLIENT_ID = "ZWB85FyZfKJJVEcNIHUfeJ1v3oalgaN7FjeCpb2E"
CLIENT_SECRET = "vxfJf9eaw5cuzExfZsUhfDolzCck6sgcedE01neQRB86AzK1r0ZB0ZMVrAiVQkYhyPuou7HDmYyy47WqpOJq0cMWLdhu8P7EdoDhrI7atp3m2puXte67m9RTKnHRWaYE"
REDIRECT_URI = "http://140.113.207.240/user/callback"

# NYCU OAuth API
NYCU_AUTHORIZE_URL = "https://id.nycu.edu.tw/o/authorize/"
NYCU_TOKEN_URL = "https://id.nycu.edu.tw/o/token/"
NYCU_PROFILE_URL = "https://id.nycu.edu.tw/api/profile/"

# The JWT secret in my services
JWT_SECRET = "super_secret_for_my_app"
JWT_ALGORITHM = "HS256"


@router.get("/")
async def test_user_service():
    return {"message": "User service is working"}

# 1. Login
@router.get("/login")
async def login():
    nycu_login_url = (
        f"{NYCU_AUTHORIZE_URL}"
        f"?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope=profile"
    )
    return RedirectResponse(url=nycu_login_url)

# 2. Callback after NYCU certification (using code to access_token, and then provide our own JWT)
@router.get("/callback")
async def callback(request: Request):
    code = request.query_params.get("code")
    if not code:
        print(request)
        raise HTTPException(status_code=400, detail="Missing code from NYCU")

    # 3. Use code to get access token
    token_response = requests.post(
        NYCU_TOKEN_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
        }
    )

    if token_response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to get access token")

    token_data = token_response.json()
    access_token = token_data.get("access_token")

    if not access_token:
        raise HTTPException(status_code=400, detail="Access token missing")

    # 4. Use access_token to get NYCU user information
    userinfo_response = requests.get(
        NYCU_PROFILE_URL,
        headers={"Authorization": f"Bearer {access_token}"}
    )
    
 
    if userinfo_response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to get profile info")

    userinfo = userinfo_response.json()
    username = userinfo.get("username")
    email = userinfo.get("email")

    # Check admin
    conn = get_db_connection()
    # role = UserRole.admin if username in admin_users else UserRole.student

    # 5. Generate our own JWT
    try:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            existing_user = cursor.fetchone()

            if not existing_user:
                # Add account
                default_role = UserRole.student.value
                cursor.execute(
                    "INSERT INTO users (username, email, role) VALUES (%s, %s, %s)",
                    (username, email, default_role)
                )
                conn.commit()
                role = default_role
            else:
                role = existing_user["role"]
                if existing_user["email"] != email:
                    cursor.execute(
                        "UPDATE users SET email = %s WHERE username = %s",
                        (email, username)
                    )
                    conn.commit()
    finally:
        conn.close()

    jwt_payload = {
        "username": username,
        "email": email,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    print(jwt_payload)
    jwt_token = jwt.encode(jwt_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    # Return JWT to frontend
    return {
        "message": "Login success",
        "jwt_token": jwt_token,
        "user_info": userinfo
    }
    # frontend_url = "https://172.18.0.6/callback"  
    # params = {
    #     "token": jwt_token,
    #     "username": userinfo.get("username")
    # }
    # url_with_params = f"{frontend_url}?{urllib.parse.urlencode(params)}"

    # return RedirectResponse(url=url_with_params)

@router.get("/logout")
async def logout():
    response = JSONResponse(content={"message": "Logged out"})
    # response.delete_cookie(key="access_token")
    return response

def get_current_user(request: Request) -> dict:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")



@router.get("/verify-admin")
async def verify_admin(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("username")
        if not username:
            raise HTTPException(status_code=400, detail="Invalid token payload")

        conn = get_db_connection()
        try:
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT role FROM users WHERE username = %s", (username,))
                user = cursor.fetchone()
                if not user:
                    raise HTTPException(status_code=404, detail="User not found")

                is_admin = user["role"] == "admin"
                return {"is_admin": is_admin, "username": username}
        finally:
            conn.close()

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# The following function are add for test

@router.get("/me")
async def get_me(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("username")
        if not username:
            raise HTTPException(status_code=400, detail="Invalid token payload")
        return {"message": "You are logged in", "user": username}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    


