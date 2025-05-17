# Run service
```
uvicorn main:app --host 0.0.0.0 --port 8006
```
# API
/login	跳轉到 NYCU 認證中心登入頁面
/callback	NYCU 登入成功後回來，拿 code 換 access token
用 access token	去 NYCU 的 /api/userinfo 抓使用者資料
簽發 JWT	用自己服務的 Secret 簽一張登入票
回傳給前端	JWT 和使用者資料


# Login 流程
[NYCU OAuth文件](https://id.nycu.edu.tw/docs/)
1. 使用者想登入
    * 使用者點擊「登入」按鈕
    * 前端跳轉到 NYCU OAuth 登入頁 (https://id.nycu.edu.tw/o/authorize)
2. NYCU 要求使用者輸入帳號密碼
    * 使用者輸入 NYCU Portal 帳號密碼
    * NYCU 會詢問「允許這個應用程式取得你的資訊嗎？」
3. NYCU 認證成功，給你一個 Authorization Code
    * NYCU Redirect 回你的後端 /callback（帶著 ?code=xxxxxx）
4. 後端（Login Service）用 Authorization Code 換 Access Token
    * 發一 個 POST 請求到 https://id.nycu.edu.tw/o/token
    * 換回一個 access_token
5. 後端用 Access Token 拿到使用者資訊
    * 送 GET 請求到 https://id.nycu.edu.tw/api/name/
    * 取得使用者姓名, 帳號名稱
6. 後端產生自己的 JWT Token
    * 把使用者資訊（例如 user_id, email, name）放進 JWT
    * 簽名後發給使用者 return token
7. 把這個 JWT Token 給前端
    * 使用者之後帶著這個 Token 跟其他服務互動

# Test
```
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8006/user/verify-admin
```

# 討論
1. login完回傳學號、email給前端、我們自己的jwt給前端
2. 每個service都自己認證?
NGINX+LUA
```
location / {
    access_by_lua_block {
        local jwt = require "resty.jwt"
        local uri = ngx.var.uri

        -- 定義不需驗證的路徑白名單
        local whitelist = {
            ["/user/login"] = true,
            ["/user/callback"] = true
        }

        -- 如果是白名單路徑，就放行
        if whitelist[uri] then
            return
        end

        -- 否則進行 JWT 驗證
        local auth_header = ngx.var.http_Authorization
        if not auth_header then
            ngx.status = 401
            ngx.say("Missing Authorization header")
            return
        end

        local _, _, token = string.find(auth_header, "Bearer%s+(.+)")
        if not token then
            ngx.status = 401
            ngx.say("Invalid Authorization format")
            return
        end

        local jwt_obj = jwt:verify("your_jwt_secret", token)
        if not jwt_obj.verified then
            ngx.status = 401
            ngx.say("Invalid token")
            return
        end
    }

    proxy_pass http://127.0.0.1:8006;  # 根據實際路徑選擇轉發
}

```