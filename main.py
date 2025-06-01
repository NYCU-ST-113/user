from fastapi import FastAPI
from routers import user

app = FastAPI(title="User Service")
app.include_router(user.router, prefix="/api/user", tags=["User"])
for route in app.routes:
    print(route.path)