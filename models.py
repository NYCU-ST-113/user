from enum import Enum
from pydantic import BaseModel, EmailStr

class UserRole(str, Enum):
    student = "student"
    admin = "admin"

class User(BaseModel):
    username: str
    email: EmailStr
    role: UserRole
