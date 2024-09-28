"""
original author: Dominik Cedro
created: 2024-09-28
license: none
description: Models for user objects in DB, they also perform DTO role
"""
from typing import Optional

from pydantic import BaseModel, EmailStr, Field
from bson import ObjectId


class Token(BaseModel):
    access_token: str
    refresh_token: str


class TokenData(BaseModel):
    email: EmailStr | None = None


class User(BaseModel):
    email: EmailStr
    district: str
    full_name: str
    pesel: str
    role: str
    disabled: bool | None = None



class UserCreate(BaseModel):
    email: EmailStr
    district: str
    full_name: str
    pesel: str
    role: str
    hashed_password: str


class UserInDB(User):
    id: Optional[str] = Field(None, alias="_id")
    hashed_password: str

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }


class UserResponse(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    email: EmailStr
    district: str
    full_name: str
    role: str
    disabled: bool | None = None

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

from pydantic import BaseModel, EmailStr

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    pesel: str
    full_name: str
    district: Optional[str] = None
    role: Optional[str] = None


from pydantic import BaseModel

class RefreshRequest(BaseModel):
    refresh_token: str

class TokenRequest(BaseModel):
    access_token: str