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
    password: str


class UserInDB(User):
    id: Optional[str] = Field(None, alias="_id")
    hashed_password: str

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }


class UserOut(BaseModel):
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

