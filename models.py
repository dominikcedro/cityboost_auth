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
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    district: str
    full_name: str
    pesel: str
    role: str
    disabled: bool | None = None



class UserCreate(BaseModel):
    username: str
    district: str
    full_name: str
    pesel: str
    role: str
    email: EmailStr
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
    username: str
    district: str
    full_name: str
    role: str
    disabled: bool | None = None

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }

