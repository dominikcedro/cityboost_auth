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

