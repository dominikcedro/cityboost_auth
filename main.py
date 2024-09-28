"""
original author: Dominik Cedro
created: 2024-09-28
license: none
description: Main script for users endpoints
"""
# from dotenv import load_dotenv
import os
from enum import Enum
from typing import Optional

import bson
from icecream import ic
from datetime import datetime, timedelta, timezone
import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel
from pydantic import BaseModel, EmailStr
from pymongo.mongo_client import MongoClient
from dotenv import load_dotenv
# module imports
from models import User, UserCreate, UserInDB, Token, TokenData, LoginRequest, RegisterRequest, UserResponse, \
    RefreshRequest, TokenRequest
from security import get_password_hash, verify_password, oauth2_scheme, SECRET_KEY, ALGORITHM, \
    ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token, REFRESH_TOKEN_EXPIRE_MINUTES, create_refresh_token
from fastapi import Body

load_dotenv()

# DB setup
uri = os.getenv("MONGO_URI")
client = MongoClient(uri)
db = client.hackyeahdb
collection_users = db["users"]
collection_counters = db["counters"]

# API setup
app = FastAPI()


from fastapi import Request, HTTPException, status

async def validate_user_create(request: Request):
    body = await request.json()
    email = body.get("email")
    if not email or "@" not in email or "." not in email.split("@")[1]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email address. An email address must have an @-sign and a period after the @-sign."
        )
    return body

def add_user_to_db(collection, user: UserCreate):
    user_dict = user.dict()
    result = collection.insert_one(user_dict)
    if result.inserted_id:
        user_dict["_id"] = str(result.inserted_id)
        return UserInDB(**user_dict)
    else:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User registration failed")


def get_user(collection, email: str):
    user_dict = collection.find_one({"email": email})
    if user_dict:
        user_dict["_id"] = str(user_dict["_id"])
        return UserInDB(**user_dict)
    return None


def authenticate_user(collection, email: EmailStr, password: str):
    user = get_user(collection, email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")
        ic("Extracted user_id from token:", user_id)  # Add logging here
        if user_id is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    user = get_user_by_id(collection_users, user_id)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

from bson import ObjectId


def get_user_by_id(collection, user_id: str):
    ic("user id here is")
    ic(user_id)
    try:
        user_dict = collection.find_one({"_id": ObjectId(user_id)})
    except bson.errors.InvalidId:
        ic("Invalid user ID format")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user ID format")
    if user_dict:
        user_dict["_id"] = str(user_dict["_id"])
        return UserResponse(**user_dict)
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

@app.post("/login", response_model=Token)
async def login_for_access_token(
    login_request: LoginRequest = Body(...),
) -> Token:
    user = authenticate_user(collection_users, login_request.email, login_request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "user_id": user.id}, expires_delta=access_token_expires)

    refresh_token_expires = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    refresh_token = create_refresh_token(data={"user_id": user.id}, expires_delta=refresh_token_expires)
    return Token(access_token=access_token, refresh_token=refresh_token)

from fastapi import Request

@app.post("/register", response_model=Token)
async def register_new_user(register_request: RegisterRequest):
    if get_user(collection_users, register_request.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    if get_user(collection_users, register_request.pesel):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pesel already registered",
        )
    hashed_password = get_password_hash(register_request.password)
    new_user = UserCreate(
        email=register_request.email,
        hashed_password=hashed_password,
        pesel=register_request.pesel,
        full_name=register_request.full_name,
        district=register_request.district,
        role="USER"
    )
    added_user = add_user_to_db(collection_users, new_user)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": added_user.email, "user_id": added_user.id},
        expires_delta=access_token_expires)

    refresh_token_expires = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    refresh_token = create_refresh_token(data={"user_id": added_user.id}, expires_delta=refresh_token_expires)
    return Token(access_token=access_token, refresh_token=refresh_token)

@app.get("/users/{user_id}", response_model=UserResponse)
async def read_user_by_id(user_id):
    user = get_user_by_id(collection_users, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

from fastapi import Body, HTTPException, status
from jwt.exceptions import InvalidTokenError
from datetime import timedelta

@app.post("/refresh", response_model=Token)
async def refresh_access_token(refresh_request: RefreshRequest = Body(...)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        token = refresh_request.refresh_token
        if not token:
            ic("not token")
            raise credentials_exception
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")
        if user_id is None:
            ic("user_id is None")
            raise credentials_exception
    except InvalidTokenError:
        ic("invalid token")

        raise credentials_exception

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": payload.get("sub"), "user_id": user_id}, expires_delta=access_token_expires)

    return Token(access_token=access_token, refresh_token=token)


def extract_user_id_from_token(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")
        ic("Extracted user_id from token:", user_id)
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user_id
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.post("/get_me")
async def extract_user_id(token_request: TokenRequest = Body(...)):
    token = token_request.access_token
    user_id = extract_user_id_from_token(token)
    user = get_user_by_id(collection_users, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
