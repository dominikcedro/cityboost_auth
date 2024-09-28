
########### new one

"""
original author: Dominik Cedro
created: 2024-09-28
license: GSB 3.0
description: Main script for security setup, endpoint operation and app config
"""
# from dotenv import load_dotenv
import os
from enum import Enum
from typing import Optional
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
from models import User, UserCreate, UserInDB, Token, TokenData, UserOut
from security import get_password_hash, verify_password, oauth2_scheme, SECRET_KEY, ALGORITHM, \
    ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token

load_dotenv()
uri = os.getenv("MONGO_URI")
# DB setup

# Create a new client and connect to the server
client = MongoClient(uri)
db = client.hackyeahdb
collection_users = db["users"]
collection_counters = db["counters"]
app = FastAPI()

### counters setup

def add_user_to_db(db, user: UserCreate):
    hashed_password = get_password_hash(user.password)
    user_dict = user.dict()
    user_dict["hashed_password"] = hashed_password
    del user_dict["password"]
    result = db.insert_one(user_dict)
    if result.inserted_id:
        ic("user collection posted")  #### log

        return UserInDB(**user_dict)
    else:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User registration failed")


def get_user(collection, username: str):
    user_dict = collection.find_one({"username": username})
    if user_dict:
        user_dict["_id"] = str(user_dict["_id"])
        return UserInDB(**user_dict)
    return None


def authenticate_user(collection, username: str, password: str):
    user = get_user(collection, username)
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
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(collection_users, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> Token:
    user = authenticate_user(collection_users, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.post("/register", response_model=Token)
async def register_new_user(user: UserCreate):
    if get_user(collection_users, user.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )
    new_user = add_user_to_db(collection_users, user)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": new_user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/", response_model=UserInDB)
async def read_users_me(current_user: UserInDB = Depends(get_current_active_user)):
    return current_user

@app.get("/users/me/items/")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.username}]


def get_user_by_id(collection, user_id: str):
    from bson import ObjectId
    user_dict = collection.find_one({"_id": ObjectId(user_id)})
    if user_dict:
        user_dict["_id"] = str(user_dict["_id"])
        return UserInDB(**user_dict)
    return None


@app.get("/users/{user_id}", response_model=UserOut)
async def read_user_by_id(user_id: str):
    user = get_user_by_id(collection_users, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


