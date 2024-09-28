# """
# original author: Dominik Cedro
# created: 2024-09-28
# license: none
# description: holds crud operations for db
# """
#
# import jwt
# from fastapi import Depends
# from jwt import InvalidTokenError
# from starlette import status
# from icecream import ic
# from main import collection_users
# from models import TokenData, User, UserInDB, UserCreate
# from security import SECRET_KEY, ALGORITHM, oauth2_scheme, verify_password, get_password_hash
# from fastapi import Depends, HTTPException, status
#
#
# def add_user_to_db(db, user: UserCreate):
#     hashed_password = get_password_hash(user.password)
#     user_dict = user.dict()
#     user_dict["hashed_password"] = hashed_password
#     del user_dict["password"]
#     result = db.insert_one(user_dict)
#     if result.inserted_id:
#         ic("user collection posted")
#
#         return UserInDB(**user_dict)
#     else:
#         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User registration failed")
#
#
# def get_user(collection, username: str):
#     user_dict = collection.find_one({"username": username})
#     if user_dict:
#         user_dict["_id"] = str(user_dict["_id"])
#         return UserInDB(**user_dict)
#     return None
#
#
# def authenticate_user(collection, username: str, password: str):
#     user = get_user(collection, username)
#     if not user:
#         return False
#     if not verify_password(password, user.hashed_password):
#         return False
#     return user
#
#
# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             raise credentials_exception
#         token_data = TokenData(username=username)
#     except InvalidTokenError:
#         raise credentials_exception
#     user = get_user(collection_users, username=token_data.username)
#     if user is None:
#         raise credentials_exception
#     return user
#
#
# async def get_current_active_user(current_user: User = Depends(get_current_user)):
#     if current_user.disabled:
#         raise HTTPException(status_code=400, detail="Inactive user")
#     return current_user
#
#
# def get_user_by_id(collection, user_id: str):
#     from bson import ObjectId
#     user_dict = collection.find_one({"_id": ObjectId(user_id)})
#     if user_dict:
#         user_dict["_id"] = str(user_dict["_id"])
#         return UserInDB(**user_dict)
#     return None