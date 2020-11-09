from pydantic import BaseModel
from time import time

from blake3 import blake3

from fastapi import FastAPI, HTTPException

from totp import generate_secret, check_code, time_window, generate_code
from users import users


class User(BaseModel):
    user_id: str
    totp_secret: str
    code: str
    misses_since_success: int = 0


class TotpCheckResult(BaseModel):
    success: bool
    misses_since_success: int


app = FastAPI()


@app.get("/v1/")
def read_root():
    return {"description": "A Simple FastAPI TOTP Server v1"}


@app.post("/v1/users/create/{user_id}", response_model=User, status_code=201)
def create_user(user_id: str):
    """Try to create new user; replies with new user object along with a secret, or appropriate error"""
    if user_id in users:
        raise HTTPException(status_code=409, detail="User '{}' already exists".format(user_id))
    
    secret = generate_secret()
    code = generate_code(secret)
    user = User(user_id=user_id, totp_secret=secret, code=code)
    users[user_id] = user
    return user


@app.put("/v1/users/check_totp/{user_id}/{code}", response_model=TotpCheckResult)
def check_totp(user_id: str, code: str):
    """Checks if the code of a user is correct for the current moment.
    Arguments:
    user_id -- user to check against
    code -- 4-digit string TOTP code.

    Returns True if the code is valid for the current or previous time window
    """
    if not users.get(user_id):
        raise HTTPException(status_code=404, detail="User '{}' not found".format(user_id))

    check_response = TotpCheckResult(success=False, misses_since_success=1000)

    try:
        # success if code is valid for current or immediately preceding time window
        check_response.success = check_code(users[user_id].totp_secret, code) or \
                                check_code(users[user_id].totp_secret, code, int(time()) - time_window)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not check_response.success:
        users[user_id].misses_since_success += 1
    else:
        users[user_id].misses_since_success = 0

    check_response.misses_since_success = users[user_id].misses_since_success

    return check_response
