from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from server.auth import (
    register_user,
    login_user,
    get_auth_salt,
    require_auth,
)
from server.storage import store_blob, load_blob

app = FastAPI()

class RegisterReq(BaseModel):
    username: str
    salt: str
    verifier: str

class LoginReq(BaseModel):
    username: str
    verifier: str

class VaultReq(BaseModel):
    blob: dict

@app.get("/auth_salt/{username}")
def auth_salt(username: str):
    username = username.lower()
    salt = get_auth_salt(username)
    if not salt:
        raise HTTPException(404, "User not found")
    return {"salt": salt}

@app.post("/register")
def register(req: RegisterReq):
    try:
        register_user(req.username.lower(), req.salt, req.verifier)
        return {"ok": True}
    except ValueError:
        raise HTTPException(400, "User exists")

@app.post("/login")
def login(req: LoginReq):
    try:
        token = login_user(req.username.lower(), req.verifier)
        return {"token": token}
    except ValueError:
        raise HTTPException(401, "Invalid credentials")

@app.get("/vault")
def get_vault(authorization: str = Header()):
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")
    return {"blob": load_blob(user)}

@app.post("/vault")
def put_vault(req: VaultReq, authorization: str = Header()):
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")
    store_blob(user, req.blob)
    return {"ok": True}
