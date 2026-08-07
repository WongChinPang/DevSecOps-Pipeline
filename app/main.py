import secrets
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os

from scan_service import run_scan, get_scans

app = FastAPI(title="DevSecOps Pipeline Demo")

tokens: set[str] = set()


class LoginRequest(BaseModel):
    username: str
    password: str


class ScanRequest(BaseModel):
    iac_content: str
    dockerfile_content: str


def require_auth(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(401, "Authentication required")
    token = authorization.replace("Bearer ", "")
    if token not in tokens:
        raise HTTPException(401, "Invalid authentication token")
    return token


@app.post("/api/login")
def login(req: LoginRequest):
    if req.username == "alan" and req.password == "123456789":
        token = secrets.token_hex(16)
        tokens.add(token)
        return {"success": True, "token": token}
    raise HTTPException(401, "Invalid credentials")


@app.get("/api/health")
def health():
    return {"status": "healthy"}


@app.post("/api/scan")
def scan(req: ScanRequest, _token: str = Depends(require_auth)):
    return run_scan(req.iac_content, req.dockerfile_content)


@app.get("/api/scans")
def list_scans(_token: str = Depends(require_auth)):
    return get_scans()


STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    file_path = os.path.join(STATIC_DIR, full_path)
    if full_path and os.path.isfile(file_path):
        return FileResponse(file_path)
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))
