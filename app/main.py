from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os

from scan_service import run_scan, get_scans

app = FastAPI(title="DevSecOps Pipeline Demo")


class ScanRequest(BaseModel):
    iac_content: str
    dockerfile_content: str


@app.get("/api/health")
def health():
    return {"status": "healthy"}


@app.post("/api/scan")
def scan(req: ScanRequest):
    result = run_scan(req.iac_content, req.dockerfile_content)
    return result


@app.get("/api/scans")
def list_scans():
    return get_scans()


STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    file_path = os.path.join(STATIC_DIR, full_path)
    if full_path and os.path.isfile(file_path):
        return FileResponse(file_path)
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))
