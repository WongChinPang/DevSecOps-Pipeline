import json
from fastapi import FastAPI, Header, HTTPException, Depends, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os

import boto3
from scan_service import run_scan, get_scans
from code_scanner import scan_app_code
from auth_service import authenticate, validate_token, init_db

init_db()

app = FastAPI(title="DevSecOps Pipeline Demo")

s3 = boto3.client("s3", region_name="us-east-1")
REPORT_BUCKET = "devsecops-reports-087572104425"


class LoginRequest(BaseModel):
    username: str
    password: str


class ScanRequest(BaseModel):
    iac_content: str
    dockerfile_content: str
    app_code: str = ""


def require_auth(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authentication required")
    token = authorization.replace("Bearer ", "")
    if not validate_token(token):
        raise HTTPException(401, "Invalid or expired token")
    return token


@app.post("/api/login")
def login(req: LoginRequest):
    token = authenticate(req.username, req.password)
    if token:
        return {"success": True, "token": token}
    raise HTTPException(401, "Invalid credentials")


@app.get("/api/health")
def health():
    return {"status": "healthy"}


@app.post("/api/scan")
def scan(req: ScanRequest, _token: str = Depends(require_auth)):
    result = run_scan(req.iac_content, req.dockerfile_content, req.app_code)
    if req.app_code.strip():
        result["code_findings"] = scan_app_code(req.app_code)
    return result


@app.get("/api/scans")
def list_scans(_token: str = Depends(require_auth)):
    return get_scans()


@app.get("/api/audit-log")
def audit_log(
    _token: str = Depends(require_auth),
    risk: str = Query(None, description="Filter by risk: CRITICAL, HIGH, MEDIUM, LOW"),
):
    reports: list[dict] = []
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=REPORT_BUCKET, Prefix="reports/"):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if not key.endswith(".json"):
                    continue
                try:
                    resp = s3.get_object(Bucket=REPORT_BUCKET, Key=key)
                    data = json.loads(resp["Body"].read().decode())
                    summary = data.get("summary", {})
                    entry = {
                        "report": key,
                        "timestamp": obj["LastModified"].isoformat(),
                        "total_checks": summary.get("total_checks", 0),
                        "passed": summary.get("passed", 0),
                        "failed": summary.get("failed", 0),
                        "overall_risk": summary.get("overall_risk", "UNKNOWN"),
                    }
                    if risk and entry["overall_risk"] != risk.upper():
                        continue
                    reports.append(entry)
                except Exception:
                    continue
    except Exception:
        pass

    reports.sort(key=lambda r: r["timestamp"], reverse=True)
    return reports


@app.get("/api/audit-log/{report_key:path}")
def audit_report_detail(report_key: str, _token: str = Depends(require_auth)):
    try:
        resp = s3.get_object(Bucket=REPORT_BUCKET, Key=f"reports/{report_key}")
        data = json.loads(resp["Body"].read().decode())
        return data
    except Exception:
        raise HTTPException(404, "Report not found")


STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    file_path = os.path.join(STATIC_DIR, full_path)
    if full_path and os.path.isfile(file_path):
        return FileResponse(file_path)
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))
