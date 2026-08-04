import json
import sys
import uuid
from datetime import datetime, timezone

import boto3

SCANNER_LAMBDA = "devsecops-security-scanner"
LLM_LAMBDA = "llm-auditor"
REGION = "us-east-1"
S3_BUCKET = "devsecops-reports-087572104425"

client = boto3.client("lambda", region_name=REGION)
s3 = boto3.client("s3", region_name=REGION)

scans: list[dict] = []


def _log(msg: str) -> None:
    sys.stderr.write(f"[scan_service] {msg}\n")
    sys.stderr.flush()


def _invoke_scanner(iac_content: str, dockerfile_content: str) -> tuple[bool, str, list[dict]]:
    payload = json.dumps({"iac_content": iac_content, "dockerfile_content": dockerfile_content})
    response = client.invoke(FunctionName=SCANNER_LAMBDA, Payload=payload)
    result = json.loads(response["Payload"].read().decode())
    has_error = "FunctionError" in response and response["FunctionError"] == "Unhandled"
    error_msg = result.get("errorMessage", "") if has_error else ""

    summary: list[dict] = []
    if has_error and error_msg:
        try:
            parts = error_msg.split("发现 ")
            if len(parts) > 1:
                nums = parts[1].split("，")[0]
                critical = int(nums.split(" ")[0]) if "严重" in nums else 0
                high = 0
                for segment in parts[1].split("，"):
                    if "高危" in segment:
                        high = int(segment.strip().split(" ")[0])
                        break
                if critical > 0:
                    summary.append({"rule": "CRITICAL", "count": critical})
                if high > 0:
                    summary.append({"rule": "HIGH", "count": high})
        except (ValueError, IndexError):
            pass

    return has_error, error_msg, summary


def _invoke_llm_auditor(iac_content: str) -> list[dict]:
    scan_id = str(uuid.uuid4())[:8]
    s3_key = f"templates/web-scan-{scan_id}.yaml"
    _log(f"uploading IaC to s3://{S3_BUCKET}/{s3_key}")

    try:
        s3.put_object(Bucket=S3_BUCKET, Key=s3_key, Body=iac_content.encode("utf-8"), ContentType="text/yaml")
    except Exception as e:
        _log(f"S3 upload failed: {type(e).__name__}: {e}")
        return []

    llm_payload = json.dumps({"s3_bucket": S3_BUCKET, "s3_key": s3_key})

    try:
        _log("invoking llm-auditor")
        response = client.invoke(FunctionName=LLM_LAMBDA, Payload=llm_payload)
        result = json.loads(response["Payload"].read().decode())
        _log(f"llm-auditor response keys: {list(result.keys())}")

        if "statusCode" not in result or result["statusCode"] != 200:
            _log(f"llm-auditor non-200 status")
            return []

        body = json.loads(result["body"])
        report_location = body.get("report_location", "")
        if not report_location:
            _log("no report_location in llm-auditor response")
            return []

        report_bucket = report_location.replace("s3://", "").split("/", 1)[0]
        report_key = report_location.replace(f"s3://{report_bucket}/", "")
        _log(f"reading report s3://{report_bucket}/{report_key}")

        report_obj = s3.get_object(Bucket=report_bucket, Key=report_key)
        report_data = json.loads(report_obj["Body"].read().decode())
        all_details = report_data.get("details", [])
        _log(f"got {len(all_details)} detail items")

        return [
            {
                "rule_id": d["rule_id"],
                "status": d["status"],
                "risk_level": d["risk_level"],
                "finding": d["finding"],
                "remediation": d["remediation"],
            }
            for d in all_details
        ]
    except Exception as e:
        _log(f"error: {type(e).__name__}: {e}")

    return []


def run_scan(iac_content: str, dockerfile_content: str) -> dict:
    _log(f"scan start — iac={len(iac_content)} chars, docker={len(dockerfile_content)} chars")
    has_error, error_msg, summary = _invoke_scanner(iac_content, dockerfile_content)
    _log(f"scanner result: has_error={has_error}")

    details: list[dict] = []
    if has_error:
        details = _invoke_llm_auditor(iac_content)

    scan_id = str(uuid.uuid4())[:8]
    record = {
        "id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "blocked" if has_error else "passed",
        "findings": summary,
        "details": details,
        "iac_snippet": iac_content[:200],
        "dockerfile_snippet": dockerfile_content[:200],
    }
    scans.insert(0, record)
    if len(scans) > 50:
        scans.pop()

    _log(f"scan done — details={len(details)}")
    return record


def get_scans() -> list[dict]:
    return scans
