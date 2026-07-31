import json
import uuid
from datetime import datetime, timezone

import boto3

LAMBDA_FUNCTION = "devsecops-security-scanner"
REGION = "us-east-1"

client = boto3.client("lambda", region_name=REGION)

scans: list[dict] = []


def run_scan(iac_content: str, dockerfile_content: str) -> dict:
    payload = json.dumps({
        "iac_content": iac_content,
        "dockerfile_content": dockerfile_content,
    })

    response = client.invoke(
        FunctionName=LAMBDA_FUNCTION,
        Payload=payload,
    )

    result = json.loads(response["Payload"].read().decode())

    has_error = "FunctionError" in response and response["FunctionError"] == "Unhandled"
    error_msg = result.get("errorMessage", "") if has_error else ""

    findings: list[dict] = []
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
                    findings.append({"rule": "CRITICAL", "count": critical})
                if high > 0:
                    findings.append({"rule": "HIGH", "count": high})
        except (ValueError, IndexError):
            pass

    scan_id = str(uuid.uuid4())[:8]
    record = {
        "id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "blocked" if has_error else "passed",
        "findings": findings,
        "iac_snippet": iac_content[:200],
        "dockerfile_snippet": dockerfile_content[:200],
    }
    scans.insert(0, record)
    if len(scans) > 50:
        scans.pop()

    return record


def get_scans() -> list[dict]:
    return scans
