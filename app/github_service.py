import base64
import os
import requests

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_OWNER = "WongChinPang"
GITHUB_REPO = "DevSecOps-Pipeline"
GITHUB_BRANCH = "main"
API_BASE = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}"
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json",
}


def _get_file_sha(filepath: str) -> str | None:
    url = f"{API_BASE}/contents/{filepath}?ref={GITHUB_BRANCH}"
    resp = requests.get(url, headers=HEADERS)
    if resp.status_code == 200:
        return resp.json().get("sha")
    return None


def commit_file(filepath: str, content: str, message: str) -> bool:
    if not GITHUB_TOKEN:
        return False

    sha = _get_file_sha(filepath)
    encoded = base64.b64encode(content.encode("utf-8")).decode("utf-8")

    body = {
        "message": message,
        "content": encoded,
        "branch": GITHUB_BRANCH,
    }
    if sha:
        body["sha"] = sha

    url = f"{API_BASE}/contents/{filepath}"
    resp = requests.put(url, headers=HEADERS, json=body)
    return resp.status_code in (200, 201)


def trigger_scan(iac_content: str, dockerfile_content: str) -> dict:
    if not GITHUB_TOKEN:
        return {"success": False, "error": "GITHUB_TOKEN not configured"}

    results = []

    ok = commit_file(
        "infrastructure.yaml",
        iac_content,
        "scan: update IaC template from web platform",
    )
    results.append({"file": "infrastructure.yaml", "committed": ok})

    ok = commit_file(
        "Dockerfile",
        dockerfile_content,
        "scan: update Dockerfile from web platform",
    )
    results.append({"file": "Dockerfile", "committed": ok})

    all_ok = all(r["committed"] for r in results)
    return {
        "success": all_ok,
        "results": results,
        "pipeline_url": f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/actions" if all_ok else None,
    }
