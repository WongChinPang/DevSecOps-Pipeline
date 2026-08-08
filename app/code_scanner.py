import re
import os
from typing import NamedTuple

PYTHON_RULES: list[dict] = [
    {"id": "SECRET-01", "risk": "CRITICAL", "desc": "Hardcoded password", "fix": "Use environment variables or a secrets manager for credentials",
     "pattern": r'password\s*=\s*["\'](?![a-zA-Z0-9\s]*\$\{)(?![\s]*$)(?!ChangeMe)(?!template)[^"\']{3,}["\']'},
    {"id": "SECRET-02", "risk": "CRITICAL", "desc": "Hardcoded AWS access key (AKIA...)", "fix": "Use IAM roles instead of static access keys",
     "pattern": r'AKIA[0-9A-Z]{16}'},
    {"id": "SECRET-03", "risk": "HIGH", "desc": "Hardcoded GitHub token", "fix": "Store tokens in ECS environment variables or Secrets Manager",
     "pattern": r'gh[pous]_[0-9a-zA-Z]{36}'},
    {"id": "SECRET-04", "risk": "HIGH", "desc": "Hardcoded API key or token", "fix": "Use environment variables: os.getenv('API_KEY') instead of hardcoding",
     "pattern": r'(?:api[_-]?key|secret[_-]?key|token)\s*=\s*["\'][^"\']{8,}["\']'},
    {"id": "INJECT-01", "risk": "HIGH", "desc": "SQL injection risk — string interpolation in query", "fix": "Use parameterized queries: cursor.execute('SELECT ... WHERE id = %s', (id,))",
     "pattern": r'f["\'].*?\bSELECT\b|f["\'].*?\bINSERT\b|f["\'].*?\bUPDATE\b|f["\'].*?\bDELETE\b|".*SELECT.*\b.*%s.*' },
    {"id": "INJECT-02", "risk": "HIGH", "desc": "Command injection risk — os.system with variables", "fix": "Use subprocess.run() with a list of arguments, not shell=True",
     "pattern": r'os\.system\s*\(\s*f?["\']|subprocess\.(?:call|Popen|run)\s*\([^)]*\bshell\s*=\s*True'},
    {"id": "DESER-01", "risk": "HIGH", "desc": "Unsafe deserialization — pickle.loads() or yaml.load()", "fix": "Use pickle with trusted input only, or yaml.safe_load()",
     "pattern": r'pickle\.loads?\s*\(|yaml\.load\s*\(\s*[^)]*,\s*yaml\.Loader\s*\)|yaml\.load\s*\([^{]'},
    {"id": "INPUT-01", "risk": "MEDIUM", "desc": "Using eval() or exec() on dynamic input", "fix": "Avoid eval/exec entirely; use ast.literal_eval() for safe parsing",
     "pattern": r'\beval\s*\(|\bexec\s*\('},
]

JS_RULES: list[dict] = [
    {"id": "SECRET-JS-01", "risk": "CRITICAL", "desc": "Hardcoded AWS key or GitHub token in JS/TS", "fix": "Use process.env or a secrets manager",
     "pattern": r'AKIA[0-9A-Z]{16}|gh[pous]_[0-9a-zA-Z]{36}'},
    {"id": "SECRET-JS-02", "risk": "HIGH", "desc": "Hardcoded password or API key in JS/TS", "fix": "Use environment variables: process.env.API_KEY",
     "pattern": r'(?:password|apiKey|api_key|secretKey|token)\s*[:=]\s*["\'`][^"\'`\s]{4,}["\'`]'},
    {"id": "SECRET-JS-03", "risk": "MEDIUM", "desc": "localStorage used for sensitive data", "fix": "Store tokens in httpOnly cookies instead of localStorage",
     "pattern": r'localStorage\.(?:setItem|getItem)\s*\(\s*["\']?token'},
    {"id": "INJECT-JS-01", "risk": "HIGH", "desc": "Potential XSS via innerHTML or dangerouslySetInnerHTML", "fix": "Use textContent instead of innerHTML; avoid dangerouslySetInnerHTML",
     "pattern": r'\.innerHTML\s*=|dangerouslySetInnerHTML'},
    {"id": "INJECT-JS-02", "risk": "HIGH", "desc": "SQL injection in JS/TS — string interpolation in query", "fix": "Use parameterized queries or an ORM",
     "pattern": r'`.*?\bSELECT\b.*\$\{|`.*?\bINSERT\b.*\$\{|query\s*\+\s*.*\bSELECT'},
    {"id": "INPUT-JS-01", "risk": "HIGH", "desc": "Using eval() or Function() in JavaScript", "fix": "Avoid eval() and Function() — there's always a safer alternative",
     "pattern": r'\beval\s*\(|new\s+Function\s*\('},
]

JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
PY_EXTENSIONS = {".py", ".pyi"}


def scan_app_code(content: str, filepath: str = "") -> list[dict]:
    findings: list[dict] = []
    ext = os.path.splitext(filepath)[1].lower() if filepath else ".py"

    lines = content.split("\n")

    if ext in PY_EXTENSIONS:
        rules = PYTHON_RULES
    elif ext in JS_EXTENSIONS:
        rules = JS_RULES
    else:
        return []

    for rule in rules:
        for i, line in enumerate(lines, 1):
            m = re.search(rule["pattern"], line, re.IGNORECASE)
            if m:
                findings.append({
                    "rule_id": rule["id"],
                    "risk_level": rule["risk"],
                    "finding": rule["desc"],
                    "remediation": rule["fix"],
                    "file": filepath or "input",
                    "line": i,
                    "code": line.strip()[:120],
                })
                break  # one finding per rule per file

    return findings


def scan_directory(base_dir: str) -> list[dict]:
    all_findings: list[dict] = []
    for root, _, files in os.walk(base_dir):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in PY_EXTENSIONS and ext not in JS_EXTENSIONS:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="replace") as f:
                    content = f.read()
                all_findings.extend(scan_app_code(content, fpath))
            except Exception:
                pass
    return all_findings
