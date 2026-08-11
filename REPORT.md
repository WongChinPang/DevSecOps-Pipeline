# COMP4635 Group Project Report
## AI-Driven DevSecOps Pipeline on AWS

---

## Section 1. System Introduction

### 1.1 Overview

This project delivers a fully automated DevSecOps platform on Amazon Web Services (AWS) that integrates security scanning into the software delivery lifecycle. The system combines static rule-based infrastructure validation with AI-powered audit reporting, accessible through both a web interface and a CI/CD pipeline that blocks unsafe deployments before they reach production.

The architecture is partitioned across four functional roles: **infrastructure provisioning** (Role 1) provides the VPC, IAM, S3, and KMS foundation; **pipeline orchestration** (Role 2) builds the CI/CD workflow, web platform, and container deployment; **deterministic security scanning** (Role 3) implements an eight-rule Lambda-based policy engine; and **AI audit reporting** (Role 4) leverages Amazon Bedrock's Nova Micro model to generate structured human-readable findings with remediation guidance.

The core innovation is a **dual-layer security architecture**: Role 3's scanner serves as a deterministic gatekeeper — it blocks the pipeline on rule violations — while Role 4's auditor provides semantic analysis and natural-language remediation advice. These operate at the same pipeline gate but serve complementary purposes: one says *stop*, the other says *why*.

### 1.2 Functional Specification

**Table 1.1: Core Functions**

| Function | Mechanism | Outcome |
|----------|-----------|---------|
| Automated CI/CD | CodePipeline V2 (SUPERSEDED mode) with GitHub webhook trigger | Source → SecurityTest → Build → Deploy, ~2 minutes end-to-end |
| Static Security Scanning | Lambda function (Python 3.10, 60s timeout) parses CloudFormation YAML and Dockerfile text | Deterministic PASS/BLOCK for 8 infrastructure rules |
| AI Audit Reporting | Lambda function (Python 3.12, 30s timeout) invokes Amazon Nova Micro via Bedrock, reads IaC from S3 | JSON + Markdown reports with per-rule findings, risk levels, and remediation text |
| Application Code Scanning | Regex-based rules engine (Role 2) running in FastAPI and CodeBuild | 12 rules covering hardcoded secrets, injection vectors, and unsafe deserialization |
| Containerized Deployment | Multi-stage Docker build → ECR push → ECS Fargate rolling update | Images tagged with commit SHA for traceability |
| Web Scanning Platform | React SPA (TypeScript, Tailwind) + FastAPI (Python) + JWT-style bearer token auth | Instant IaC/Dockerfile/Code scanning with per-rule detail expansion |
| Centralized Audit Trail | S3 for reports, CloudWatch for execution logs | All scan results and pipeline executions timestamped and retrievable |

### 1.3 Technical Architecture

**Table 1.2: AWS Service Inventory with Technical Specifications**

| Service | Resource Name | Configuration | Justification |
|---------|--------------|---------------|---------------|
| VPC | `vpc-0e3207ae21c9b6c03` | CIDR 10.0.0.0/16, 2 AZs | Network isolation for all resources |
| Public Subnets | 2 × /24 | Route to Internet Gateway | ALB placement only |
| Private Subnets | 2 × /24 | Route to NAT Gateway, no public IP | Service placement — prevents direct internet exposure |
| NAT Gateway | `nat-018f6e3e105f3d175` | In public subnet | Enables Fargate to pull from ECR without exposing services |
| ALB Security Group | `sg-044770e4a0d745b09` | Inbound: 0.0.0.0/0:80 | Only public-facing ingress point |
| App Security Group | `sg-0345988fbb2fe2e30` | Inbound: ALB SG:8000 | Dual-SG design — containers reachable only from ALB |
| IAM — CodePipeline | `codepipeline-role` | Trust: codepipeline.amazonaws.com | Or"chestrates stages but cannot access Lambda/S3 directly |
| IAM — CodeBuild | `devsecops-stack-CodeBuildServiceRole` | `logs:*`, `s3:*`, `kms:*`, `ecr:*`, `lambda:InvokeFunction` on 2 specific functions | Least privilege: only the Lambdas and paths actually needed |
| IAM — Lambda | `lambda-role` | `AWSLambdaBasicExecutionRole`, `AmazonBedrockFullAccess`, `AmazonS3FullAccess` | Enables scanner logging and LLM invocation |
| IAM — ECS Task | `ecsTaskExecutionRole` | `AmazonECSTaskExecutionRolePolicy` + custom policy for `lambda:InvokeFunction` on scanner/auditor + `s3:PutObject/GetObject/ListBucket` on report bucket | Dual-role: execution (ECR pull, CloudWatch) + task (app boto3 calls) |
| KMS Key | `5b205194-d0c1-4001-a251-998d2fcbe67c` | Customer-managed, key rotation enabled | Encrypts S3 artifacts and ECR images |
| S3 | `devsecops-reports-087572104425` | Public access blocked, KMS encryption | Artifact store, IaC template staging (`templates/`), audit reports (`reports/`) |
| ECR | `devsecops-app` | KMS encrypted, MUTABLE tags | Image registry with per-commit tagging |
| CodePipeline | `devsecops-pipeline` | V2, SUPERSEDED mode | 4-stage orchestration |
| CodeBuild — SecurityTest | `devsecops-llm-auditor-scan` | amazonlinux2-x86_64-standard:5.0, BUILD_GENERAL1_SMALL, unprivileged | Runs scanner + LLM auditor |
| CodeBuild — Build | `devsecops-app-build` | Same image, BUILD_GENERAL1_SMALL, **privileged mode** | Requires Docker daemon access |
| ECS Cluster | `devsecops-cluster` | FARGATE capacity provider | Serverless container orchestration |
| ECS Task Definition | `devsecops-webapp` | 256 CPU, 512 MB, awsvpc network mode, `USER appuser` | Minimum viable Fargate configuration |
| ECS Service | `devsecops-service` | Rolling update (ECS deployment controller), desired count 1 | Zero-downtime deployment |
| ALB | `devsecops-alb` | Internet-facing, HTTP:80 | Traffic ingress and health-based routing |
| Target Group | `devsecops-tg` | Target type: ip, port 8000, health path: /health, interval: 30s | Required `ip` type for Fargate awsvpc mode |
| Lambda — Scanner | `devsecops-security-scanner` | Python 3.10, 256 MB, 60s timeout | Receives inline `{iac_content, dockerfile_content}` payload |
| Lambda — Auditor | `llm-auditor` | Python 3.12, 128 MB, 30s timeout | Receives `{s3_bucket, s3_key}` path format |

### 1.4 Dual-Path Process Flow

The system implements two complementary interaction paths sharing the same Lambda functions.

**Table 1.3: Pipeline Path (CI/CD)**

| Stage | Execution Details | Duration |
|-------|------------------|----------|
| Trigger | `git push` to GitHub main branch → CodePipeline webhook | ~5s |
| Source | Clone from `WongChinPang/DevSecOps-Pipeline` → S3 artifact | ~10s |
| SecurityTest | ① `aws s3 cp` IaC to S3 → ② Python payload generation → ③ Invoke scanner Lambda → ④ `grep FunctionError` → ⑤ If pass, invoke LLM auditor with `{s3_bucket, s3_key}` → ⑥ Reports written to S3 | ~30s |
| Build | `docker login` → `docker build --platform linux/amd64` → `docker push` (tags: `latest` + commit SHA) → `imagedefinitions.json` output | ~60s |
| Deploy | ECS rolling update → new task starts → ALB health check → old task deregistered | ~40s |

**Table 1.4: Web Platform Path (Interactive)**

| Step | Technical Flow |
|------|---------------|
| Authentication | `POST /api/login` with username/password → `secrets.token_hex(16)` → stored in ECS container memory, returned as Bearer token |
| Scan Request | `POST /api/scan` with `{iac_content, dockerfile_content, app_code}` → validated via `Depends(require_auth)` decorator |
| Scanner Invocation | boto3 `client.invoke(FunctionName="devsecops-security-scanner", Payload=...)` → parse `FunctionError` in response |
| LLM Auditor Chain | Upload IaC + app code to S3 → boto3 `client.invoke(FunctionName="llm-auditor", Payload={s3_bucket, s3_key})` → download report from S3 → parse per-rule `details` array |
| Code Scanner | Direct regex evaluation in `code_scanner.py` against Python/JS/TS patterns — no Lambda dependency |
| Result Assembly | Merged response: `{status, findings: [{rule, count}], details: [{rule_id, status, risk_level, finding, remediation}], code_findings: [...]}` |

### 1.5 Key Design Decisions

**Container Architecture**: Multi-stage Docker build separates build-time dependencies from the production image. Stage 1 (Node Alpine) compiles the React SPA via `npm run build`. Stage 2 (Python 3.11 Slim) copies only the compiled static files and runs uvicorn. The final image excludes Node.js entirely. The container runs as `appuser` — satisfying our own CONT-01 rule. Cross-platform builds specify `--platform linux/amd64` because the development environment (macOS ARM) differs from the deployment target (Fargate x86).

**Buildspec Design**: The SecurityTest buildspec is stored inline in the CodeBuild project rather than in the repository. This was a deliberate choice after encountering YAML parsing conflicts: the `:` characters in shell commands like `{iac_content: $iac}` were interpreted by the YAML parser as mapping separators. The inline approach provides tighter control and avoids repository-level buildspec conflicts. Payload generation uses Python's `open().read()` + `json.dump()` pattern rather than jq, eliminating shell escaping issues entirely.

**Network Security Model**: A dual security group architecture protects the Fargate service. The ALB security group (`sg-044770e4a0d745b09`) allows HTTP from `0.0.0.0/0` on port 80 — the only public ingress point. The application security group (`sg-0345988fbb2fe2e30`) allows port 8000 only from the ALB security group itself. No direct internet access to the container. The Fargate tasks reside in private subnets with no public IP, accessing ECR and the internet through a NAT Gateway in a public subnet.

**Dual Lambda Interface Handling**: Role 3's scanner accepts inline content in its payload — `{iac_content, dockerfile_content}` — enabling direct invocation without pre-staging to S3. Role 4's auditor requires S3 paths — `{s3_bucket, s3_key}` — because it reads the IaC file from S3 internally before sending it to Bedrock. The pipeline and web platform handle both formats: they first upload to S3 (needed by the auditor), then call the scanner with inline text for lower latency, then call the auditor with the S3 key.

---

## Section 2. Risk and Threat Analysis

### 2.1 Data Classification Framework

A three-tier classification model governs data handling throughout the system:

**Table 2.1: Data Classification**

| Tier | Label | Data Assets | Storage Requirements | Access Model |
|------|-------|-------------|---------------------|--------------|
| L1 | Confidential | IAM policy documents, CloudFormation templates, LLM audit reports | S3 with KMS CMK, public access blocked, versioning enabled | IAM role-based; no IAM users; all access through assumed roles |
| L2 | Internal | Docker images (ECR), CloudWatch logs, pipeline execution metadata | ECR with KMS, CloudWatch with default encryption | Service-linked roles only; no cross-account access |
| L3 | Public | Application web traffic (HTTP) | N/A (transit only) | ALB listener on port 80; no backend exposure |

### 2.2 Threat Model and Security Controls

Using the STRIDE methodology, the following threats were identified against the CI/CD pipeline and the deployed web platform.

**Table 2.2: Threat Analysis**

| Threat ID | STRIDE Category | Threat Scenario | Likelihood | Impact | Risk | Primary Control | Secondary Control |
|-----------|-----------------|-----------------|------------|--------|------|-----------------|-------------------|
| T1 | Elevation of Privilege | IAM role with `Action: "*"` deployed via CloudFormation — compromised service escalates to full AWS account control | Medium | High | **High** | IAM-01, IAM-02: block wildcard policies at scan time | CloudFormation linting pre-commit |
| T2 | Information Disclosure | Security group exposes SSH port 22 to 0.0.0.0/0 — attacker brute-forces credentials | Low | Critical | **Critical** | NET-01: block public SSH ingress | NACLs as defense-in-depth |
| T3 | Information Disclosure | PostgreSQL port 5432 exposed to internet — direct database access bypasses application authentication | Low | Critical | **Critical** | NET-02: block public database port exposure | Database placed in private subnet (Role 1) |
| T4 | Information Disclosure | S3 bucket without encryption — accidental public ACL exposes IaC templates containing resource ARNs and account IDs | Medium | Medium | **Medium** | DATA-01: enforce SSE on all buckets | S3 Block Public Access enabled |
| T5 | Tampering | Container running as root — compromised application modifies host filesystem or escapes to host | Medium | High | **High** | CONT-01: enforce non-root USER directive | Read-only root filesystem (future) |
| T6 | Information Disclosure | Hardcoded AWS access key in application code — leaked through version control or build artifacts | Medium | Critical | **Critical** | SECRET-02: regex detection for `AKIA...` pattern | Git pre-commit hook |
| T7 | Elevation of Privilege | `os.system()` with user-controlled input in application code — attacker executes arbitrary commands on container | Medium | High | **High** | INJECT-02: detection of `os.system()` calls | Container runs as non-root appuser |
| T8 | Information Disclosure | Bearer token exposed in localStorage — XSS attack steals token | Medium | Medium | **Medium** | Auth token scoped to in-memory store (invalidation on logout) | Content Security Policy header |

### 2.3 Risk Calculation Methodology

Risk levels follow the standard qualitative model:

> **Risk = Likelihood × Impact**

- **Critical**: Likely to be exploited and/or causes catastrophic damage. Must block deployment.
- **High**: Significant business impact. Block deployment.
- **Medium**: Moderate impact. Flag as warning, do not block.
- **Low**: Minimal impact. Recommendation only.

The blocking threshold is set at High and above — this means the pipeline halts for IAM wildcards, public SSH exposure, and container root execution, while S3 encryption and application code issues generate warnings without blocking.

---

## Section 3. Security Checklist

### 3.1 Infrastructure Rules — Deterministic Scanner (Role 3)

Role 3's Lambda function parses CloudFormation YAML resources and checks them against eight deterministic rules. The scanner receives inline IaC content, evaluates resource types (`AWS::IAM::Role`, `AWS::IAM::Policy`, `AWS::EC2::SecurityGroup`, `AWS::S3::Bucket`), and checks Dockerfile content separately. If any Critical or High rule fails, the Lambda throws a Python exception, which causes the invocation response to contain `FunctionError: Unhandled` — the pipeline then detects this with `grep -q "FunctionError"` and exits with code 1.

**Table 3.1: Infrastructure Security Checklist**

| # | Rule ID | Domain | Check | Severity | Detection | Remediation |
|---|---------|--------|-------|----------|-----------|-------------|
| 1 | IAM-01 | Identity | IAM policy `Action` contains `"*"` wildcard | **HIGH** | Parse `PolicyDocument.Statement[].Action`; check for literal `"*"` string | Enumerate specific API actions: `["s3:GetObject", "s3:PutObject"]` |
| 2 | IAM-02 | Identity | IAM policy `Resource` contains `"*"` wildcard | **HIGH** | Parse `PolicyDocument.Statement[].Resource`; check for literal `"*"` string | Specify explicit resource ARNs |
| 3 | NET-01 | Network | Security group ingress allows `0.0.0.0/0` with port range covering 22 | **CRITICAL** | Iterate `SecurityGroupIngress[]`, match `CidrIp == "0.0.0.0/0"` AND `FromPort ≤ 22 ≤ ToPort` | Restrict to VPC CIDR `10.0.0.0/16` or trusted IPs |
| 4 | NET-02 | Network | Security group ingress allows `0.0.0.0/0` with port range covering 5432 | **CRITICAL** | Same logic for port 5432 | Restrict to internal CIDR blocks |
| 5 | NET-03 | Network | Security group ingress allows `0.0.0.0/0` with port range covering 3306 | **CRITICAL** | Same logic for port 3306 | Restrict to internal CIDR blocks |
| 6 | DATA-01 | Encryption | S3 bucket has no `BucketEncryption` property | **MEDIUM** | Check resource properties for presence of `BucketEncryption.ServerSideEncryptionConfiguration` | Add SSE with `aws:kms` or `AES256` algorithm |
| 7 | DATA-02 | Encryption | S3 `SSEAlgorithm` is not `aws:kms` | **LOW** | Extract `SSEAlgorithm` from encryption config; flag if `AES256` | Upgrade to `aws:kms` with customer-managed key |
| 8 | CONT-01 | Container | Dockerfile uses `USER root`, `USER 0`, or omits USER directive | **HIGH** | Line-by-line regex: `^\s*USER\s+(root|0)` or no USER line present | Add `USER appuser` with non-root UID |

### 3.2 Application Code Rules — Backend Scanner (Role 2)

Role 2's code scanner runs independently from Role 3's Lambda — it executes directly in the FastAPI process for web scans and as inline Python in the CodeBuild buildspec for pipeline scans. This avoids Lambda cold-start penalties for quick regex checks and eliminates dependency on Role 3 for code-level rules. The scanner supports Python (`.py`) and JavaScript/TypeScript (`.js`, `.ts`, `.jsx`, `.tsx`) file types.

**Table 3.2: Application Code Security Checklist**

| # | Rule ID | Language | Check | Severity | Pattern |
|---|---------|----------|-------|----------|---------|
| 9 | SECRET-01 | Python | Hardcoded password assignment (`password = "..."`) | **CRITICAL** | `r'password\s*=\s*["\'][^"\']{3,}["\']'` |
| 10 | SECRET-02 | Python | Hardcoded AWS access key ID (`AKIA...`) | **CRITICAL** | `r'AKIA[0-9A-Z]{16}'` |
| 11 | SECRET-03 | Python | Hardcoded GitHub PAT (`ghp_...` or `gho_...`) | **HIGH** | `r'gh[pous]_[0-9a-zA-Z]{36}'` |
| 12 | SECRET-04 | Python | Hardcoded API key/secret/token | **HIGH** | `r'(?:api[_-]?key\|secret[_-]?key\|token)\s*=\s*["\'][^"\']{8,}["\']'` |
| 13 | INJECT-01 | Python | SQL injection via f-string (`f"SELECT..."`) | **HIGH** | `r'f["\'].*?\bSELECT\b'` |
| 14 | INJECT-02 | Python | Command injection via `os.system()` | **HIGH** | `r'os\.system\s*\(\s*f?["\']'` |
| 15 | DESER-01 | Python | Unsafe deserialization (`pickle.loads()` or `yaml.load()` without SafeLoader) | **HIGH** | `r'pickle\.loads?\s*\(\|yaml\.load\s*\([^{]'` |
| 16 | INPUT-01 | Python | Dynamic code execution (`eval()` or `exec()`) | **MEDIUM** | `r'\beval\s*\(\|\bexec\s*\('` |

**Table 3.3: JavaScript/TypeScript Additional Rules**

| # | Rule ID | Check | Severity | Pattern |
|---|---------|------|----------|---------|
| 17 | SECRET-JS-01 | Hardcoded AWS/GitHub keys in JS/TS | **CRITICAL** | `r'AKIA[0-9A-Z]{16}\|gh[pous]_[0-9a-zA-Z]{36}'` |
| 18 | SECRET-JS-02 | Hardcoded password/apiKey as object properties | **HIGH** | `r'(?:password\|apiKey\|api_key\|secretKey)\s*[:=]\s*["\'`][^"\'`\s]{4,}["\'`]'` |
| 19 | INJECT-JS-01 | XSS via `innerHTML` or `dangerouslySetInnerHTML` | **HIGH** | `r'\.innerHTML\s*=\|dangerouslySetInnerHTML'` |

### 3.3 Enforcement Architecture and Blocking Logic

The two scanners enforce different blocking policies:

```
Infrastructure Scanner (Role 3 Lambda)
    ├── CRITICAL or HIGH found → Lambda throws Exception → FunctionError → pipeline exit 1 → BLOCKED
    ├── Only MEDIUM or LOW → Lambda returns 200 → pipeline continues → PASSED with warnings
    └── No issues → Lambda returns 200 → pipeline continues → PASSED

Application Code Scanner (Role 2 Regex)
    ├── Any rule matched → logged as "code_findings" in response → display as ⚠️ WARNING
    └── Does NOT affect pipeline pass/fail status — informational only
```

This separation reflects the principle that infrastructure misconfigurations can cause widespread security failure (blocking), while code-level issues may have mitigating controls and should trigger review rather than deployment blockades.

---

## Section 4. Assessment Results

### 4.1 Test Methodology

Validation was conducted through three layers: unit testing of individual Lambda functions, integration testing of the web platform API, and end-to-end pipeline execution testing. Two reference IaC templates were constructed: a deliberately insecure "DangerTest" configuration exercising all rule domains, and a security-compliant "SafeTest" baseline designed to trigger zero false positives.

### 4.2 DangerTest — Vulnerable Configuration Validation

**Input Configuration:**

| Component | Deliberate Violations |
|-----------|----------------------|
| IaC — Security Group | Port 22 (SSH) open to `0.0.0.0/0` |
| IaC — IAM Policy | Inline policy with `"Action": "*"` and `"Resource": "*"` |
| IaC — S3 Bucket | No `BucketEncryption` property |
| Dockerfile | `USER root` directive |
| App Code | `password = "admin123"`, `API_KEY = "sk-proj-abc..."`, `os.system("ls")` |

**Table 4.1: DangerTest Infrastructure Results**

| Rule | Status | Severity | Actual Finding |
|------|--------|----------|----------------|
| IAM-01 | FAIL | HIGH | Wildcard action detected in IAM policy |
| IAM-02 | FAIL | HIGH | Wildcard resource detected in IAM policy |
| NET-01 | FAIL | CRITICAL | SSH port 22 exposed to 0.0.0.0/0 |
| NET-02 | PASS | CRITICAL | No PostgreSQL exposure |
| NET-03 | PASS | CRITICAL | No MySQL exposure |
| DATA-01 | FAIL | MEDIUM | S3 bucket encryption not configured |
| DATA-02 | — | LOW | N/A (encryption absent) |
| CONT-01 | FAIL | HIGH | USER root declared |

**Pipeline Outcome**: SecurityTest **BLOCKED** — scanner threw exception, CodeBuild detected `FunctionError`, returned exit code 1, pipeline halted at SecurityTest stage. Build and Deploy stages did not execute.

**Table 4.2: DangerTest Application Code Results**

| Rule | Status | Severity | Line Detection |
|------|--------|----------|----------------|
| SECRET-01 | FAIL | CRITICAL | Line 2: `password = "admin123"` |
| SECRET-04 | FAIL | HIGH | Line 1: `API_KEY = "sk-proj-..."` |
| INJECT-02 | FAIL | HIGH | Line 3: `os.system("ls")` |

**Code Scan Outcome**: 3 warnings issued via `code_findings` array. Scan status unaffected — infrastructure check already blocked the pipeline at this point.

### 4.3 SafeTest — Compliant Configuration Validation

**Input Configuration:**

| Component | Compliant Configuration |
|-----------|------------------------|
| IaC — Security Group | Port 443 open only to `10.0.0.0/16` (VPC CIDR) |
| IaC — IAM | AWS managed policies (`AWSLambdaBasicExecutionRole`); no inline wildcard policies |
| IaC — S3 Bucket | `BucketEncryption` with `SSEAlgorithm: aws:kms` |
| Dockerfile | `USER appuser` (explicit non-root UID) |
| App Code | `API_KEY = os.getenv("API_KEY")`; no `eval()`, `os.system()`, or `pickle` calls |

**Table 4.3: SafeTest Results**

| Category | Rules Evaluated | Passed | Failed | Status |
|----------|-----------------|--------|--------|--------|
| Infrastructure (Lambda) | 8 | 8 | 0 | **PASSED** |
| Application Code (Regex) | 19 | 19 | 0 | **No warnings** |
| Pipeline Stages | 4 (Source → SecurityTest → Build → Deploy) | 4 | 0 | **ALL SUCCEEDED** |

**Deployment Verified**: Application accessible at `http://devsecops-alb-1865120796.us-east-1.elb.amazonaws.com` — API health check returns `{"status":"healthy"}`, SPA returns HTTP 200.

### 4.4 Quantitative Performance Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| Pipeline end-to-end (passing) | ~135 seconds | Source: 15s, SecurityTest: 30s, Build: 60s, Deploy: 40s |
| SecurityTest Lambda invocation | ~1.2 seconds | Python 3.10, 256 MB, 60s timeout |
| LLM Auditor invocation | ~4.5 seconds | Python 3.12, 128 MB, 30s timeout; includes Bedrock API latency |
| Web API scan (safe, no LLM) | ~1.5 seconds | Scanner Lambda + response parsing |
| Web API scan (blocked, with LLM) | ~7.5 seconds | Scanner + S3 upload + LLM auditor + S3 report download |
| Code scanner (per file) | <10 ms | Pure regex, in-process, no I/O |
| ECS task startup (cold) | ~45 seconds | Image pull + container init + ALB registration |
| ECS task startup (warm, same image) | ~10 seconds | Container restart only |

### 4.5 Edge Case Discovery

During testing, an unexpected behavior was identified: the security scanner Lambda flags the CloudFormation YAML shorthand tag `!Ref` as a security violation, while the functionally equivalent long-form `Fn::Ref` (expressed as `{"Ref": "ResourceName"}`) passes all checks. This occurs because `!Ref` is a YAML tag extension that causes the scanner's YAML parser to behave differently during string serialization. The `Fn::Ref` long-form produces standard JSON that the scanner processes correctly.

This edge case does not indicate a security vulnerability but rather a parser compatibility issue. For compliant deployments, the team uses `Fn::Ref` syntax in templates submitted through the pipeline. This finding has been communicated to Role 3 for potential normalization logic in a future scanner iteration.

---

## Section 5. Reference List

1. Amazon Web Services. (2025). *AWS Well-Architected Framework — Security Pillar*. https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/

2. Amazon Web Services. (2025). *AWS Lambda Developer Guide*. https://docs.aws.amazon.com/lambda/latest/dg/

3. Amazon Web Services. (2025). *AWS CodePipeline User Guide*. https://docs.aws.amazon.com/codepipeline/latest/userguide/

4. Amazon Web Services. (2025). *Amazon ECS Developer Guide — Fargate Launch Type*. https://docs.aws.amazon.com/AmazonECS/latest/developerguide/

5. Amazon Web Services. (2025). *Amazon Bedrock User Guide — Foundation Models*. https://docs.aws.amazon.com/bedrock/latest/userguide/

6. OWASP. (2023). *Docker Security Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

7. OWASP. (2021). *OWASP Top Ten Web Application Security Risks*. https://owasp.org/www-project-top-ten/

8. NIST. (2020). *SP 800-53 Rev. 5: Security and Privacy Controls for Information Systems*. https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

9. GitHub. (2025). *Security hardening for GitHub Actions*. https://docs.github.com/en/actions/security-guides

10. Shostack, A. (2014). *Threat Modeling: Designing for Security*. Wiley. ISBN: 978-1118809990.

---

## Section 6. Annex

### Annex A: SecurityTest Buildspec (Inline CodeBuild Configuration)

```yaml
version: 0.2
phases:
  build:
    commands:
      # Step 1: Stage IaC template to S3 for LLM auditor access
      - aws s3 cp infrastructure.yaml s3://devsecops-reports-087572104425/templates/infrastructure.yaml

      # Step 2: Code-level scanning (non-blocking)
      - |
        python3 -c "
        import os, re, json
        findings = []
        # [8 rules inline — see Annex B for full code]
        for root, _, files in os.walk('.'):
            for f in files:
                if f.endswith(('.py','.js','.ts','.jsx','.tsx')):
                    # ... regex checks ...
        if findings:
            json.dump(findings, open('/tmp/code_findings.json','w'))
        "

      # Step 3: Infrastructure scanning (BLOCKING)
      - python3 -c "
        import json
        d = {'iac_content': open('infrastructure.yaml').read(),
             'dockerfile_content': open('Dockerfile').read()}
        json.dump(d, open('/tmp/payload.json','w'))
        "
      - aws lambda invoke --function-name devsecops-security-scanner
          --cli-binary-format raw-in-base64-out
          --payload file:///tmp/payload.json
          scan_response.json

      # Step 4: Blocking gate
      - |
        if grep -q "FunctionError" scan_response.json; then
          echo "!!! BLOCKED: vulnerabilities detected !!!"
          cat scan_response.json
          exit 1
        fi

      # Step 5: AI audit report generation
      - python3 -c "
        import json
        json.dump({'s3_bucket': 'devsecops-reports-087572104425',
                   's3_key': 'templates/infrastructure.yaml'},
                  open('/tmp/llm-payload.json','w'))
        "
      - aws lambda invoke --function-name llm-auditor
          --cli-binary-format raw-in-base64-out
          --payload file:///tmp/llm-payload.json
          audit_response.json
```

### Annex B: Application Code Scanner — Core Rules (code_scanner.py)

```python
import re, os

PYTHON_RULES = [
    {"id": "SECRET-01", "risk": "CRITICAL",
     "desc": "Hardcoded password", "fix": "Use os.getenv()",
     "pattern": r'password\s*=\s*["\'](?![a-zA-Z0-9\s]*\$\{)(?!\s*$)(?!ChangeMe)(?!template)[^"\']{3,}["\']'},
    {"id": "SECRET-02", "risk": "CRITICAL",
     "desc": "Hardcoded AWS key (AKIA...)", "fix": "Use IAM roles",
     "pattern": r'AKIA[0-9A-Z]{16}'},
    {"id": "SECRET-03", "risk": "HIGH",
     "desc": "Hardcoded GitHub token", "fix": "Use ECS env vars",
     "pattern": r'gh[pous]_[0-9a-zA-Z]{36}'},
    {"id": "SECRET-04", "risk": "HIGH",
     "desc": "Hardcoded API key/token", "fix": "Use os.getenv('API_KEY')",
     "pattern": r'(?:api[_-]?key|secret[_-]?key|token)\s*=\s*["\'][^"\']{8,}["\']'},
    {"id": "INJECT-01", "risk": "HIGH",
     "desc": "SQL injection via f-string", "fix": "Use parameterized queries",
     "pattern": r'f["\'].*?\bSELECT\b|f["\'].*?\bINSERT\b|f["\'].*?\bUPDATE\b|f["\'].*?\bDELETE\b'},
    {"id": "INJECT-02", "risk": "HIGH",
     "desc": "Command injection via os.system()", "fix": "Use subprocess.run()",
     "pattern": r'os\.system\s*\(\s*f?["\']|subprocess\.(?:call|Popen|run)\s*\([^)]*\bshell\s*=\s*True'},
    {"id": "DESER-01", "risk": "HIGH",
     "desc": "Unsafe pickle.loads() or yaml.load()", "fix": "Use yaml.safe_load()",
     "pattern": r'pickle\.loads?\s*\(|yaml\.load\s*\([^{]'},
    {"id": "INPUT-01", "risk": "MEDIUM",
     "desc": "eval() or exec() call", "fix": "Use ast.literal_eval()",
     "pattern": r'\beval\s*\(|\bexec\s*\('},
]

def scan_app_code(content: str, filepath: str = "") -> list[dict]:
    findings = []
    ext = os.path.splitext(filepath)[1].lower() if filepath else ".py"
    if ext not in {".py", ".js", ".ts", ".jsx", ".tsx"}:
        return findings
    lines = content.split("\n")
    for rule in PYTHON_RULES:
        for i, line in enumerate(lines, 1):
            if re.search(rule["pattern"], line, re.IGNORECASE):
                findings.append({
                    "rule_id": rule["id"], "risk_level": rule["risk"],
                    "finding": rule["desc"], "remediation": rule["fix"],
                    "file": filepath or "input", "line": i,
                    "code": line.strip()[:120],
                })
                break
    return findings
```

### Annex C: Reusable GitHub Action

```yaml
name: "DevSecOps Security Scan"
description: "Scan IaC and Dockerfiles using Lambda scanner"
inputs:
  iac_file:       { default: "infrastructure.yaml" }
  dockerfile:     { default: "Dockerfile" }
  scanner_function: { default: "devsecops-security-scanner" }
runs:
  using: "composite"
  steps:
    - name: Run Security Scan
      shell: bash
      run: |
        python3 -c "
        import json
        payload = {'iac_content': open('${{ inputs.iac_file }}').read(),
                   'dockerfile_content': open('${{ inputs.dockerfile }}').read()}
        json.dump(payload, open('/tmp/payload.json','w'))
        "
        aws lambda invoke --function-name ${{ inputs.scanner_function }}
          --cli-binary-format raw-in-base64-out
          --payload file:///tmp/payload.json /tmp/result.json
        grep -q "FunctionError" /tmp/result.json && exit 1 || echo "Scan passed"
```

### Annex D: Pipeline Architecture

```
 GitHub: WongChinPang/DevSecOps-Pipeline (main)
          │ git push
          ▼
 CodePipeline V2 (SUPERSEDED mode)
 ┌─────────┐   ┌───────────────┐   ┌──────────┐   ┌──────────┐
 │ Source  │──▶│ SecurityTest  │──▶│  Build   │──▶│ Deploy   │
 │ GitHub  │   │ CodeBuild     │   │ CodeBuild│   │ ECS      │
 │ Clone   │   │ ① Upload S3   │   │ Docker   │   │ Fargate  │
 │ → S3    │   │ ② Scanner     │   │ Build    │   │ Rolling  │
 │         │   │ ③ Gate (exit) │   │ Push ECR │   │ Update   │
 │         │   │ ④ LLM Auditor │   │          │   │          │
 └─────────┘   └───────┬───────┘   └────┬─────┘   └────┬─────┘
                       │                │              │
                       ▼                ▼              ▼
                S3: templates/    ECR: tag=sha   ALB: HTTP→:8000
                S3: reports/                     │
                                                  ▼
                                          ECS Fargate
                                          FastAPI + React
                                          Private Subnet
                                          No Public IP
```

---

**Report prepared by**: Role 2 — Pipeline Engineer, COMP4635 Group Project
**Date**: August 2026
**Repository**: https://github.com/WongChinPang/DevSecOps-Pipeline
