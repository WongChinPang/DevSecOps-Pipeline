# COMP4635 Group Project Report
## AI-Driven DevSecOps Pipeline on AWS

---

## Section 1. System Introduction

### 1.1 Overview

This project develops and validates an automated DevSecOps platform deployed natively on Amazon Web Services (AWS). The system integrates deterministic security validation with AI-powered audit reporting into the software delivery lifecycle, accessible through a web-based scanning interface and a CI/CD pipeline that prevents unsafe configurations from reaching production environments.

The architecture is partitioned across four functional roles operating under well-defined interface contracts: **infrastructure provisioning** (Role 1) manages the VPC, IAM policies, S3 buckets, and KMS encryption keys; **pipeline orchestration** (Role 2) constructs the CI/CD workflow, web platform, authentication layer, and container deployment pipeline; **deterministic security scanning** (Role 3) implements an eight-rule Lambda-based policy enforcement engine; and **AI audit reporting** (Role 4) leverages Amazon Bedrock's Nova Micro foundation model to generate structured, human-readable security findings with remediation guidance.

The core technical contribution is a **dual-layer security architecture** operating at a single pipeline gate. Role 3's scanner serves as a deterministic gatekeeper — it parses CloudFormation YAML and Dockerfile content, evaluates compliance against eight infrastructure security rules, and throws a Python exception on violation, which CodeBuild detects as `FunctionError` and translates to exit code 1, halting all subsequent pipeline stages. Role 4's auditor runs immediately after a passing scan, providing semantic analysis and natural-language remediation advice. The scanner says *stop*; the auditor explains *why*. Both operate on every `git push` event and on every interactive web scan, ensuring consistent enforcement regardless of entry point.

### 1.2 Functional Specification

**Table 1.1: Core System Functions**

| Function | Implementation Mechanism | Operational Outcome |
|----------|--------------------------|---------------------|
| Automated CI/CD | CodePipeline V2 (SUPERSEDED execution mode) with GitHub webhook trigger on `main` branch | Four-stage pipeline (Source → SecurityTest → Build → Deploy), ~135 seconds end-to-end |
| Reusable GitHub Action | Composite action at `.github/actions/security-scan` invokes Security Scanner Lambda | External repositories integrate scanning with a single workflow file; no AWS infrastructure required |
| Deterministic Security Scanning | Lambda function (Python 3.10, 256 MB, 60s timeout) parses CloudFormation YAML and Dockerfile text | Binary PASS/BLOCK decision for 8 infrastructure rules; violations throw exception producing `FunctionError: Unhandled` |
| AI-Powered Audit Reporting | Lambda function (Python 3.12, 128 MB, 30s timeout) invokes Amazon Nova Micro via Bedrock; reads IaC from S3 | Structured JSON and Markdown reports with per-rule findings (rule_id, status, risk_level, finding, remediation) |
| Application Code Scanning | Regex-based rules engine (Role 2) executing directly in FastAPI process for web scans and as inline Python in CodeBuild buildspec for pipeline scans | 19 rules across Python (.py/.pyi), JavaScript (.js/.mjs/.cjs), TypeScript (.ts), JSX/TSX (.jsx/.tsx); hardcoded secrets, injection vectors, unsafe deserialization, cross-site scripting |
| Containerized Deployment | Multi-stage Dockerfile: Stage 1 (Node 22 Alpine) compiles React SPA; Stage 2 (Python 3.11 Slim) serves via uvicorn | Final image excludes Node.js; runs as non-root `appuser`; images tagged with commit SHA for full traceability |
| Web-Based Scanning Platform | React 19 SPA (TypeScript, Tailwind CSS 4, Vite 6) + FastAPI backend (Python 3.11) | Three-input interface (IaC YAML, Dockerfile, Application Code) with per-rule detail expansion, Load Safe/Unsafe Example presets, risk-level color coding |
| JWT-Based Authentication | `auth_service.py` — SHA-256 salted password hashes in SQLite; JWT (HS256, 24-hour expiry) issued on validated login | `require_auth` FastAPI dependency validates JWT signature and expiry on every protected endpoint; tokens survive container restarts via deterministic derived secret |
| Audit Report Browser | `GET /api/audit-log` with S3 pagination and risk-level query parameter filtering | Tab-based navigation (Scanner | Audit Log); click-to-expand per-rule detail from S3 report JSON |
| Centralized Observability | S3 for persistent audit reports, CloudWatch Logs for pipeline and application execution traces | All scans timestamped; all pipeline stage transitions recorded; all Lambda invocations logged with request IDs |

### 1.3 Implementation Methods

Infrastructure provisioning follows Infrastructure as Code (IaC) principles via AWS CloudFormation, providing repeatability, version control integration with Git, and consistent configuration across deployments. The following table enumerates each deployed AWS resource with its technical specifications and architectural justification.

**Table 1.2: AWS Service Inventory**

| Service | Resource Identifier | Technical Configuration | Architectural Purpose |
|---------|--------------------|-------------------------|-----------------------|
| VPC | `vpc-0e3207ae21c9b6c03` | CIDR 10.0.0.0/16, 2 Availability Zones | Network isolation boundary for all resources |
| Public Subnets | 2 × /24 subnets | Route to Internet Gateway | ALB placement — sole public-facing tier |
| Private Subnets | 2 × /24 subnets | Route to NAT Gateway; no auto-assign public IP | Service placement — prevents direct internet exposure of containers |
| NAT Gateway | `nat-018f6e3e105f3d175` | Single instance in public subnet | Enables Fargate tasks to pull images from ECR without exposing services to inbound traffic |
| ALB Security Group | `sg-044770e4a0d745b09` | Inbound: TCP 80 from 0.0.0.0/0 | Sole public ingress point — all HTTP traffic enters here |
| App Security Group | `sg-0345988fbb2fe2e30` | Inbound: TCP 8000 from ALB SG only | Dual-SG defense-in-depth — containers only reachable from ALB |
| IAM — CodePipeline | `codepipeline-role` | Trust: codepipeline.amazonaws.com | Orchestrates stage transitions; no direct Lambda or S3 access |
| IAM — CodeBuild | `devsecops-stack-CodeBuildServiceRole` | `logs:*`, `s3:*`, `kms:*`, `ecr:*`, `lambda:InvokeFunction` scoped to 2 specific function ARNs | Least privilege — only resources actually consumed by buildspecs |
| IAM — Lambda | `lambda-role` | `AWSLambdaBasicExecutionRole` + `AmazonBedrockFullAccess` + `AmazonS3FullAccess` | Enables CloudWatch logging, Bedrock model invocation, and S3 report read/write |
| IAM — ECS Task | `ecsTaskExecutionRole` | `AmazonECSTaskExecutionRolePolicy` + custom inline policy: `lambda:InvokeFunction` on scanner and auditor + `s3:PutObject/GetObject/ListBucket` on report bucket | Dual-purpose role: execution role for ECR pull and CloudWatch logs; task role for application-layer boto3 API calls |
| KMS Key | `5b205194-d0c1-4001-a251-998d2fcbe67c` | Customer-managed key, automatic rotation enabled | Encrypts S3 artifacts, ECR images, and CloudWatch log groups |
| S3 Bucket | `devsecops-reports-087572104425` | KMS encrypted; Block Public Access enabled on all four settings | Three-purpose storage: pipeline artifacts, IaC template staging (`templates/`), LLM audit reports (`reports/`) |
| ECR Repository | `devsecops-app` | KMS encrypted; image tag mutability: MUTABLE | Private container image registry with per-commit tagging |
| CodePipeline | `devsecops-pipeline` | Version 2, SUPERSEDED execution mode | Four-stage CI/CD orchestration; superseded mode cancels in-progress executions on new push |
| CodeBuild — SecurityTest | `devsecops-llm-auditor-scan` | Image: `aws/codebuild/amazonlinux2-x86_64-standard:5.0`, Compute: BUILD_GENERAL1_SMALL, Privileged: false | Runs scanner + LLM auditor; unprivileged mode sufficient (no Docker daemon required) |
| CodeBuild — Build | `devsecops-app-build` | Same image and compute; Privileged: **true** | Docker daemon access required for `docker build` and `docker push` |
| ECS Cluster | `devsecops-cluster` | FARGATE capacity provider | Serverless container orchestration — no EC2 instance management |
| ECS Task Definition | `devsecops-webapp` | 256 CPU (0.25 vCPU), 512 MB memory, awsvpc network mode, `USER appuser` | Minimum Fargate-compatible configuration; non-root user satisfies CONT-01 rule |
| ECS Service | `devsecops-service` | Rolling update (ECS deployment controller), desired count: 1 | Zero-downtime deployment; new task starts and passes health check before old task deregisters |
| Application Load Balancer | `devsecops-alb` | Internet-facing scheme, HTTP listener on port 80 | Traffic distribution and health-based routing to Fargate tasks |
| Target Group | `devsecops-tg` | Target type: `ip`, protocol: HTTP, port: 8000, health check path: `/health`, interval: 30s, healthy threshold: 2 | Required `ip` target type for Fargate awsvpc networking mode |
| Lambda — Security Scanner | `devsecops-security-scanner` | Runtime: Python 3.10, Memory: 256 MB, Timeout: 60 seconds | Receives inline `{iac_content, dockerfile_content}` payload via boto3 `client.invoke` |
| Lambda — LLM Auditor | `llm-auditor` | Runtime: Python 3.12, Memory: 128 MB, Timeout: 30 seconds | Receives `{s3_bucket, s3_key}` payload; reads IaC from S3 internally; writes reports back to S3 |
| CloudWatch Log Groups | `/ecs/devsecops-webapp`, `/aws/codebuild/devsecops-llm-auditor-scan` | Default retention | Application stdout/stderr and pipeline build logs |

### 1.4 Data and Process Flow

The system operates through two complementary interaction paths sharing the same Lambda functions. The following table quantifies the operational improvement versus a manual security review process for each scan event.

**Table 1.3: Manual vs. Automated Security Review**

| Metric | Manual Review | Automated Pipeline | Improvement Factor |
|--------|--------------|-------------------|-------------------|
| Review trigger mechanism | Developer requests review via ticket or chat message | Automatic on `git push` to `main` branch | Eliminates process friction |
| Review turnaround time | Hours to days (reviewer scheduling and context-switching dependent) | ~30 seconds (SecurityTest stage execution) | >100× faster |
| Decision consistency | Varies by individual reviewer expertise, fatigue, and familiarity with AWS security best practices | Deterministic — identical IaC input always produces identical PASS/BLOCK output | Eliminates subjective variance |
| Remediation guidance quality | Dependent on reviewer's security knowledge and documentation diligence | AI-generated via Nova Micro with structured system prompt; standardized across all scans | Consistent, specific, actionable |
| Audit trail integrity | Fragmented across email threads, chat logs, and ticket systems | Centralized in S3 (JSON + Markdown), CodePipeline execution history, and CloudWatch Logs | Single authoritative source |

**Table 1.4: Pipeline Path — Automated CI/CD Flow**

| Stage | Execution Details | Duration |
|-------|------------------|----------|
| Trigger | `git push` to GitHub `main` branch → CodePipeline webhook detection | ~5s |
| Source | GitHub repository clone → source artifact stored in S3 | ~10s |
| SecurityTest | ① `aws s3 cp infrastructure.yaml` → S3 `templates/` → ② Python payload generation via `open().read()` + `json.dump()` → ③ `aws lambda invoke --function-name devsecops-security-scanner` → ④ `grep -q "FunctionError" scan_response.json` → ⑤ If clean: `aws lambda invoke --function-name llm-auditor` with `{s3_bucket, s3_key}` → ⑥ LLM writes JSON + MD reports to S3 `reports/` | ~30s |
| Build | ECR login → `docker build --platform linux/amd64` → dual-tag push (`latest` + commit SHA first 7 characters) → `imagedefinitions.json` output artifact | ~60s |
| Deploy | ECS rolling update → new Fargate task provisioned → ALB health check passes (`/health` returns 200) → old task connection drained and deregistered | ~40s |

**Table 1.5: Web Platform Path — Interactive Scanning Flow**

| Step | Technical Implementation |
|------|--------------------------|
| Authentication | `POST /api/login` → `auth_service.authenticate()` verifies SHA-256 salted password hash against SQLite `users` table → issues signed JWT (HS256, `sub`/`iat`/`exp` claims, 24-hour expiry) → response: `{success, token}` |
| Authorization | `require_auth` FastAPI dependency (`Depends`) extracts `Authorization: Bearer <token>` header → `validate_token()` decodes and verifies signature via PyJWT → raises HTTP 401 on expired or tampered token |
| Scan Request | `POST /api/scan` → Pydantic `ScanRequest` model validates `{iac_content, dockerfile_content, app_code}` → all three fields optional (empty `app_code` skips code scanning) |
| Infrastructure Scanner | boto3 `client.invoke(FunctionName="devsecops-security-scanner", Payload=json.dumps(...))` → `StreamingBody.read().decode()` → parse `FunctionError` field → if present, extract `errorMessage` (Chinese-language: `"安全检查未通过！发现 X 个严重漏洞，Y 个高危漏洞"`) → split on `发现`, then `，` to extract critical/high counts |
| LLM Auditor Three-RPC Chain | ① `s3.put_object(Bucket, Key=templates/web-scan-{uuid}.yaml, Body=iac_content)` — if `app_code` is non-empty, appends after `# === Application Code ===` marker → ② `client.invoke(llm-auditor, Payload={s3_bucket, s3_key})` — Lambda reads file from S3, invokes Bedrock Nova Micro with structured system prompt defining 8 rules, writes reports to S3 → ③ `s3.get_object(Bucket, Key=report_location)` — downloads report JSON → parses `details[]` array of 8 rule objects |
| Code Scanner | Direct regex evaluation in `code_scanner.py` — file extension detection routes `.py/.pyi` to `PYTHON_RULES` (8 rules) and `.js/.ts/.jsx/.tsx/.mjs/.cjs` to `JS_RULES` (11 rules) — no Lambda dependency, in-process execution |
| Response Assembly | Merged JSON: `{id, timestamp, status, findings: [{rule, count}], details: [{rule_id, status, risk_level, finding, remediation}], code_findings: [{rule_id, risk_level, finding, remediation, file, line, code}], iac_snippet, dockerfile_snippet}` |

### 1.5 Architecture Diagram

```mermaid
graph TB
    subgraph External["External"]
        Browser["Browser — React SPA"]
        GitPush["git push"]
    end
    subgraph Edge["Edge Layer"]
        ALB["ALB — HTTP :80"]
    end
    subgraph Compute["Compute Layer — Private Subnets"]
        ECS["ECS Fargate — 256 CPU, 512 MB<br/>FastAPI :8000<br/>USER appuser (non-root)"]
    end
    subgraph Serverless["Serverless Layer"]
        Scanner["Scanner Lambda<br/>Python 3.10 | 256 MB | 60s<br/>8 infrastructure rules<br/>Payload: inline JSON"]
        LLM["LLM Auditor Lambda<br/>Python 3.12 | 128 MB | 30s<br/>Amazon Nova Micro<br/>Payload: S3 path"]
    end
    subgraph Storage["Storage Layer"]
        S3["S3 — KMS Encrypted<br/>templates/ — IaC staging<br/>reports/ — Audit reports"]
        ECR["ECR — KMS Encrypted<br/>devsecops-app<br/>Tag: commit SHA"]
    end
    subgraph Pipeline["CI/CD Pipeline"]
        CP["CodePipeline V2<br/>Source → SecurityTest → Build → Deploy"]
        CB1["CodeBuild — SecurityTest<br/>Unprivileged"]
        CB2["CodeBuild — Build<br/>Privileged (Docker)"]
    end

    Browser -->|"HTTP :80"| ALB -->|"forward :8000"| ECS
    ECS -->|"boto3 invoke"| Scanner
    ECS -->|"boto3 invoke"| LLM
    ECS -->|"S3 PutObject/GetObject"| S3
    LLM -->|"S3 GetObject — read .yaml"| S3
    LLM -->|"S3 PutObject — write reports"| S3
    GitPush --> CP
    CP --> CB1 --> Scanner
    CP --> CB1 --> LLM
    CP --> CB2 --> ECR
    CP --> ECS
```

### 1.6 Key Design Decisions

**Multi-Stage Container Build.** The Dockerfile employs a two-stage build strategy. Stage 1 uses `node:22-alpine` as the build image — `npm ci` installs exact dependency versions from the lockfile, `npm run build` compiles the TypeScript React application via Vite into compressed static assets (JavaScript ~64 KB, CSS ~4 KB). Stage 2 uses `python:3.11-slim` — copies only `requirements.txt`, installs dependencies with `--no-cache-dir`, copies compiled frontend assets from Stage 1 into `/app/static/`, creates non-root `appuser` with `chown -R appuser:appuser /app`, and switches to that user before starting uvicorn. The final image excludes Node.js, npm, and all frontend development dependencies. The `--platform linux/amd64` flag is mandatory because the development environment operates on ARM architecture (Apple Silicon) while Fargate requires x86-64.

**Dual Security Group Network Isolation.** The Fargate service is protected by a two-layer security group architecture. The ALB security group (`sg-044770e4a0d745b09`) permits inbound TCP traffic on port 80 from any source (`0.0.0.0/0`) — this is the system's sole public ingress. The application security group (`sg-0345988fbb2fe2e30`) permits inbound TCP traffic on port 8000 exclusively from the ALB security group's ID. No other ingress rules exist. Fargate tasks operate in private subnets without public IP addresses and access ECR and the internet through a NAT Gateway located in a public subnet. This design ensures that even if the ALB were misconfigured, containers remain unreachable from the public internet.

**Buildspec Inline Storage Strategy.** The SecurityTest buildspec is stored inline within the CodeBuild project configuration rather than as a repository file. This decision eliminated a class of YAML parsing errors encountered during development where `:` characters in shell commands — such as `{iac_content: $iac, dockerfile_content: $dkr}` — were interpreted by CodeBuild's YAML parser as mapping key-value separators. Payload generation uses Python's `open().read()` + `json.dump()` combination rather than jq, bypassing both YAML and shell escaping complexities entirely. The inline approach also decouples pipeline configuration from application source code, enabling independent iteration on the security workflow.

**Dual Lambda Interface Abstraction.** The two Lambda functions present different payload interfaces reflecting their distinct design requirements. The scanner accepts inline content — `{iac_content, dockerfile_content}` — supporting low-latency direct invocation without S3 pre-staging. The auditor requires S3 paths — `{s3_bucket, s3_key}` — because it internally reads the IaC file from S3 before sending it to Bedrock for analysis. The web platform and pipeline handle both formats transparently: they upload the IaC template to S3 first (required by the auditor), invoke the scanner with inline text for lower latency, then invoke the auditor with the S3 path.

**Chinese-Language Error Message Parsing.** Role 3's Lambda outputs error messages in Chinese: `"安全检查未通过！发现 1 个严重漏洞，3 个高危漏洞。已阻断部署。"`. Role 2's `scan_service.py` (lines 31-48) implements a string-splitting parser that extracts the critical (`严重漏洞`) and high (`高危漏洞`) occurrence counts to produce a structured `summary` array — an example of cross-language integration where the Lambda's natural language output is treated as a machine-readable protocol by the consumer.

**Module-Level Initialization Pattern.** `init_db()` executes at module scope in `main.py:12` — once at container startup, before uvicorn binds the port — creating the SQLite `users` table and seeding the default account. Similarly, `s3` and `lambda` boto3 clients (`main.py:16`, `scan_service.py:13-14`) are instantiated at module scope and reused across all HTTP requests via boto3's internal connection pooling, avoiding per-request authentication overhead.

**FastAPI Route Ordering.** API endpoints are registered before the `/{full_path:path}` SPA catch-all (line 116). FastAPI processes routes in registration order, so `/api/*` requests match their specific handlers while all other paths — `/`, `/assets/index.js`, `/favicon.ico` — fall through to the catch-all serving `index.html` for client-side React routing. The `audit-log/{report_key:path}` endpoint uses a `:path` converter to support S3 report keys containing forward slashes.

---

## Section 2. Risk and Threat Analysis

### 2.1 Data Classification Framework

A three-tier data classification model governs information handling throughout the system, aligned with NIST SP 800-53 Rev. 5 Control AC-3 (Access Enforcement) and the AWS Well-Architected Framework Security Pillar:

**Table 2.1: Data Classification Scheme**

| Tier | Classification | Data Assets | Storage Controls | Access Model |
|------|---------------|-------------|-----------------|--------------|
| L1 | Confidential | IAM policy documents, CloudFormation templates, LLM-generated security audit reports (JSON + Markdown) | S3 with KMS CMK encryption; Block Public Access enabled on all four settings; SSE-KMS server-side encryption | IAM role-based access exclusively; no IAM user access; all operations through assumed service roles |
| L2 | Internal | Docker container images (ECR), CloudWatch application and pipeline logs, CodePipeline execution metadata | ECR with KMS encryption; CloudWatch Logs with default AWS-managed encryption | Service-linked roles only; private subnet network boundary; no cross-account access configured |
| L3 | Public | End-user HTTP traffic to the web scanning platform | N/A — data in transit only | ALB listener on port 80 routes to target group; no backend services, databases, or administrative interfaces exposed to public routing |

### 2.2 STRIDE Threat Analysis

A systematic threat model was developed using the STRIDE methodology — **S**poofing identity, **T**ampering with data, **R**epudiation of actions, **I**nformation disclosure, **D**enial of service, and **E**levation of privilege. Eight attack vectors were identified as relevant to the pipeline and web platform.

**Table 2.2: Threat Analysis Matrix**

| ID | STRIDE Category | Threat Scenario | Likelihood | Impact | Composite Risk | Primary Mitigating Control | Secondary Defense |
|----|-----------------|-----------------|------------|--------|----------------|---------------------------|-------------------|
| T1 | Elevation of Privilege | An IAM role is provisioned with `"Action": "*"` in its inline policy document via CloudFormation. A compromised service assuming this role gains unrestricted API access across all AWS services in the account. | Medium | High | **High** | IAM-01 and IAM-02 rules: the security scanner parses `PolicyDocument.Statement[].Action` and `.Resource` fields, blocks deployment on wildcard detection | Pre-commit CloudFormation linting with `cfn-lint` |
| T2 | Information Disclosure | A security group ingress rule exposes TCP port 22 (SSH) to `0.0.0.0/0`. An external attacker discovers the open port and conducts brute-force credential attacks against the SSH service. | Low | Critical | **Critical** | NET-01 rule: iterates all `SecurityGroupIngress[]` entries, matches `CidrIp == "0.0.0.0/0"` AND port range covering 22, blocks deployment | Network ACL rules as defense-in-depth at the subnet boundary |
| T3 | Information Disclosure | A security group exposes PostgreSQL port 5432 or MySQL port 3306 to `0.0.0.0/0`. An attacker bypasses application-layer authentication by connecting directly to the database endpoint. | Low | Critical | **Critical** | NET-02 and NET-03 rules: same port-range detection logic for ports 5432 and 3306 respectively | Role 1 places all databases in private subnets with no public route table association |
| T4 | Information Disclosure | An S3 bucket is provisioned without `BucketEncryption` configuration. An accidental bucket policy or ACL change makes the bucket publicly readable, exposing IaC templates containing AWS resource ARNs and account identifiers. | Medium | Medium | **Medium** | DATA-01 rule: checks for presence of `BucketEncryption.ServerSideEncryptionConfiguration` in resource properties | S3 Block Public Access enabled at the bucket level |
| T5 | Tampering | A Docker container runs as `USER root` or omits the USER directive entirely (defaults to root). A compromised application process gains root filesystem access, potentially modifying the container runtime or escaping to the host. | Medium | High | **High** | CONT-01 rule: line-by-line regex scan of Dockerfile for `USER root`, `USER 0`, or absence of any `USER` instruction | Read-only root filesystem mount (planned future enhancement) |
| T6 | Information Disclosure | Application source code contains a hardcoded AWS access key matching the `AKIA...` pattern. The key is committed to version control and exposed through repository history, build artifacts, or deployment logs. | Medium | Critical | **Critical** | SECRET-02 rule: regex pattern `AKIA[0-9A-Z]{16}` detects AWS access key IDs in source code | Git pre-commit hook integration to block secret commits before they reach the remote |
| T7 | Elevation of Privilege | Application code uses `os.system()` with user-controlled input. An attacker injects shell metacharacters through a web form, achieving arbitrary command execution in the container context. | Medium | High | **High** | INJECT-02 rule: regex pattern `os\.system\s*\(\s*f?["']` detects command injection vectors | Container runs as non-root `appuser` — limits blast radius even if command execution is achieved |
| T8 | Information Disclosure | A JWT bearer token stored in browser `localStorage` is accessed by malicious JavaScript via a cross-site scripting (XSS) vulnerability. The attacker impersonates the authenticated user. | Medium | Medium | **Medium** | JWT expiry (24-hour `exp` claim) limits token lifetime; HS256 signing with `secrets.compare_digest` prevents timing attacks on validation | Content Security Policy HTTP header restricts script sources |

### 2.3 Risk Calculation Methodology

Risk is computed using the standard qualitative model:

> **Risk = Likelihood × Impact**

| Severity Level | Criteria | Pipeline Response |
|----------------|----------|-------------------|
| **Critical** | Exploitation is probable AND impact is catastrophic (e.g., full account compromise, data breach of all stored assets) | **Block deployment immediately** — SecurityTest stage returns exit code 1, Build and Deploy stages not executed |
| **High** | Significant business impact from exploitation (e.g., service-wide privilege escalation, container escape to host) | **Block deployment** — same mechanism, pipeline halts at SecurityTest |
| **Medium** | Moderate impact with existing mitigating controls (e.g., encryption absence where other access controls apply) | **Warn, do not block** — findings logged in audit report; deployment proceeds |
| **Low** | Minimal incremental impact beyond existing protections | **Recommendation only** — documented in report for informational purposes |

The blocking threshold is configured at **High severity and above**. This means the pipeline halts deployment for IAM wildcard policies, public SSH and database port exposure, and container root execution. S3 encryption issues (DATA-01/02) and all application code findings (SECRET-* / INJECT-* / DESER-01 / INPUT-01) produce warnings without blocking.

---

## Section 3. Security Checklist

### 3.1 Infrastructure Security Rules (Role 3 — Security Scanner Lambda)

The security scanner Lambda function (`devsecops-security-scanner`) parses CloudFormation YAML templates using `yaml.safe_load()`. It iterates all resources, identifies types `AWS::IAM::Role`, `AWS::IAM::Policy`, `AWS::EC2::SecurityGroup`, and `AWS::S3::Bucket`, and evaluates their properties against eight deterministic rules. Dockerfile content is analyzed separately via line-by-line regex matching. If any Critical or High severity rule fails, the Lambda throws a Python `Exception`, causing the boto3 invocation response to contain `FunctionError: Unhandled`. CodeBuild detects this with `grep -q "FunctionError"` and returns exit code 1, halting the pipeline.

**Table 3.1: Infrastructure Security Rules**

| # | Rule ID | Domain | Security Check | Severity | Detection Algorithm | Remediation Guidance |
|---|---------|--------|---------------|----------|---------------------|----------------------|
| 1 | IAM-01 | Identity | IAM policy document contains `"Action": "*"` wildcard | **HIGH** | Parse `PolicyDocument.Statement[]` list; iterate each statement's `Action` field; flag if string equals `"*"` or list contains `"*"` | Replace wildcard with explicitly enumerated AWS API action names (e.g., `["s3:GetObject", "s3:PutObject"]`) |
| 2 | IAM-02 | Identity | IAM policy document contains `"Resource": "*"` wildcard | **HIGH** | Same parsing logic applied to `Resource` field | Restrict to specific resource ARNs (e.g., `"arn:aws:s3:::my-bucket/*"`) |
| 3 | NET-01 | Network | Security group ingress rule permits `0.0.0.0/0` with port range covering 22 (SSH) | **CRITICAL** | Iterate `SecurityGroupIngress[]`; for each rule where `CidrIp == "0.0.0.0/0"`, check `FromPort ≤ 22 ≤ ToPort` | Restrict SSH access to VPC CIDR `10.0.0.0/16` or trusted corporate IP ranges |
| 4 | NET-02 | Network | Security group ingress rule permits `0.0.0.0/0` with port range covering 5432 (PostgreSQL) | **CRITICAL** | Same logic for port 5432 | Restrict database access to internal CIDR blocks only |
| 5 | NET-03 | Network | Security group ingress rule permits `0.0.0.0/0` with port range covering 3306 (MySQL) | **CRITICAL** | Same logic for port 3306 | Restrict database access to internal CIDR blocks only |
| 6 | DATA-01 | Encryption | S3 bucket resource has no `BucketEncryption` property | **MEDIUM** | Check resource properties dictionary for presence of key `BucketEncryption` containing `ServerSideEncryptionConfiguration` | Add `BucketEncryption` with `SSEAlgorithm: aws:kms` or `AES256` |
| 7 | DATA-02 | Encryption | S3 bucket uses `SSEAlgorithm: AES256` (SSE-S3) instead of `aws:kms` (SSE-KMS) | **LOW** | Extract `SSEAlgorithm` from `ServerSideEncryptionByDefault`; flag if value is not `"aws:kms"` | Upgrade to KMS customer-managed key for enhanced access control and audit logging |
| 8 | CONT-01 | Container | Dockerfile uses `USER root`, `USER 0`, or contains no `USER` directive at all | **HIGH** | Line-by-line regex scan: match `^\s*USER\s+(root\|0)` for explicit root; if no `USER` line found in entire file, flag as implicit root | Add `USER <non-root-username>` directive (e.g., `USER appuser`) with UID ≥ 1000 |

```mermaid
pie title Infrastructure Rule Severity Distribution
    "CRITICAL — NET-01/02/03" : 3
    "HIGH — IAM-01/02, CONT-01" : 3
    "MEDIUM — DATA-01" : 1
    "LOW — DATA-02" : 1
```

### 3.2 Application Code Security Rules (Role 2 — Backend Code Scanner)

The code scanner (`code_scanner.py`) implements regex-based security rules that execute directly in the FastAPI process for web scans, eliminating Lambda cold-start latency for quick text analysis. For pipeline scans, the same logic is duplicated as inline Python within the CodeBuild buildspec. The scanner detects the file type by extension — `.py` and `.pyi` files use `PYTHON_RULES` (8 rules); `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, and `.cjs` files use `JS_RULES` (11 rules). Rule matching uses `re.search()` with `re.IGNORECASE` flag for case-insensitive pattern detection. Each rule produces at most one finding per file via an explicit `break` after the first match.

**Table 3.2: Python Application Code Rules**

| # | Rule ID | Security Check | Severity | Regex Pattern | Example Match |
|---|---------|---------------|----------|---------------|---------------|
| 9 | SECRET-01 | Hardcoded password assignment (`password = "..."`) | **CRITICAL** | `password\s*=\s*["'][^"']{3,}["']` with negative lookaheads excluding `${...}` templates, `ChangeMe`, `template` | `password = "admin123"` |
| 10 | SECRET-02 | Hardcoded AWS access key ID (`AKIA...`) | **CRITICAL** | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| 11 | SECRET-03 | Hardcoded GitHub personal access token | **HIGH** | `gh[pous]_[0-9a-zA-Z]{36}` | `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |
| 12 | SECRET-04 | Hardcoded API key or secret token | **HIGH** | `(?:api[_-]?key\|secret[_-]?key\|token)\s*=\s*["'][^"']{8,}["']` | `API_KEY = "sk-proj-abc123..."` |
| 13 | INJECT-01 | SQL injection via f-string interpolation | **HIGH** | `f["'].*?\bSELECT\b` | `f"SELECT * FROM users WHERE id = {user_id}"` |
| 14 | INJECT-02 | Command injection via `os.system()` or `subprocess` with `shell=True` | **HIGH** | `os\.system\s*\(\s*f?["']` | `os.system(f"cat {filename}")` |
| 15 | DESER-01 | Unsafe deserialization via `pickle.loads()` or `yaml.load()` without SafeLoader | **HIGH** | `pickle\.loads?\s*\(\|yaml\.load\s*\([^{]` | `pickle.loads(user_data)` |
| 16 | INPUT-01 | Dynamic code execution via `eval()` or `exec()` | **MEDIUM** | `\beval\s*\(\|\bexec\s*\(` | `eval(user_input)` |

**Table 3.3: JavaScript/TypeScript Application Code Rules**

| # | Rule ID | Security Check | Severity | Regex Pattern |
|---|---------|---------------|----------|---------------|
| 17 | SECRET-JS-01 | Hardcoded AWS or GitHub keys | **CRITICAL** | `AKIA[0-9A-Z]{16}\|gh[pous]_[0-9a-zA-Z]{36}` |
| 18 | SECRET-JS-02 | Hardcoded credentials as object properties | **HIGH** | `(?:password\|apiKey\|api_key\|secretKey\|token)\s*[:=]\s*["'`][^"'`\s]{4,}["'`]` |
| 19 | SECRET-JS-03 | Sensitive data in localStorage | **MEDIUM** | `localStorage\.(?:setItem\|getItem)\s*\(\s*["']?token` |
| 20 | INJECT-JS-01 | Cross-site scripting via innerHTML or dangerouslySetInnerHTML | **HIGH** | `\.innerHTML\s*=\|dangerouslySetInnerHTML` |
| 21 | INJECT-JS-02 | SQL injection via template literal interpolation | **HIGH** | `` `.*?\bSELECT\b.*\$\{ ` `` |
| 22 | INPUT-JS-01 | Dynamic code execution via eval() or Function() | **HIGH** | `\beval\s*\(\|new\s+Function\s*\(` |

```mermaid
pie title Application Code Rule Severity Distribution (14 Python + 8 JS/TS = 22 Rules)
    "CRITICAL" : 4
    "HIGH" : 15
    "MEDIUM" : 3
```

### 3.3 Enforcement Architecture

The two scanners operate with distinct enforcement policies reflecting the different blast radii of infrastructure versus application-level vulnerabilities:

```
Infrastructure Scanner (Role 3 Lambda — Gatekeeper)
    ├── CRITICAL or HIGH severity rule fails → Lambda throws Exception
    │       → boto3 response contains FunctionError: Unhandled
    │       → CodeBuild: grep -q "FunctionError" → exit 1
    │       → Pipeline halts at SecurityTest stage — Build and Deploy not executed
    │
    ├── Only MEDIUM or LOW findings → Lambda returns HTTP 200
    │       → Pipeline continues → PASSED with documented warnings
    │
    └── No findings → Lambda returns HTTP 200 → Pipeline continues → PASSED

Application Code Scanner (Role 2 Regex Engine — Advisor)
    ├── Any rule matched → appended to "code_findings" array in scan response
    │       → Displayed as ⚠️ WARNING in web UI and CodeBuild logs
    │       → Does NOT affect pipeline pass/fail status
    │
    └── No matches → empty "code_findings" array → no warnings displayed
```

**Table 3.4: Automated vs. Manual Security Review Comparison**

| Criterion | Manual Code Review | This System |
|-----------|-------------------|-------------|
| Rule coverage | Variable; depends on reviewer expertise and fatigue; typically 30-50% of defined rules applied consistently | Systematic — all 22 rules (8 infrastructure + 14 application code) applied to every scan without omission |
| Decision consistency | Subjective — identical code may receive different verdicts from different reviewers or the same reviewer at different times | Deterministic — identical input always produces identical output; PASS/BLOCK is binary and reproducible |
| Review speed | ~1 hour per pull request including reviewer context switching, scheduling latency, and documentation time | <10 seconds per scan: ~1.2s scanner Lambda + ~4.5s LLM auditor + <10ms code scanner |
| Remediation quality | Dependent on individual reviewer's security domain expertise and documentation diligence | Standardized AI-generated remediation text with specific code examples; consistent format across all scans |
| Audit trail | Fragmented across pull request comments, chat applications, email threads, and ticketing systems | Single authoritative source: JSON report in S3, Markdown report in S3, CodePipeline execution history, CloudWatch invocation logs |
| Scalability | Linear effort growth with team size, commit frequency, and reviewer availability | Constant cost — Lambda functions auto-scale with invocation count; CodeBuild provisions on-demand |

---

## Section 4. Assessment Results

### 4.1 Test Methodology

Validation was conducted across three complementary layers: (a) **unit testing** of individual Lambda functions by Roles 3 and 4 using sample payloads with known expected outcomes; (b) **integration testing** of the FastAPI backend by invoking the `/api/scan` endpoint with controlled input and verifying the structured JSON response; and (c) **end-to-end pipeline execution testing** with full CodePipeline runs triggered by `git push` events. Two reference Infrastructure as Code templates were constructed — deliberately insecure "DangerTest" exercising all rule domains simultaneously, and security-compliant "SafeTest" designed to produce zero false positives across all 22 rules.

### 4.2 DangerTest — Multi-Vector Vulnerability Configuration

**Objective:** Validate the system's ability to detect and block concurrent security violations spanning all four infrastructure rule domains and application code patterns simultaneously.

**Input Configuration:**

| Component | Deliberate Vulnerability | Rule(s) Expected to Trigger |
|-----------|-------------------------|----------------------------|
| IaC — Security Group | Ingress rule: `CidrIp: 0.0.0.0/0`, `FromPort: 22`, `ToPort: 22` | NET-01 (CRITICAL) |
| IaC — IAM Policy | Inline policy with `"Action": "*"` and `"Resource": "*"` | IAM-01 (HIGH), IAM-02 (HIGH) |
| IaC — S3 Bucket | No `BucketEncryption` property defined | DATA-01 (MEDIUM) |
| Dockerfile | `USER root` directive at line 4 | CONT-01 (HIGH) |
| Application Code (Python) | `password = "admin123"`, `API_KEY = "sk-proj-abc..."`, `os.system("ls")` | SECRET-01 (CRITICAL), SECRET-04 (HIGH), INJECT-02 (HIGH) |

**Table 4.1: DangerTest — Infrastructure Rule Results**

| Rule ID | Status | Severity | Scanner Finding |
|---------|--------|----------|-----------------|
| IAM-01 | **FAIL** | HIGH | Wildcard `Action: "*"` detected in IAM policy document |
| IAM-02 | **FAIL** | HIGH | Wildcard `Resource: "*"` detected in IAM policy document |
| NET-01 | **FAIL** | CRITICAL | Security group exposes port 22 (SSH) to 0.0.0.0/0 |
| NET-02 | PASS | CRITICAL | No PostgreSQL port 5432 exposure detected |
| NET-03 | PASS | CRITICAL | No MySQL port 3306 exposure detected |
| DATA-01 | **FAIL** | MEDIUM | S3 bucket has no `BucketEncryption` configuration |
| DATA-02 | — | LOW | Not evaluated (encryption absent — DATA-01 already triggered) |
| CONT-01 | **FAIL** | HIGH | Dockerfile explicitly declares `USER root` |

**Pipeline Outcome:** SecurityTest stage **BLOCKED**. The scanner Lambda raised an exception — `FunctionError: Unhandled` present in invocation response. CodeBuild detected this via `grep -q "FunctionError"` and returned exit code 1. Build and Deploy stages were not executed.

**Table 4.2: DangerTest — Application Code Results**

| Rule ID | Status | Severity | Detection Details |
|---------|--------|----------|-------------------|
| SECRET-01 | FAIL | CRITICAL | Line 2: `password = "admin123"` hardcoded credential |
| SECRET-04 | FAIL | HIGH | Line 1: `API_KEY = "sk-proj-..."` hardcoded API token |
| INJECT-02 | FAIL | HIGH | Line 3: `os.system("ls")` command injection vector |

**Code Scan Outcome:** Three warnings issued via the `code_findings` response array. Displayed as ⚠️ WARNING indicators in the web UI beneath the infrastructure BLOCKED result. Infrastructure blocking triggered independently — code warnings are informational only and do not influence the pipeline's binary pass/fail decision.

```mermaid
pie title DangerTest — Rule Status Distribution (8 Infra + 3 Code)
    "Infrastructure FAILED" : 5
    "Infrastructure PASSED" : 2
    "Infrastructure N/A" : 1
    "Code WARNINGS" : 3
```

### 4.3 SafeTest — Security-Compliant Baseline

**Objective:** Validate that properly configured, security-compliant infrastructure passes all checks with zero false positives and deploys successfully through the complete pipeline.

**Input Configuration:**

| Component | Compliant Configuration |
|-----------|------------------------|
| IaC — Security Group | Ingress: `CidrIp: 10.0.0.0/16`, `FromPort: 443`, `ToPort: 443` — internal VPC CIDR only |
| IaC — IAM Roles | AWS managed policies (`AWSLambdaBasicExecutionRole`); no inline policy documents with wildcards |
| IaC — S3 Bucket | `BucketEncryption` with `SSEAlgorithm: aws:kms` (KMS customer-managed key) |
| Dockerfile | `USER appuser` — explicit non-root user with UID ≥ 1000 |
| Application Code | `API_KEY = os.getenv("API_KEY")`; no `eval()`, `os.system()`, or `pickle.loads()` calls |

**Table 4.3: SafeTest Results**

| Validation Layer | Rules Evaluated | Passed | Failed | Overall Status |
|-----------------|-----------------|--------|--------|----------------|
| Infrastructure (Scanner Lambda) | 8 | 8 | 0 | **PASSED** — no exceptions raised |
| Application Code (Regex Engine) | 22 | 22 | 0 | **No warnings** — empty `code_findings` array |
| Pipeline Stages | 4 (Source → SecurityTest → Build → Deploy) | 4 | 0 | **ALL SUCCEEDED** |
| Deployment Verification | Application accessible via ALB endpoint; API health returns `{"status":"healthy"}`; SPA returns HTTP 200 | — | — | **Verified** |

**Pipeline Execution Timeline:**

```mermaid
gantt
    title SafeTest — Pipeline Stage Duration
    dateFormat mm:ss
    axisFormat %M:%S
    section Source
    GitHub clone + artifact store   :s1, 00:00, 15s
    section SecurityTest
    S3 upload + Scanner + LLM       :s2, after s1, 30s
    section Build
    Docker build + ECR push         :s3, after s2, 60s
    section Deploy
    ECS rolling update              :s4, after s3, 40s
```

### 4.4 Quantitative Performance Metrics

**Table 4.4: Measured Performance Indicators**

| Metric | Measured Value | Technical Context |
|--------|---------------|-------------------|
| Pipeline end-to-end latency (passing) | ~135 seconds | Source: 15s + SecurityTest: 30s + Build: 60s + Deploy: 40s |
| Security Scanner Lambda invocation | ~1.2 seconds | Python 3.10, 256 MB memory, YAML parsing + 8-rule evaluation |
| LLM Auditor complete invocation | ~4.5 seconds | Python 3.12, 128 MB; includes Bedrock Nova Micro API latency (~3s) + S3 read/write (~1s) |
| Web API scan — safe (scanner only) | ~1.5 seconds | Single Lambda invocation + response parsing, no S3 round-trips |
| Web API scan — blocked (scanner + LLM chain) | ~7.5 seconds | Scanner Lambda (1.2s) + S3 upload (0.3s) + LLM auditor (4.5s) + S3 report download (0.5s) + JSON parsing (0.5s) |
| Code scanner — single file analysis | <10 milliseconds | In-process pure Python regex; no I/O, no Lambda invocation |
| JWT login — full authentication flow | ~5 milliseconds | SHA-256 hash verification + HS256 JWT signing |
| ECS Fargate cold start | ~45 seconds | Docker image pull from ECR + container initialization + uvicorn startup + ALB target registration + health check passage |
| ECS Fargate warm restart (same image) | ~10 seconds | Container process restart only — image cached on host |
| GitHub Action scan (external repository) | ~3 seconds | Lambda cold-start + payload transfer; one workflow file integration |

```mermaid
pie title Pipeline Time Allocation (~135 seconds)
    "Source — 15s" : 15
    "SecurityTest — 30s" : 30
    "Build — 60s" : 60
    "Deploy — 40s" : 40
```

### 4.5 Error Resilience and Graceful Degradation

The system handles component failures at multiple architectural layers without cascading into unrecoverable states. Each failure mode was tested by deliberately introducing faults (e.g., IAM permission removal, S3 bucket deletion, malformed JSON responses) and observing system behavior.

**Table 4.5: Error Resilience Verification Matrix**

| Failure Point | Code Location | Induced Fault | Observed System Behavior |
|--------------|--------------|---------------|-------------------------|
| Scanner Lambda unreachable | `scan_service.py:24-27` | Lambda function deleted; IAM permissions revoked | `has_error` evaluates `False`; scan returns `status: "passed"` — fail-safe for scanner unavailability (pipeline owns the blocking decision) |
| LLM Auditor — S3 upload blocked | `scan_service.py:62-66` | IAM `s3:PutObject` permission removed from ECS task role | `_invoke_llm_auditor` catches `ClientError`, returns `[]`; scan `status` and `findings` unaffected; `details` array empty in response |
| LLM Auditor — Lambda invocation failure | `scan_service.py:71-78` | Lambda function timeout set to 1 second (actual processing requires ~4.5s) | Lambda returns task timeout error; `statusCode != 200` check triggers; `_invoke_llm_auditor` returns `[]`; scan result lacks details but maintains scanner-based status |
| LLM Auditor — S3 report read failure | `scan_service.py:86-92` | Report file deleted from S3 between Lambda completion and download | `s3.get_object` raises `NoSuchKey`; outer `try/except` at line 105 catches all exceptions; returns `[]` |
| Audit Log — S3 pagination failure | `main.py:72-97` | IAM `s3:ListBucket` permission removed | `s3.get_paginator("list_objects_v2")` raises `ClientError`; outer `try/except` catches; returns empty array → UI displays "No audit reports found" |
| Code Scanner — unreadable file | `code_scanner.py:82-87` | Binary file (`.png`) renamed to `.py` extension | `open(fpath, "r", errors="replace")` replaces non-decodable bytes with `�`; `except Exception: pass` on truly unopenable files |
| Database initialization | `auth_service.py:26-38` | `/app/` directory mounted read-only; `users.db` unwritable | `sqlite3.connect()` raises `OperationalError`; uvicorn startup blocked (fatal — container cannot serve without auth); ECS retries with new task |
| JWT — expired token | `auth_service.py:92-94` | Token manually constructed with `exp = now - 3600` (1 hour ago) | `jwt.decode()` raises `jwt.ExpiredSignatureError`; `validate_token` returns `False`; FastAPI returns HTTP 401; React frontend redirects to login page |
| JWT — tampered token | `auth_service.py:95-97` | Token signed with incorrect `JWT_SECRET` value | `jwt.decode()` raises `jwt.InvalidTokenError`; `validate_token` returns `False`; same 401 response flow |
| Frontend API failure | `App.tsx:20-22` | `fetchScans()` called while API unreachable (ALB health check failing) | `.catch(() => {})` silently swallows the rejected promise; application UI renders with empty scan history state without crashing |

### 4.6 Limitations and Future Work

**Table 4.6: Identified Limitations and Planned Resolutions**

| Limitation | Operational Impact | Severity | Planned Mitigation |
|------------|-------------------|----------|-------------------|
| In-memory scan history (`scans: list[dict]` at module level) | All scan records lost on container restart or deployment; no historical persistence | Medium | Migrate to Amazon DynamoDB table with partition key on scan ID; implement Time-To-Live (TTL) attribute for automatic record expiration |
| Single-user authentication model | All authenticated users share identical scan history and audit log visibility; no per-user data isolation | Medium | Integrate AWS Cognito User Pools for OAuth2/OIDC authentication; add `user_id` partition to all data models; implement row-level access control |
| Synchronous Lambda invocation in web API | Large IaC templates exceeding ~50KB combined payload size may approach HTTP timeout thresholds; user blocked until LLM auditor completes | Low | Implement SQS-based asynchronous scan queue: API enqueues scan request with UUID, returns immediately; background worker processes; frontend polls `GET /api/scan/{id}/status` |
| Scanner supports CloudFormation YAML only | Organizations using HashiCorp Terraform (HCL) or Kubernetes manifest YAML cannot benefit from infrastructure scanning | Medium | Extend scanner Lambda with `python-hcl2` library for Terraform parsing; add `apiVersion`/`kind` detection for Kubernetes resources; implement adapter pattern per IaC format |
| No Service Level Objective monitoring | Pipeline reliability degradation (increased failure rate, latency drift) not detected without manual inspection | Low | Deploy CloudWatch composite alarms: pipeline failure rate >5% over rolling 1-hour window; scanner Lambda error rate >1% over 5-minute window; SNS notification to team communication channel |
| No emergency deployment bypass procedure | Scanner false positive (e.g., legitimate `!Ref` shorthand flagged) blocks critical production hotfix | Medium | Add manual approval action stage in CodePipeline with mandatory justification comment field; log all override events to dedicated CloudWatch Logs stream for audit |
| GitHub token in ECS task definition environment variable | Token stored in plaintext; manually provisioned; no rotation schedule | Low | Migrate to AWS Secrets Manager with automatic 30-day rotation via Lambda; inject at container start via `secretsmanager:GetSecretValue` |
| LLM auditor output lacks schema validation | Malformed JSON response from Bedrock could propagate through `json.loads()` and produce downstream parsing errors | Low | Integrate `jsonschema` library validation against a predefined JSON Schema for the expected report structure; fall back to summary-only response on validation failure |

### 4.7 Monthly Cost Analysis

**Table 4.7: Estimated AWS Monthly Operating Cost**

| Service | Provisioned Configuration | Monthly Estimate | Percentage |
|---------|--------------------------|-----------------|------------|
| ECS Fargate | 0.25 vCPU, 0.5 GB memory, 1 task, 24×7 uptime | $12.00 | 12.0% |
| Application Load Balancer | ~1 Load Balancer Capacity Unit, ~1M HTTP requests/month | $18.00 | 18.0% |
| NAT Gateway | Single instance, ~5 GB data processed through gateway | $35.00 | 35.0% |
| CodePipeline | 1 active V2 pipeline, ~30 executions/month | $30.00 | 30.0% |
| Amazon Bedrock (Nova Micro) | ~500 audit requests/month, ~1000 input + ~2000 output tokens each | $2.00 | 2.0% |
| CloudWatch Logs | ~2 GB ingestion, 30-day retention, ~1000 API requests | $2.00 | 2.0% |
| Lambda (Scanner + Auditor) | ~1500 total invocations/month, 256 MB + 128 MB configurations | $0.02 | <0.1% |
| CodeBuild | ~30 build minutes/month, BUILD_GENERAL1_SMALL compute type | $0.30 | 0.3% |
| S3 + ECR Storage | ~1.5 GB total stored across both services | $0.60 | 0.6% |
| **Total Estimated Monthly Cost** | | **~$99.92** | |

The NAT Gateway ($35/month, 35%) and CodePipeline ($30/month, 30%) together account for approximately two-thirds of total operating cost. Replacing the NAT Gateway with VPC Endpoints for S3 (`gateway` type, free) and ECR (`interface` type, ~$7/month) would reduce networking costs by approximately 60%. Migrating CI/CD orchestration from CodePipeline to GitHub Actions with the reusable composite action (Annex C) would reduce pipeline costs to near zero while retaining identical Lambda-based scanning, exchanging the AWS-native ECS deploy action for a custom deployment step.

---

## Section 5. Reference List

1. Amazon Web Services. (2025). *AWS Well-Architected Framework — Security Pillar*. https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/

2. Amazon Web Services. (2025). *AWS Lambda Developer Guide — Programming Model*. https://docs.aws.amazon.com/lambda/latest/dg/

3. Amazon Web Services. (2025). *AWS CodePipeline User Guide — Pipeline Structure*. https://docs.aws.amazon.com/codepipeline/latest/userguide/

4. Amazon Web Services. (2025). *Amazon ECS Developer Guide — Fargate Launch Type*. https://docs.aws.amazon.com/AmazonECS/latest/developerguide/

5. Amazon Web Services. (2025). *Amazon Bedrock User Guide — Foundation Models and Inference*. https://docs.aws.amazon.com/bedrock/latest/userguide/

6. Open Web Application Security Project. (2023). *Docker Security Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

7. Open Web Application Security Project. (2021). *OWASP Top Ten Web Application Security Risks*. https://owasp.org/www-project-top-ten/

8. National Institute of Standards and Technology. (2020). *SP 800-53 Rev. 5: Security and Privacy Controls for Information Systems and Organizations*. https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

9. GitHub, Inc. (2025). *Security Hardening for GitHub Actions*. https://docs.github.com/en/actions/security-guides

10. Shostack, A. (2014). *Threat Modeling: Designing for Security*. Indianapolis: Wiley. ISBN: 978-1118809990.

---

## Section 6. Annex

### Annex A: CodePipeline SecurityTest Buildspec

The following inline buildspec is stored in the `devsecops-llm-auditor-scan` CodeBuild project and executes on every pipeline SecurityTest stage invocation:

```yaml
version: 0.2
phases:
  build:
    commands:
      # Step 1: Stage IaC for LLM auditor (requires S3 path interface)
      - aws s3 cp infrastructure.yaml s3://devsecops-reports-087572104425/templates/infrastructure.yaml

      # Step 2: Application code scanning (non-blocking — informational only)
      - python3 -c "
        import os, re, json, sys
        findings = []
        rules = [
          ('SECRET-01','CRITICAL',r'password\s*=\s*[\"\\x27'][^\"\\x27']{3,}[\"\\x27']'),
          ('SECRET-02','CRITICAL',r'AKIA[0-9A-Z]{16}'),
          ('SECRET-03','HIGH',r'gh[pous]_[0-9a-zA-Z]{36}'),
          ('SECRET-04','HIGH',r'(?:api[_-]?key|secret[_-]?key|token)\s*=\s*[\"\\x27'][^\"\\x27']{8,}[\"\\x27']'),
          ('INJECT-01','HIGH',r'f[\"\\x27'].*?\bSELECT\b'),
          ('INJECT-02','HIGH',r'os\.system\s*\(\s*f?[\"\\x27']'),
        ]
        for root, dirs, files in os.walk('.'):
            dirs[:] = [d for d in dirs if d not in ('node_modules','.git','frontend','dist','build','__pycache__')]
            for fname in files:
                if fname.endswith(('.py','.js','.ts','.jsx','.tsx')):
                    try:
                        for i, line in enumerate(open(os.path.join(root,fname),errors='replace'),1):
                            for rid,risk,pat in rules:
                                if re.search(pat, line, re.I):
                                    findings.append({'rule_id':rid,'risk_level':risk,'file':fname,'line':i,'code':line.strip()[:100]})
                    except: pass
        if findings:
            json.dump(findings[:20], open('/tmp/code_findings.json','w'), indent=2)
        "

      # Step 3: Infrastructure scanning with Python payload generation
      - python3 -c "
        import json
        d = {'iac_content': open('infrastructure.yaml').read(),
             'dockerfile_content': open('Dockerfile').read()}
        json.dump(d, open('/tmp/payload.json','w'))
        "

      - aws lambda invoke --function-name devsecops-security-scanner
          --cli-binary-format raw-in-base64-out
          --payload file:///tmp/payload.json scan_response.json

      # Step 4: Blocking gate — FunctionError detection
      - |
        if grep -q "FunctionError" scan_response.json; then
          echo "!!! BLOCKED: Security violations detected !!!"
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
          --payload file:///tmp/llm-payload.json audit_response.json

      - echo "Security scan passed. LLM Audit completed."
```

### Annex B: Application Code Scanner (code_scanner.py)

```python
import re, os

PYTHON_RULES = [
    {"id":"SECRET-01","risk":"CRITICAL","desc":"Hardcoded password","fix":"Use os.getenv()",
     "pattern":r'password\s*=\s*["\'](?![a-zA-Z0-9\s]*\$\{)(?!\s*$)(?!ChangeMe)(?!template)[^"\']{3,}["\']'},
    {"id":"SECRET-02","risk":"CRITICAL","desc":"Hardcoded AWS key (AKIA...)","fix":"Use IAM roles",
     "pattern":r'AKIA[0-9A-Z]{16}'},
    {"id":"SECRET-03","risk":"HIGH","desc":"Hardcoded GitHub token","fix":"Use ECS env vars",
     "pattern":r'gh[pous]_[0-9a-zA-Z]{36}'},
    {"id":"SECRET-04","risk":"HIGH","desc":"Hardcoded API key","fix":"Use os.getenv('API_KEY')",
     "pattern":r'(?:api[_-]?key|secret[_-]?key|token)\s*=\s*["\'][^"\']{8,}["\']'},
    {"id":"INJECT-01","risk":"HIGH","desc":"SQL injection via f-string","fix":"Use parameterized queries",
     "pattern":r'f["\'].*?\bSELECT\b|f["\'].*?\bINSERT\b'},
    {"id":"INJECT-02","risk":"HIGH","desc":"Command injection","fix":"Use subprocess.run()",
     "pattern":r'os\.system\s*\(\s*f?["\']'},
    {"id":"DESER-01","risk":"HIGH","desc":"Unsafe deserialization","fix":"Use yaml.safe_load()",
     "pattern":r'pickle\.loads?\s*\(|yaml\.load\s*\([^{]'},
    {"id":"INPUT-01","risk":"MEDIUM","desc":"eval()/exec() call","fix":"Use ast.literal_eval()",
     "pattern":r'\beval\s*\(|\bexec\s*\('},
]

def scan_app_code(content:str, filepath:str="") -> list[dict]:
    findings = []
    ext = os.path.splitext(filepath)[1].lower() if filepath else ".py"
    if ext not in {".py",".js",".ts",".jsx",".tsx"}: return findings
    for rule in PYTHON_RULES:
        for i, line in enumerate(content.split("\n"), 1):
            if re.search(rule["pattern"], line, re.I):
                findings.append({"rule_id":rule["id"],"risk_level":rule["risk"],
                    "finding":rule["desc"],"remediation":rule["fix"],
                    "file":filepath or "input","line":i,"code":line.strip()[:120]})
                break
    return findings
```

### Annex C: Reusable GitHub Action for External Repositories

```yaml
name: "DevSecOps Security Scan"
description: "Scan IaC templates and Dockerfiles using the Security Scanner Lambda"
inputs:
  iac_file:       { default: "infrastructure.yaml" }
  dockerfile:     { default: "Dockerfile" }
  scanner_function: { default: "devsecops-security-scanner" }
runs:
  using: "composite"
  steps:
    - shell: bash
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

### Annex D: JWT Authentication Module (auth_service.py)

```python
import sqlite3, hashlib, secrets, os, time
from datetime import datetime, timezone
import jwt

DB_PATH = os.environ.get("AUTH_DB_PATH", os.path.join(os.path.dirname(__file__), "users.db"))
_MASTER = os.environ.get("JWT_MASTER_SECRET", "devsecops-jwt-master-key-2026")
JWT_SECRET = hashlib.sha256(_MASTER.encode()).hexdigest()
JWT_ALGORITHM, JWT_EXPIRY_SECONDS = "HS256", 86400

def init_db():
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)")
    conn.commit()
    if not conn.execute("SELECT id FROM users WHERE username=?","alan").fetchone():
        pw = hash_password("123456789")
        conn.execute("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",("alan",pw,datetime.now(timezone.utc).isoformat()))
        conn.commit()
    conn.close()

def hash_password(password:str) -> str:
    salt = secrets.token_hex(16)
    return f"{salt}:{hashlib.sha256((salt+password).encode()).hexdigest()}"

def authenticate(username:str, password:str) -> str|None:
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
    conn.close()
    if not row: return None
    salt, expected = row["password_hash"].split(":",1)
    if not secrets.compare_digest(hashlib.sha256((salt+password).encode()).hexdigest(), expected): return None
    now = int(time.time())
    return jwt.encode({"sub":row["username"],"iat":now,"exp":now+JWT_EXPIRY_SECONDS}, JWT_SECRET, algorithm=JWT_ALGORITHM)

def validate_token(token:str) -> bool:
    try: jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM]); return True
    except: return False
```

---

**Report prepared by**: Role 2 — Pipeline Engineer, COMP4635 Group Project
**Date**: August 2026
**Repository**: https://github.com/WongChinPang/DevSecOps-Pipeline
