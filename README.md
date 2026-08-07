# DevSecOps Pipeline

Automated security scanning platform for IaC templates and Dockerfiles. Combines static rule-based detection with LLM-powered auditing, triggered through a CI/CD pipeline or directly from the web UI.

## 运行时架构

### Full System Architecture

```mermaid
graph TB
    User["Browser (React SPA)"] -->|"HTTP :80"| ALB["ALB"]

    subgraph Compute["ECS Fargate (FastAPI)"]
        API["POST /api/scan<br/>GET /api/scans<br/>SPA fallback"]
    end

    ALB -->|"forward :8000"| API
    API -->|"boto3 invoke"| Scanner["Scanner Lambda<br/>Role 3 — 8 rules"]
    API -->|"S3 PutObject"| S3["S3 Reports Bucket"]
    API -->|"boto3 invoke"| LLM["LLM Auditor Lambda<br/>Role 4 — Nova Micro"]
    LLM -->|"S3 read .yaml"| S3
    LLM -->|"S3 write reports"| S3
    API -->|"S3 read reports"| S3
    API -->|"GitHub API<br/>PUT commit"| GitHub["GitHub<br/>WongChinPang/DevSecOps-Pipeline"]

    GitHub -->|"push event"| Pipeline["CodePipeline"]

    subgraph Pipeline["CodePipeline (4 stages)"]
        Source["Source"] --> SecurityTest["SecurityTest<br/>Scanner + LLM"] --> Build["Build<br/>Docker + ECR"] --> Deploy["Deploy<br/>ECS Fargate"]
    end

    Build -->|"docker push"| ECR["ECR<br/>tag: commit SHA"]
    Deploy -->|"rolling update"| API
```

### Scan Request Flow

```mermaid
sequenceDiagram
    actor User
    participant Browser as React SPA
    participant API as FastAPI :8000
    participant Scanner as Scanner Lambda
    participant S3 as S3 Bucket
    participant LLM as LLM Auditor
    participant GitHub as GitHub API

    User->>Browser: Paste IaC + Dockerfile, tick checkbox, click Scan
    Browser->>API: POST /api/scan {iac_content, dockerfile_content, trigger_pipeline}

    par Instant Scan
        API->>Scanner: invoke payload
        Scanner-->>API: PASSED or FunctionError

        alt Blocked
            API->>S3: PutObject templates/
            API->>LLM: invoke {s3_bucket, s3_key}
            LLM->>S3: GetObject → analyze → write report
            API->>S3: GetObject → parse per-rule details
        end
    and Pipeline Trigger
        API->>GitHub: GET file SHA → PUT commit
        GitHub-->>API: commit created → pipeline fires
    end

    API-->>Browser: {status, findings, details, pipeline}
    Browser-->>User: ✅ PASSED or ❌ BLOCKED with per-rule analysis
```

### Pipeline Stage Details

```mermaid
flowchart TD
    Trigger(["git push OR web UI checkbox"]) --> Source

    subgraph Stage1["Source"]
        Source["GitHub clone → SourceOutput artifact"]
    end

    Source --> SecurityTest

    subgraph Stage2["SecurityTest (CodeBuild)"]
        S1["① aws s3 cp → S3 templates/"]
        S2["② python3 build JSON payload"]
        S3["③ aws lambda invoke scanner"]
        S4{"④ grep FunctionError"}
        S5["⑤ aws lambda invoke llm-auditor"]
        S6["⑥ LLM writes → S3 reports/"]

        S1 --> S2 --> S3 --> S4
        S4 -->|"❌ Found"| Block["exit 1 — Pipeline BLOCKED"]
        S4 -->|"✅ Clean"| S5 --> S6
    end

    SecurityTest --> Build

    subgraph Stage3["Build (CodeBuild, privileged)"]
        B1["pre_build: ECR login"]
        B2["build: docker build --platform linux/amd64"]
        B3["post_build: docker push (tag: commit SHA)"]
        B4["output: imagedefinitions.json"]
        B1 --> B2 --> B3 --> B4
    end

    Build --> Deploy

    subgraph Stage4["Deploy (ECS)"]
        D1["Read imagedefinitions.json"]
        D2["ECS rolling update → new task → healthy → stop old"]
        D1 --> D2
    end
```

## Quick Start

Open the web platform, paste IaC YAML + Dockerfile, and click **Run Security Scan**.

Tick the checkbox to also commit to GitHub and trigger the full CI/CD pipeline.

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/scan` | POST | Scan IaC + Dockerfile (`{iac_content, dockerfile_content, trigger_pipeline}`) |
| `/api/scans` | GET | Scan history |

## Security Checklist

| Category | Rule | Risk | Check |
|----------|------|------|-------|
| IAM | IAM-01 | HIGH | No `Action: '*'` wildcards |
| IAM | IAM-02 | HIGH | No `Resource: '*'` wildcards |
| Network | NET-01 | CRITICAL | No `0.0.0.0/0:22` (SSH) |
| Network | NET-02 | CRITICAL | No `0.0.0.0/0:5432` (PostgreSQL) |
| Network | NET-03 | CRITICAL | No `0.0.0.0/0:3306` (MySQL) |
| Data | DATA-01 | MEDIUM | S3 bucket encryption enabled |
| Data | DATA-02 | LOW | S3 uses KMS encryption |
| Container | CONT-01 | HIGH | Dockerfile uses non-root user |

## Pipeline

CodePipeline runs on every push to `main` and on web UI trigger:

1. **Source** — GitHub clone
2. **SecurityTest** — Upload IaC to S3 → static scan → LLM audit (blocks on failure)
3. **Build** — Docker build (`linux/amd64`) → push to ECR with commit SHA tag
4. **Deploy** — ECS rolling update behind ALB

## Project Structure

```
├── app/                    # FastAPI backend
│   ├── main.py             # API endpoints + SPA fallback
│   ├── scan_service.py     # Lambda invocation + result parsing
│   └── github_service.py   # GitHub Contents API integration
├── frontend/               # React + TypeScript + Tailwind SPA
│   └── src/components/     # UploadForm, ScanResults, ScanHistory
├── Dockerfile              # Multi-stage: Node build + Python serve
├── infrastructure.yaml     # CloudFormation IaC template
├── infrastructure-safe.yaml # Compliant version (Fn::Ref, KMS)
├── tests/                  # Safe/unsafe test cases
├── demo-block.sh           # Demo: push unsafe IaC → pipeline blocks
├── demo-pass.sh            # Demo: push safe IaC → pipeline passes
├── demo-push.sh            # Demo: simple trigger push
├── CONTEXT.md              # Domain model glossary
└── docs/agents/            # Agent skills configuration
```
