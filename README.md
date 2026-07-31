# DevSecOps Pipeline

Automated security scanning platform for IaC templates and Dockerfiles. Combines static rule-based detection with LLM-powered auditing, triggered through a CI/CD pipeline.

## Architecture

```
Browser (React SPA)  →  ALB  →  ECS Fargate (FastAPI)  →  Lambda (scanner)
                                                               ↓
Git push  →  CodePipeline  →  SecurityTest  →  Build  →  Deploy
                                  │              │          │
                             Scanner+LLM    docker push   ECS Fargate
                                  │
                             S3 reports/ (JSON + MD)
```

## Quick Start

Open the web platform at the ALB URL, paste IaC YAML + Dockerfile, and click **Run Security Scan**.

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/scan` | POST | Scan IaC + Dockerfile (`{iac_content, dockerfile_content}`) |
| `/api/scans` | GET | Scan history |

## Pipeline

CodePipeline runs on every push to `main`:

1. **Source** — GitHub clone
2. **SecurityTest** — Upload IaC to S3 → static scan → LLM audit
3. **Build** — Docker build + push to ECR
4. **Deploy** — Rolling update to ECS Fargate

Unsafe configurations (open ports, IAM wildcards, unencrypted S3) block the pipeline.

## Project Structure

```
├── app/                  # FastAPI backend
│   ├── main.py           # API endpoints + SPA fallback
│   └── scan_service.py   # Lambda invocation logic
├── frontend/             # React + TypeScript + Tailwind SPA
│   └── src/components/   # UploadForm, ScanResults, ScanHistory
├── Dockerfile            # Multi-stage: Node build + Python serve
├── infrastructure.yaml   # CloudFormation IaC template
├── tests/                # Safe/unsafe test cases
├── CONTEXT.md            # Domain model glossary
└── docs/agents/          # Agent skills configuration
```
