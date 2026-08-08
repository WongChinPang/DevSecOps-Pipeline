import { useState } from "react";
import type { ScanRequest } from "../api";

interface Props {
  onScan: (data: ScanRequest) => void;
  loading: boolean;
}

const SAFE_IAC = `Resources:
  MySG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - CidrIp: 10.0.0.0/16
          FromPort: 443
          ToPort: 443
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: aws:kms
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true`;

const SAFE_DOCKERFILE = `FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --create-home appuser
USER appuser
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]`;

const SAFE_APP_CODE = `import os
from fastapi import FastAPI

app = FastAPI()
API_KEY = os.getenv("API_KEY")
DB_PASSWORD = os.getenv("DB_PASSWORD")

@app.get("/")
def root():
    return {"status": "ok"}`;

const UNSAFE_APP_CODE = `import os
from fastapi import FastAPI

app = FastAPI()
# UNSAFE: hardcoded credentials
API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"
DB_PASSWORD = "admin123!"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

@app.get("/")
def root():
    # UNSAFE: command injection
    user_input = "data.txt"
    os.system(f"cat {user_input}")
    
    # UNSAFE: eval
    result = eval("1 + 1")
    
    return {"status": "ok"}`;

const UNSAFE_IAC = `Resources:
  BadSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - CidrIp: 0.0.0.0/0
          FromPort: 22
          ToPort: 22
          IpProtocol: tcp
  BadPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: OverlyPermissive
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action: "*"
            Resource: "*"
  BadBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: insecure-bucket`;

const UNSAFE_DOCKERFILE = `FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
USER root
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]`;

export default function UploadForm({ onScan, loading }: Props) {
  const [iac, setIac] = useState(SAFE_IAC);
  const [dockerfile, setDockerfile] = useState(SAFE_DOCKERFILE);
  const [appCode, setAppCode] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onScan({ iac_content: iac, dockerfile_content: dockerfile, app_code: appCode });
  };

  const loadSafe = () => { setIac(SAFE_IAC); setDockerfile(SAFE_DOCKERFILE); setAppCode(SAFE_APP_CODE); };
  const loadUnsafe = () => { setIac(UNSAFE_IAC); setDockerfile(UNSAFE_DOCKERFILE); setAppCode(UNSAFE_APP_CODE); };

  return (
    <div>
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <p className="text-sm text-gray-400">
          Paste your IaC template, Dockerfile, and optionally application code — click Scan.
        </p>
        <div className="flex gap-2 ml-auto">
          <button type="button" onClick={loadSafe}
            className="text-xs px-3 py-1 rounded bg-emerald-900/50 text-emerald-300 border border-emerald-700/50 hover:bg-emerald-800/50 cursor-pointer">
            Load Safe Example
          </button>
          <button type="button" onClick={loadUnsafe}
            className="text-xs px-3 py-1 rounded bg-red-900/50 text-red-300 border border-red-700/50 hover:bg-red-800/50 cursor-pointer">
            Load Unsafe Example
          </button>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              IaC Template <span className="text-gray-500">(CloudFormation YAML)</span>
            </label>
            <textarea value={iac} onChange={(e) => setIac(e.target.value)}
              rows={12} spellCheck={false} placeholder="Paste your CloudFormation YAML here..."
              className="w-full bg-gray-900 border border-gray-700 rounded-lg p-3 text-sm font-mono text-green-400 focus:outline-none focus:border-emerald-500 resize-y"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Dockerfile <span className="text-gray-500">(container build)</span>
            </label>
            <textarea value={dockerfile} onChange={(e) => setDockerfile(e.target.value)}
              rows={12} spellCheck={false} placeholder="Paste your Dockerfile here..."
              className="w-full bg-gray-900 border border-gray-700 rounded-lg p-3 text-sm font-mono text-green-400 focus:outline-none focus:border-emerald-500 resize-y"
            />
          </div>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">
            Application Code <span className="text-gray-500">(optional — Python, JS, TS)</span>
          </label>
          <textarea value={appCode} onChange={(e) => setAppCode(e.target.value)}
            rows={8} spellCheck={false} placeholder="Paste your application code here (Python, JavaScript, TypeScript)..."
            className="w-full bg-gray-900 border border-gray-700 rounded-lg p-3 text-sm font-mono text-green-400 focus:outline-none focus:border-emerald-500 resize-y"
          />
        </div>
        <button
          type="submit" disabled={loading}
          className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg font-semibold transition-colors cursor-pointer"
        >
          {loading ? "Scanning..." : "Run Security Scan"}
        </button>
      </form>
    </div>
  );
}
