import { useState } from "react";
import type { ScanRequest } from "../api";

interface Props {
  onScan: (data: ScanRequest) => void;
  loading: boolean;
}

const SAMPLE_IAC = `Resources:
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
              SSEAlgorithm: aws:kms`;

const SAMPLE_DOCKERFILE = `FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
RUN useradd appuser && chown -R appuser /app
USER appuser
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]`;

export default function UploadForm({ onScan, loading }: Props) {
  const [iac, setIac] = useState(SAMPLE_IAC);
  const [dockerfile, setDockerfile] = useState(SAMPLE_DOCKERFILE);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onScan({ iac_content: iac, dockerfile_content: dockerfile });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-400 mb-1">
            IaC Template (YAML)
          </label>
          <textarea
            value={iac}
            onChange={(e) => setIac(e.target.value)}
            rows={14}
            className="w-full bg-gray-900 border border-gray-700 rounded-lg p-3 text-sm font-mono text-green-400 focus:outline-none focus:border-emerald-500 resize-y"
            spellCheck={false}
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-400 mb-1">
            Dockerfile
          </label>
          <textarea
            value={dockerfile}
            onChange={(e) => setDockerfile(e.target.value)}
            rows={14}
            className="w-full bg-gray-900 border border-gray-700 rounded-lg p-3 text-sm font-mono text-green-400 focus:outline-none focus:border-emerald-500 resize-y"
            spellCheck={false}
          />
        </div>
      </div>
      <button
        type="submit"
        disabled={loading}
        className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg font-semibold transition-colors cursor-pointer"
      >
        {loading ? "Scanning..." : "Run Security Scan"}
      </button>
    </form>
  );
}
