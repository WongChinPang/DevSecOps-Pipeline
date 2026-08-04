#!/bin/bash
# ==================================================
#  Demo: BLOCK Pipeline — 用不安全 IaC 展示阻斷
#  bash demo-block.sh
# ==================================================
set -e

echo ">>> 切換為不安全 IaC 模板（含 0.0.0.0/0:22 + IAM *）..."
cat > infrastructure.yaml << 'UNSAFEEOF'
AWSTemplateFormatVersion: "2010-09-09"
Description: DevSecOps Pipeline Infrastructure (DEMO - Unsafe)

Resources:
  UnsafeSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: DO NOT USE - insecure example
      SecurityGroupIngress:
        - CidrIp: 0.0.0.0/0
          FromPort: 22
          ToPort: 22
          IpProtocol: tcp
  UnsafePolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: OverlyPermissive
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action: "*"
            Resource: "*"
  UnsafeBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: insecure-data-bucket
UNSAFEEOF

echo ">>> git add + commit + push ..."
git add infrastructure.yaml
git commit -m "demo: UNSAFE IaC template — expect SecurityTest BLOCK" || echo "(no changes)"
git push origin main

echo ""
echo "✅ 推送完成！SecurityTest 應被阻斷（BLOCKED）。"
echo "👉 aws codepipeline get-pipeline-state --name devsecops-pipeline"
