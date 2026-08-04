#!/bin/bash
# ==================================================
#  Demo: PASS Pipeline — 用安全 IaC 展示全線通過
#  bash demo-pass.sh
# ==================================================
set -e

echo ">>> 切換為安全 IaC 模板（無 !Ref，無 * 權限）..."
cp infrastructure-safe.yaml infrastructure.yaml

echo ">>> git add + commit + push ..."
git add infrastructure.yaml
git commit -m "demo: security-compliant IaC template — expect ALL PASS" || echo "(no changes)"
git push origin main

echo ""
echo "✅ 推送完成！Pipeline 應全部通過。"
echo "👉 aws codepipeline get-pipeline-state --name devsecops-pipeline"
