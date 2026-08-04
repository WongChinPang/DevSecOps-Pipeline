#!/bin/bash
# ===========================================
#  Demo Push Script — 自動觸發 CI/CD 流水線
#  用法: bash demo-push.sh "你的 commit 訊息"
# ===========================================

MESSAGE="${1:-demo: live demo push}"

echo ">>> 修改示範檔案..."
DATE=$(date '+%Y-%m-%d %H:%M:%S')
echo "Demo push at $DATE — Pipeline triggered successfully." >> demo-trigger.txt

echo ">>> git add ..."
git add demo-trigger.txt

echo ">>> git commit ..."
git commit -m "$MESSAGE"

echo ">>> git push ..."
git push origin main

echo ""
echo "✅ 推送完成！"
echo "👉 打開 AWS Console → CodePipeline → devsecops-pipeline 檢視進度"
echo "👉 或跑: aws codepipeline get-pipeline-state --name devsecops-pipeline"
