#!/bin/bash
# Deploy PromptLock to Google Cloud Run
#
# Prerequisites:
#   gcloud auth login
#   gcloud config set project YOUR_PROJECT_ID
#
# Usage:
#   ./deploy.sh                    # deploy using Cloud Build
#   ./deploy.sh --direct           # deploy directly from source

set -euo pipefail

PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
REGION="us-central1"
SERVICE="promptlock"

if [ -z "$PROJECT_ID" ]; then
  echo "Error: No GCP project set. Run: gcloud config set project YOUR_PROJECT_ID"
  exit 1
fi

echo "Deploying PromptLock to Cloud Run"
echo "  Project: $PROJECT_ID"
echo "  Region:  $REGION"
echo "  Service: $SERVICE"
echo ""

if [ "${1:-}" = "--direct" ]; then
  # Direct source deploy (simpler, no Cloud Build setup needed)
  echo "Deploying from source..."
  gcloud run deploy "$SERVICE" \
    --source . \
    --region "$REGION" \
    --allow-unauthenticated \
    --port 8080 \
    --memory 256Mi \
    --cpu 1 \
    --min-instances 0 \
    --max-instances 3 \
    --concurrency 80 \
    --timeout 10s
else
  # Cloud Build deploy (CI/CD pipeline)
  echo "Submitting to Cloud Build..."
  gcloud builds submit --config cloudbuild.yaml
fi

# Show the URL
URL=$(gcloud run services describe "$SERVICE" --region "$REGION" --format='value(status.url)' 2>/dev/null)
echo ""
echo "Deployed: $URL"
echo ""
echo "To map shield.cawght.com:"
echo "  gcloud run domain-mappings create --service $SERVICE --domain shield.cawght.com --region $REGION"
echo "  Then add DNS CNAME: shield.cawght.com → ghs.googlehosted.com"
