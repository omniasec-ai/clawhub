#!/bin/bash

# Exit on error
set -e

FORCE_DEPLOY=false

# get environment name, force option and tag
ENVIRONMENT=staging
TAG=$(date +%Y%m%d-%H%M%S)


# Parse command line arguments
while getopts "e:f" opt; do
    case $opt in
        e)
            ENVIRONMENT="$OPTARG"
            ;;
        f)
            FORCE_DEPLOY=true
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            echo "Usage: $0 [-e environment] [-f]" >&2
            exit 1
            ;;
        :)
            echo "Option -$OPTARG requires an argument." >&2
            echo "Usage: $0 [-e environment] [-f]" >&2
            exit 1
            ;;
    esac
done


if [ "$FORCE_DEPLOY" = false ]; then
    # Check if we're on feat/vt-integration branch (as requested)
    CURRENT_BRANCH=$(git branch --show-current)
    if [ "$CURRENT_BRANCH" != "feat/vt-integration" ]; then
        echo "Error: Must be on feat/vt-integration branch to deploy or force deploy with -f"
        exit 1
    fi
fi

# Configuration
GOOGLE_CLOUD_PROJECT="virustotal-uma-colab-prod"
PROJECT_REPO="virustotal-uma-colab-repo"
SERVICE_NAME=$(echo "clawhub-vt-${ENVIRONMENT}" | tr '_' '-')
REGION="us-central1"
IMAGE_NAME="${SERVICE_NAME}-image"

artifact_registry_repo="us-central1-docker.pkg.dev/${GOOGLE_CLOUD_PROJECT}/${PROJECT_REPO}"

# Create config directory and dummy env file if they don't exist
mkdir -p config
if [ ! -f "config/env.${ENVIRONMENT}.yaml" ]; then
    echo "Creating dummy config/env.${ENVIRONMENT}.yaml"
    cat <<EOF > "config/env.${ENVIRONMENT}.yaml"
# Add your environment variables here
# VITE_CONVEX_URL: "your-url"
EOF
fi

# build docker image with tag and push to artifact registry
echo "Building docker image with tag: $TAG"
docker build -f Dockerfile -t $artifact_registry_repo/$IMAGE_NAME:$TAG .

echo "Pushing to artifact registry..."
docker push $artifact_registry_repo/$IMAGE_NAME:$TAG

# Deploy to Cloud Run
echo "Deploying to Cloud Run service: $SERVICE_NAME"
gcloud run deploy $SERVICE_NAME \
    --image $artifact_registry_repo/$IMAGE_NAME:$TAG \
    --cpu=1 \
    --memory=2Gi \
    --concurrency=20 \
    --platform managed \
    --region $REGION \
    --project $GOOGLE_CLOUD_PROJECT \
    --allow-unauthenticated \
    --execution-environment gen2 \
    --no-cpu-throttling \
    --min-instances=1 \
    --max-instances=30 \
    --env-vars-file=config/env.${ENVIRONMENT}.yaml

# Update all traffic to route to the latest revision of the Cloud Run service
echo "Updating traffic..."
gcloud run services update-traffic $SERVICE_NAME --to-latest --region $REGION --project $GOOGLE_CLOUD_PROJECT

# Get the service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME --platform managed --region $REGION --project $GOOGLE_CLOUD_PROJECT --format 'value(status.url)')
echo "Deployment complete! Service URL: $SERVICE_URL"
