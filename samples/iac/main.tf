# Sample Terraform module for ATMS IaC ingest (v0.14).
# Realistic AWS-only AI-on-Bedrock stack: Lambda + Bedrock + Secrets Manager
# + S3 + KMS + DynamoDB + API Gateway + CloudWatch + IAM. Run:
#
#   atms ingest-iac samples/iac/main.tf --out drafted.yaml --analyze
#
# Modules / count / for_each are NOT exercised here; the Terraform parser is a
# pragmatic regex sweep, not a full HCL evaluator. For module-heavy projects
# run `terraform show -json` and feed the output through a JSON-to-HCL bridge
# instead.

terraform {
  required_providers { aws = { source = "hashicorp/aws", version = "~> 5.0" } }
}

provider "aws" { region = "us-east-1" }

# ─── Identity ───────────────────────────────────────────────────────────
resource "aws_iam_role" "lambda_exec" {
  name = "rag-lambda-exec"
  assume_role_policy = jsonencode({})
}

resource "aws_iam_policy" "lambda_perms" {
  name   = "rag-lambda-perms"
  policy = jsonencode({})
}

# ─── Storage / data ─────────────────────────────────────────────────────
resource "aws_s3_bucket" "documents" {
  bucket = "rag-documents-prod"
}

resource "aws_kms_key" "documents_cmk" {
  description = "Customer-managed key for documents bucket."
}

resource "aws_dynamodb_table" "sessions" {
  name             = "rag-sessions"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "session_id"
  attribute        = []
}

# ─── Secrets ────────────────────────────────────────────────────────────
resource "aws_secretsmanager_secret" "anthropic_api_key" {
  name = "rag/anthropic_api_key"
}

# ─── Compute ────────────────────────────────────────────────────────────
resource "aws_lambda_function" "rag_handler" {
  function_name = "rag-handler"
  role          = aws_iam_role.lambda_exec.arn
  s3_bucket     = aws_s3_bucket.documents.bucket
  depends_on    = [
    aws_iam_role.lambda_exec,
    aws_secretsmanager_secret.anthropic_api_key,
    aws_kms_key.documents_cmk,
  ]
}

# ─── API gateway / network ──────────────────────────────────────────────
resource "aws_apigatewayv2_api" "front" {
  name          = "rag-api"
  protocol_type = "HTTP"
}

resource "aws_lb" "front_alb" {
  name               = "rag-alb"
  internal           = false
  load_balancer_type = "application"
}

resource "aws_security_group" "alb_sg" {
  name = "rag-alb-sg"
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "private_a" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}

# ─── Messaging / observability ──────────────────────────────────────────
resource "aws_sqs_queue" "evidence_jobs" {
  name = "rag-evidence-jobs"
}

resource "aws_cloudwatch_log_group" "rag_logs" {
  name = "/atms/rag-handler"
}

# ─── Bedrock / SageMaker (AI tier) ──────────────────────────────────────
resource "aws_sagemaker_endpoint" "embedder" {
  name                 = "rag-embedder"
  endpoint_config_name = "rag-embedder-config"
}

resource "aws_sagemaker_model" "embedder_model" {
  name               = "rag-embedder-model"
  execution_role_arn = aws_iam_role.lambda_exec.arn
}
