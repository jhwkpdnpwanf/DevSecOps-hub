output "report_bucket_name" {
  value       = aws_s3_bucket.reports.bucket
  description = "S3 bucket name for raw scan reports"
}

output "app_runtime_role_arn" {
  value       = aws_iam_role.app_runtime.arn
  description = "Role ARN for application runtime"
}

output "github_actions_role_arn" {
  value       = aws_iam_role.github_actions.arn
  description = "Role ARN for GitHub Actions OIDC"
}