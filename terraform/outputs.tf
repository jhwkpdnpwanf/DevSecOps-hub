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

output "rds_mysql_endpoint" {
  value       = aws_db_instance.hub_mysql.address
  description = "RDS MySQL endpoint hostname"
}

output "rds_mysql_port" {
  value       = aws_db_instance.hub_mysql.port
  description = "RDS MySQL port"
}

output "rds_mysql_db_name" {
  value       = aws_db_instance.hub_mysql.db_name
  description = "RDS MySQL database name"
}

output "rds_mysql_username" {
  value       = aws_db_instance.hub_mysql.username
  description = "RDS MySQL master username"
}

output "database_url_template" {
  value       = "mysql+pymysql://${aws_db_instance.hub_mysql.username}:<DB_PASSWORD>@${aws_db_instance.hub_mysql.address}:${aws_db_instance.hub_mysql.port}/${aws_db_instance.hub_mysql.db_name}"
  description = "Template for DATABASE_URL env var (replace <DB_PASSWORD>)"
}