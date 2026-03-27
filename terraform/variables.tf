variable "aws_region" {
  type        = string
  description = "AWS region"
  default     = "ap-northeast-2"
}

variable "project_name" {
  type        = string
  description = "Project name prefix"
  default     = "devsecops-hub"
}

variable "github_org" {
  type        = string
  description = "GitHub organization/user name"
}

variable "github_repo" {
  type        = string
  description = "GitHub repository name"
}

variable "app_role_principal_arns" {
  type        = list(string)
  description = "AWS principal ARNs allowed to assume app runtime role (ECS/EC2/Lambda role ARN etc.)"
  default     = []
}