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

variable "vpc_id" {
  type        = string
  description = "VPC ID where RDS MySQL will be provisioned"
}

variable "db_subnet_ids" {
  type        = list(string)
  description = "Private/Public subnet IDs for RDS subnet group (at least 2 subnets recommended)"
}

variable "db_allowed_cidrs" {
  type        = list(string)
  description = "CIDR ranges allowed to connect to MySQL 3306 (for Render use, set trusted egress CIDRs)"
  default     = ["0.0.0.0/0"]
}

variable "db_name" {
  type        = string
  description = "Initial MySQL database name for DevSecOps Hub"
  default     = "devsecops_hub"
}

variable "db_username" {
  type        = string
  description = "Master username for RDS MySQL"
  default     = "hubadmin"
}

variable "db_password" {
  type        = string
  description = "Master password for RDS MySQL (store securely)"
  sensitive   = true
}

variable "db_instance_class" {
  type        = string
  description = "RDS instance class"
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  type        = number
  description = "Allocated storage (GB)"
  default     = 20
}

variable "db_engine_version" {
  type        = string
  description = "MySQL engine version"
  default     = "8.0"
}

variable "db_multi_az" {
  type        = bool
  description = "Enable Multi-AZ for RDS MySQL"
  default     = false
}

variable "db_publicly_accessible" {
  type        = bool
  description = "Expose RDS endpoint publicly (needed when app is outside VPC, e.g., Render)"
  default     = true
}

variable "db_backup_retention_period" {
  type        = number
  description = "RDS backup retention period in days"
  default     = 7
}

variable "db_deletion_protection" {
  type        = bool
  description = "Enable deletion protection on RDS"
  default     = false
}
